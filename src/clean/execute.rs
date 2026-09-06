//! The DESTRUCTIVE clean step — actually remove the planned candidates. Isolated from planning so
//! the deletion path is small, obvious, and guarded.
//!
//! THREE safety rails on every item, matching the three the oracle runs. The first two are
//! `safe_clean`'s own (`bin/clean.sh:600-612`): [`should_protect_path`] then [`deletion_is_whitelisted`],
//! re-checked here per item even though [`super::plan::plan_clean`] already applied them — defense in
//! depth, and it matters because the candidate list is assembled from two independent planners.
//! digger does the same thing in one place: `safe_clean` re-checks every path it is handed, no matter
//! which caller built the argument list.
//!
//! The third is [`validate_path_for_deletion`], which the oracle runs from INSIDE `safe_remove`
//! (`file_ops.sh:224-226`) and `mole_delete` (`:522`) — so every delete it performs passes it, in
//! both commands. It is checked here rather than inside [`remove_one`] so that every remover
//! inherits it, including [`super::tool_delegate::remover_for`]'s wrapper and the injected fakes the
//! tests use; see that module for the one place this ordering is not a literal transcription.
//!
//! All of that lives in ONE per-path function, [`remove_guarded`], which is also what `purge` and
//! `installer` remove through — the oracle's purge deletes via `safe_remove` and its installer via
//! `mole_delete`, so those commands get the same rails and the same after-the-fact byte
//! verification as `clean` rather than a re-spelled subset of them.
//!
//! Which protection REGIME the first and third rails apply is an explicit
//! [`ProtectionMode`] parameter — the ported `MOLE_UNINSTALL_MODE`. `clean` passes `Cleanup`,
//! `uninstall` passes `Uninstall`. It is a parameter and not a default precisely because this
//! executor is shared: when the protection rail was added here with no mode, `uninstall --apply`
//! silently removed nothing for every data-protected app.
//!
//! The caller gates all of this behind an explicit `--apply`; the default everywhere is the
//! non-destructive dry-run.
//!
//! A FOURTH knob selects HOW a surviving candidate is removed: `permanent: bool` chooses between
//! [`crate::trash::move_to_trash`] (the default — recoverable, via the real macOS Trash) and
//! `fs::remove_dir_all`/`fs::remove_file` (`--permanent` — irreversible, today's only behavior
//! before this existed). A failed recoverable delete is reported as an ordinary per-item error, the
//! same as a missing path or a permission failure — it is NEVER a reason to fall back to the
//! permanent path for that item. See `crate::trash`'s module docs for why that mechanism, not `mv`,
//! is what actually reaches the OS Trash.

use super::plan::CleanCandidate;
use super::protect::{should_protect_path, ProtectionMode};
use super::validate::{deletion_is_whitelisted, validate_path_for_deletion};
use std::fs;
use std::path::Path;

/// What a remover actually DID to a candidate. The whole reason this is not `Result<(), String>`:
/// `Ok` alone cannot distinguish "the bytes are gone, and on the default path they are in a Trash
/// you can point at" from "a subprocess exited zero without touching the filesystem" — and the byte
/// accounting and the recoverability audit log both hang off exactly that distinction
/// (RULEBOOK §3m).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// This engine removed the path itself. Post-condition: the path is gone, so the candidate's
    /// measured size is what went away, and `permanent: false` means it went to the real Trash.
    Removed,
    /// This engine removed the removable CHILDREN of the path, sparing the ones the rails refuse
    /// (see `super::tool_delegate::sweep_children`). The directory itself remains, so only `bytes`
    /// — measured per child, before each removal — is accountable, never the parent's planned
    /// total.
    Swept { bytes: u64 },
    /// A tool's own cache-clean command ran and exited zero. This engine never touched the
    /// filesystem: how much was freed is not knowable, and whatever WAS freed the tool unlinked
    /// permanently — `uv cache prune` and `go clean -cache` do not use any Trash.
    Delegated,
}

/// What this run can honestly say it freed for one removed item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freed {
    /// This run removed the bytes itself, and this is how many. A deletion audit record may be
    /// written for it, and its `mode` is truthful.
    Bytes(u64),
    /// A tool cleaned its own cache. No byte count, and NOT recoverable — so no `trash` record.
    Delegated,
    /// The path was already gone when this run reached it. NO LONGER PRODUCED by the executor:
    /// `execute_clean_with_remover` drops such a candidate outright, because bash counts and logs
    /// a path it cannot see in neither place — see the comment at that filter for the two fences.
    /// The variant is kept because it is still a legal thing for a caller to hand the reporting
    /// helpers (`src/cli.rs`'s `log_clean_session` matches on it), and because deleting it would
    /// silently turn "we deliberately claim nothing here" into a compile error somewhere else
    /// rather than into a decision anyone re-reads.
    AlreadyGone,
    /// The remover reported success and the path is STILL on disk. Nothing may be claimed: not the
    /// bytes (they are demonstrably still there) and not a Trash location (there is nothing in it
    /// to point at). Unreachable through `remove_one`, which is why it exists — it is the check
    /// that makes "verified after the fact" true of the code and not just of the comment.
    Unverified,
}

/// One entry in [`CleanOutcome::removed`] — the candidate, plus what may honestly be claimed about
/// it. Flat rather than wrapping [`CleanCandidate`] because a "removed item" and a "planned
/// candidate" are not the same thing: the planned size is a prediction, `freed` is a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedItem {
    pub path: String,
    pub label: String,
    pub freed: Freed,
}

impl RemovedItem {
    /// Bytes this run may claim for the item — 0 whenever it may claim none. `freed_bytes` is the
    /// sum of exactly this over `removed`, so `sum(removed[].bytes()) == freed_bytes` holds by
    /// construction (it did not before: phantom entries carried plan sizes that were never in the
    /// total, and delegated ones carried sizes that were never freed at all).
    pub fn bytes(&self) -> u64 {
        match self.freed {
            Freed::Bytes(n) => n,
            Freed::Delegated | Freed::AlreadyGone | Freed::Unverified => 0,
        }
    }

    /// Whether a deletion AUDIT record may be written for this item. True only when this run
    /// removed the bytes itself, which is what makes the record's `mode` column truthful: on the
    /// default path `trash` promises a Trash the user can open and Put Back from, and neither a
    /// tool's own `prune` nor a path an ancestor already took can honour that promise.
    pub fn is_auditable_deletion(&self) -> bool {
        matches!(self.freed, Freed::Bytes(_))
    }
}

/// One path the filesystem refused to give up: which, and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalError {
    pub path: String,
    pub error: String,
}

/// How a destructive command disposes of a path — the one switch every `--apply` reads
/// (`--permanent` present or not), spelled once so the audit log's `mode` column, the history
/// lines and the JSON never derive the word separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalMode {
    /// The default: the real macOS Trash, recoverable, frees no space until emptied.
    Trash,
    /// `--permanent`: unlinked immediately, irreversible.
    Permanent,
}

impl RemovalMode {
    /// The mode `--permanent` selects, or the default.
    pub fn from_permanent(permanent: bool) -> Self {
        if permanent {
            RemovalMode::Permanent
        } else {
            RemovalMode::Trash
        }
    }

    pub fn is_permanent(self) -> bool {
        matches!(self, RemovalMode::Permanent)
    }

    /// The `mode` word `deletions.log` records — the oracle's `trash` / `permanent`.
    pub fn word(self) -> &'static str {
        match self {
            RemovalMode::Trash => "trash",
            RemovalMode::Permanent => "permanent",
        }
    }
}

/// What actually happened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanOutcome {
    pub removed: Vec<RemovedItem>,
    /// Bytes this run PERMANENTLY freed — verified gone, and unlinked rather than moved. Always 0
    /// on the default (Trash) path: a Trash move frees nothing, the bytes are still on the volume
    /// until the user empties the Trash, so they are billed to `moved_to_trash_bytes` instead
    /// (RULEBOOK §3m: a byte count means bytes that are gone).
    pub freed_bytes: u64,
    /// Bytes this run moved to the real macOS Trash — verified absent from their original path.
    /// Recoverable, and NOT free space. Always 0 under `--permanent`.
    pub moved_to_trash_bytes: u64,
    /// Anything that couldn't be removed, with what the filesystem said.
    pub errors: Vec<RemovalError>,
    /// Paths any of the three protection rails refused — the two `safe_clean` filters or
    /// `validate_path_for_deletion`. All three mean the same thing to a caller (the engine declined
    /// to touch this path), which is why they share a bucket; `errors` stays reserved for "we tried
    /// and the filesystem said no", so a consumer can still tell policy from failure.
    pub protected: Vec<String>,
}

/// A live event emitted per candidate as [`execute_clean_with`] processes it — the unit of the
/// `clean --stream` NDJSON feed (a GUI renders each as it arrives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanEvent<'a> {
    Removed {
        path: &'a str,
        size: u64,
    },
    Failed {
        path: &'a str,
        error: &'a str,
    },
    Protected {
        path: &'a str,
    },
    /// A `clean --plan` line the engine declined before any rail ran, with the machine-readable
    /// reason (`super::plan_file::NOT_A_CLEAN_TARGET`). Streams as a `protected` event carrying a
    /// `reason` — the same vocabulary a reader already handles, one additive field.
    Refused {
        path: &'a str,
        reason: &'a str,
    },
}

/// Remove each planned candidate, re-checking all three protection rails first. `mode` is the
/// ported `MOLE_UNINSTALL_MODE` and MUST match the command on whose behalf this runs. `permanent`
/// selects the removal mechanism: `false` (the default everywhere this is called) routes each
/// surviving candidate through the real macOS Trash; `true` removes it immediately via
/// `fs::remove_dir_all`/`fs::remove_file`. Errors (including a failed recoverable delete) and
/// protection skips are collected, not fatal — one item failing never stops the rest of the plan
/// from being processed.
pub fn execute_clean(
    plan: &[CleanCandidate],
    whitelist: &[&str],
    permanent: bool,
    mode: ProtectionMode,
) -> CleanOutcome {
    execute_clean_with(plan, whitelist, permanent, mode, |_| {})
}

/// Like [`execute_clean`] but invokes `emit` with a [`CleanEvent`] for each candidate as it is
/// processed — the streaming core. `emit` runs synchronously between removals, so a caller can
/// flush an NDJSON line live. The returned outcome is identical to `execute_clean`'s.
pub fn execute_clean_with(
    plan: &[CleanCandidate],
    whitelist: &[&str],
    permanent: bool,
    mode: ProtectionMode,
    emit: impl FnMut(CleanEvent),
) -> CleanOutcome {
    execute_clean_with_remover(plan, whitelist, permanent, mode, emit, remove_one_reported)
}

/// How ONE surviving candidate is actually removed, selected by `permanent`. Split out from the
/// loop so the choice is a single, tiny, obviously-correct function — and so tests can inject a
/// fake in its place (see `execute_clean_with_remover`) to prove the DISPATCH logic (which mode a
/// candidate goes through, and that a failure never becomes a different kind of delete) without
/// ever touching the real filesystem's Trash. The real recoverable path (`permanent: false`) is
/// exercised for real by `crate::trash`'s own tests and by manual verification — see that module's
/// docs for why an automated test here would have to write into whoever runs `cargo test`'s actual
/// Trash to prove anything, which this crate avoids.
///
/// `pub(crate)`: also the DEFAULT fallback [`super::tool_delegate::remover_for`] wraps — a
/// tool-delegated cache tries the tool's own clean command first and falls through to this exact
/// function only where the oracle allows a raw removal at all.
pub(crate) fn remove_one(p: &Path, permanent: bool) -> Result<(), String> {
    if permanent {
        let result = if p.is_dir() {
            fs::remove_dir_all(p)
        } else {
            fs::remove_file(p)
        };
        result.map_err(|e| e.to_string())
    } else {
        crate::trash::move_to_trash(p)
    }
}

/// [`remove_one`] in remover shape: this engine removing the path itself is [`Removal::Removed`],
/// by definition. Kept separate from `remove_one` so the "how do I delete a path" primitive stays a
/// tiny obviously-correct function and the "what may I claim about it" vocabulary lives here.
pub(crate) fn remove_one_reported(p: &Path, permanent: bool) -> Result<Removal, String> {
    remove_one(p, permanent).map(|()| Removal::Removed)
}

/// [`execute_clean_with`] with the per-candidate removal function injected — the seam that makes
/// the permanent/recoverable DISPATCH testable without a real Trash call (see `remove_one`'s doc
/// comment). Most production callers get [`remove_one`] via `execute_clean_with`/`execute_clean`;
/// `pub(crate)` because `src/cli.rs`'s `clean` command calls this directly with
/// [`super::tool_delegate::remover_for`] instead, so a tool-delegated candidate tries the tool's own
/// cache-clean command before ever reaching `remove_one`.
pub(crate) fn execute_clean_with_remover(
    plan: &[CleanCandidate],
    whitelist: &[&str],
    permanent: bool,
    mode: ProtectionMode,
    mut emit: impl FnMut(CleanEvent),
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
) -> CleanOutcome {
    let mut outcome = CleanOutcome::default();
    for c in plan {
        execute_one(
            &mut outcome,
            c,
            whitelist,
            permanent,
            mode,
            &mut emit,
            &remover,
        );
    }
    outcome
}

/// ONE candidate through [`remove_guarded`], its verdict recorded on `outcome` and announced through
/// `emit` — the body of [`execute_clean_with_remover`]'s loop, split out so a caller whose list is
/// not a plain slice of candidates (`super::plan_file`, which interleaves refusals with candidates
/// in the order a file listed them) records each verdict through exactly the same arms rather than
/// a second transcription of them.
pub(crate) fn execute_one(
    outcome: &mut CleanOutcome,
    c: &CleanCandidate,
    whitelist: &[&str],
    permanent: bool,
    mode: ProtectionMode,
    emit: &mut impl FnMut(CleanEvent),
    remover: &impl Fn(&Path, bool) -> Result<Removal, String>,
) {
    match remove_guarded(&c.path, c.size, whitelist, permanent, mode, remover) {
        Guarded::Protected => {
            emit(CleanEvent::Protected { path: &c.path });
            outcome.protected.push(c.path.clone());
        }
        // MISSING IS NOT A FAILURE, and it is not an EVENT either — see `remove_guarded`.
        // DROPPED ENTIRELY: no event, no `removed` entry, no byte count, no audit record.
        // Keeping the item out of `removed` also makes the dry run and the apply of the same
        // plan agree on their item count instead of disagreeing by construction, and keeps
        // `sum(removed[].bytes()) == freed_bytes` true for free.
        Guarded::Missing => {}
        Guarded::Removed(freed) => {
            emit(CleanEvent::Removed {
                path: &c.path,
                size: match freed {
                    Freed::Bytes(n) => n,
                    _ => 0,
                },
            });
            outcome.record_removed(&c.path, &c.label, freed, permanent);
        }
        Guarded::Failed(msg) => {
            emit(CleanEvent::Failed {
                path: &c.path,
                error: &msg,
            });
            outcome.errors.push(RemovalError {
                path: c.path.clone(),
                error: msg,
            });
        }
    }
}

impl CleanOutcome {
    /// Append a removed item and bill what it may honestly claim, to the counter that tells the
    /// truth about WHERE the bytes went: `freed_bytes` under `--permanent`, `moved_to_trash_bytes`
    /// on the default path. The ONE place either counter grows, so
    /// `sum(removed[].bytes()) == freed_bytes + moved_to_trash_bytes` holds for every command that
    /// reports through this struct, not just `clean`.
    ///
    /// `Freed::Delegated` bills nothing either way; the count is not knowable. (A tool's own
    /// `prune` unlinks permanently, but that is a fact about the audit `mode`, not about a number
    /// this engine never had.)
    pub(crate) fn record_removed(
        &mut self,
        path: &str,
        label: &str,
        freed: Freed,
        permanent: bool,
    ) {
        let item = RemovedItem {
            path: path.to_string(),
            label: label.to_string(),
            freed,
        };
        if permanent {
            self.freed_bytes += item.bytes();
        } else {
            self.moved_to_trash_bytes += item.bytes();
        }
        self.removed.push(item);
    }

    /// Every byte this run verified leaving its original path, whichever way it went — what the
    /// history session's size column records (the audit record's `mode` says whether it is
    /// recoverable).
    pub fn accounted_bytes(&self) -> u64 {
        self.freed_bytes + self.moved_to_trash_bytes
    }
}

/// What the shared guarded remover decided about ONE path — the four things that can happen to a
/// candidate on any destructive path in this crate, so every command reports them the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Guarded {
    /// A protection rail refused. Nothing was attempted and nothing on disk changed.
    Protected,
    /// The rails passed and the path was not there. Nothing was attempted. bash counts and logs a
    /// path it cannot see in neither place (`bin/clean.sh:614`, `file_ops.sh:230-232`).
    Missing,
    /// The remover reported success; the payload is what may honestly be CLAIMED about it, decided
    /// from the filesystem rather than from the remover's word (RULEBOOK §3m).
    Removed(Freed),
    /// The remover failed. The path is left exactly as it was — never retried the other way.
    Failed(String),
}

/// THE shared guarded remover: every destructive command (`clean`, `uninstall`, `purge`,
/// `installer`) removes each path through this one function, so the rails cannot be forgotten by
/// a caller and the byte accounting cannot be inferred from a remover's exit status.
///
/// In order: `safe_clean`'s two rails ([`should_protect_path`] then [`deletion_is_whitelisted`] —
/// callers whose oracle consults no whitelist pass `&[]`), then `safe_remove`'s
/// [`validate_path_for_deletion`], then the existence check, then the removal, then the
/// post-condition. The rails sit BEFORE the existence check, which is where `safe_remove` puts
/// them too (`file_ops.sh:224-231`: validate, THEN `[[ ! -e "$path" ]] && return 0`), so a path
/// that both fails validation AND has vanished is reported as PROTECTED rather than missing.
///
/// The planned size is a preview only. Bill the current tree measured immediately before removal,
/// and only after confirming the name is gone.
pub(crate) fn remove_guarded(
    path: &str,
    _planned_size: u64,
    whitelist: &[&str],
    permanent: bool,
    mode: ProtectionMode,
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
) -> Guarded {
    // Defense in depth: never delete a protected path, even if the planner missed it. Both of
    // `safe_clean`'s rails, in digger's own order — `should_protect_path` cannot be configured
    // away, so it goes first.
    if should_protect_path(path, mode) || deletion_is_whitelisted(path, whitelist) {
        return Guarded::Protected;
    }
    // The third rail.
    if validate_path_for_deletion(path, mode).is_err() {
        return Guarded::Protected;
    }
    if mode == ProtectionMode::Cleanup && !super::plan::crash_report_retention_allows(path) {
        return Guarded::Protected;
    }
    let p = Path::new(path);
    if !p.exists() {
        // digger's rule is unconditional and has no bookkeeping behind it: `safe_clean` collects a
        // path only `if [[ -e "$path" ]]` (`bin/clean.sh:614`), `safe_remove` returns 0 for a path
        // that is not there (`file_ops.sh:230-232`) — before its one `log_operation … "REMOVED"`
        // at `:300` — and `bin/clean.sh` ends `exit 0`. So a vanished target contributes nothing,
        // is logged nowhere, and can never change the exit status.
        //
        // Two things make a planned candidate vanish, and this engine cannot tell them apart.
        // An earlier candidate in the SAME plan removed it or a shared ancestor: the target
        // table has coarse `~/Library/Caches/*` sweeps sitting alongside specific sub-paths
        // nested under them, and `src/cli.rs` merges two planners whose outputs overlap
        // (`~/Library/Caches/go-build` is both a child of that sweep and `tool_delegate`'s
        // resolved Go target), which on the apply path is no longer deduped — see
        // `super::plan::PlanMode` for why it must not be. Or something OUTSIDE this run deleted
        // it: `~/Library/Caches` is live, apps drop their own cache subdirectories constantly,
        // and the planner walks the whole tree with `dir_size` before the removal loop starts,
        // so that window is seconds to tens of seconds wide.
        //
        // bash's counters are the reason both are dropped. A path bash never saw is filtered at
        // `:614` and lands in neither `files_cleaned` nor `total_items`, and both of the cases
        // above are that case in bash: it re-scans on every `safe_clean` call, so the second call
        // for a path the first already deleted simply never collects it. (A path that vanishes in
        // the narrow window INSIDE one bash call does reach `safe_remove` and is counted in
        // `total_count` while still logging nothing — an earlier comment here generalised that
        // arm to both cases, which is wrong: it is the rarer one, and it is unreachable through
        // this port's plan-then-execute split in the shape bash hits it.)
        return Guarded::Missing;
    }
    let measured_size = match removal_bytes(p, permanent) {
        Ok(n) => n,
        Err(e) => return Guarded::Failed(format!("cannot measure before removal: {e}")),
    };
    match remover(p, permanent) {
        Ok(removal) => {
            // What may be CLAIMED, decided from what the remover says it did plus, for the one
            // case that asserts a post-condition, the filesystem itself. RULEBOOK §3m: a byte
            // count means bytes that are gone, verified after the fact — never a plausible figure
            // borrowed from the plan.
            Guarded::Removed(match removal {
                // The remover says the path is gone. Check. This is the only
                // thing standing between "a remover returned Ok" and a number the user is told
                // they got back; a remover that reports success without deleting (a tool shim, a
                // Trash move that silently no-oped) claims nothing here.
                //
                // lstat checks the directory entry itself, including a dangling link. Only a
                // NotFound error establishes absence; permission or I/O failures prove nothing.
                Removal::Removed if is_gone(p) => Freed::Bytes(measured_size),
                Removal::Removed => Freed::Unverified,
                // Only what the sweep measured going away — the parent's planned size counts the
                // protected/whitelisted/hidden children the sweep deliberately spared.
                Removal::Swept { bytes } => Freed::Bytes(bytes),
                Removal::Delegated => Freed::Delegated,
            })
        }
        // A failed removal — permanent or recoverable alike — is an ordinary per-item error. It
        // is NEVER retried through the other mode: a Trash failure must not silently escalate
        // into a hard delete, and (though it cannot happen today, since fs::remove_* has no
        // fallback of its own) a permanent-delete failure must not be papered over either.
        Err(msg) => Guarded::Failed(msg),
    }
}

/// Measure what this removal can release now, after earlier items may have changed the tree.
/// A file with a surviving hardlink outside this subtree contributes no permanently freed bytes.
/// Trash accounting counts the content moved, since its freed counter is always zero.
fn removal_bytes(path: &Path, permanent: bool) -> std::io::Result<u64> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    let mut links = std::collections::HashMap::<(u64, u64), (u64, u64, u64)>::new();
    fn walk(
        path: &Path,
        // Only Unix exposes the metadata needed for hardlink accounting.
        _links: &mut std::collections::HashMap<(u64, u64), (u64, u64, u64)>,
    ) -> std::io::Result<u64> {
        let md = fs::symlink_metadata(path)?;
        if md.is_symlink() {
            return Ok(md.len());
        }
        if md.is_dir() {
            let mut bytes = 0u64;
            for entry in fs::read_dir(path)? {
                bytes = bytes.saturating_add(walk(&entry?.path(), _links)?);
            }
            return Ok(bytes);
        }
        if !md.is_file() {
            return Ok(0);
        }
        #[cfg(unix)]
        {
            let size = md.len().min(md.blocks().saturating_mul(512));
            let entry = _links
                .entry((md.dev(), md.ino()))
                .or_insert((md.nlink(), 0, size));
            entry.1 += 1;
            Ok(0)
        }
        #[cfg(not(unix))]
        Ok(md.len())
    }
    let mut bytes = walk(path, &mut links)?;
    for (total_links, removed_links, size) in links.into_values() {
        if !permanent || removed_links >= total_links {
            bytes = bytes.saturating_add(size);
        }
    }
    Ok(bytes)
}

/// "The name this run was asked to remove is no longer there", including a dangling symlink.
pub(crate) fn is_gone(p: &Path) -> bool {
    p.symlink_metadata()
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

use crate::json::escape as esc;

const RULE: &str = "======================================================================";

/// Whether an item counts toward the oracle's cleanup counters at all.
///
/// [`Freed::Delegated`] means a dev tool ran its OWN cache-clean command, which in bash is
/// `clean_tool_cache` (`lib/clean/dev.sh:10-42`) — a function that echoes a line and touches
/// neither `files_cleaned` nor `total_items`. Everything else came through this engine removing the
/// path, which is `safe_clean`, which does (`bin/clean.sh:962`, `:964`). The split is exact rather
/// than a heuristic: `tool_delegate::remover_for` reports `Removal::Delegated` in precisely the case
/// bash takes the `clean_tool_cache` branch, and falls through to a real removal — reported as
/// [`Freed::Bytes`] — in precisely the case bash falls back to `safe_clean` (e.g. `dev.sh:54` vs
/// `:56` for Corepack). [`Freed::Unverified`] counts, because bash's `removed=1` comes from
/// `safe_remove` returning zero, not from a post-condition it checks.
fn counts_as_cleaned(item: &RemovedItem) -> bool {
    !matches!(item.freed, Freed::Delegated)
}

/// `files_cleaned` (`bin/clean.sh:962`): one per individual PATH a `safe_clean` call removed.
fn items_cleaned(outcome: &CleanOutcome) -> usize {
    outcome
        .removed
        .iter()
        .filter(|c| counts_as_cleaned(c))
        .count()
}

/// `total_items` (`bin/clean.sh:964`): `+ 1` per `safe_clean` CALL that removed anything, ported as
/// the number of distinct LABELS — the label IS the `description` argument each call passes. Same
/// counter and same grouping key as `super::plan::render_plan_text`'s dry-run `Categories`, so the
/// preview and the report of one run cannot disagree about how many categories it touched; see that
/// function's doc for the residual (bash counts calls, so two calls sharing a description count
/// twice there and once here).
fn category_count(outcome: &CleanOutcome) -> usize {
    outcome
        .removed
        .iter()
        .filter(|c| counts_as_cleaned(c))
        .map(|c| c.label.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len()
}

/// Human-readable report text for a completed (`--apply`) clean, alongside the structured
/// fields — see `crate::purge::render_dry_run_text`'s doc for why this exists, and
/// `super::plan::render_plan_text`'s doc for why the summary WORDING matters here (unlike
/// purge): `bin/clean.sh`'s live-run summary line is `Tracked cleanup: … | Items cleaned: … |
/// Categories: …`, and the app's real `mergeSummaryFields` (TaskReport.swift, origin/main) keys
/// on the literal phrase "tracked cleanup". `Free space change` / `Free space now` are dropped —
/// they require a before/after free-disk-space reading this binary doesn't take; both are
/// optional accumulator fields in `TaskSummary` (default `""`), so omitting them still leaves
/// `sawSummary=true` off the "Tracked cleanup" line alone.
///
/// `Items cleaned` and `Categories` are TWO DIFFERENT counters in the shipping script and this
/// prints them as such — see [`items_cleaned`] and [`category_count`]. Printing `removed.len()`
/// for both was a straight mis-port that survived here after the dry-run half was fixed, and this
/// is the line the GUI's report card renders after a real clean, so it is the one that was actually
/// being read.
fn render_outcome_text(outcome: &CleanOutcome) -> String {
    let mut out = String::new();
    out.push_str("Clean Your Mac\n\n");
    if !outcome.removed.is_empty() {
        out.push_str("➤ Cleanup\n");
        for c in &outcome.removed {
            match c.freed {
                // `safe_clean`'s own line: description then size.
                Freed::Bytes(n) => out.push_str(&format!(
                    "  ✓ {}, {}\n",
                    c.label,
                    super::format::bytes_to_human(n)
                )),
                // `clean_tool_cache`'s line (`dev.sh:36`) is `  ✓ $description` with NO size, for
                // exactly this reason — the action happened, the number is not knowable. Same
                // shape here rather than printing a misleading `0B`.
                Freed::Delegated | Freed::AlreadyGone | Freed::Unverified => {
                    out.push_str(&format!("  ✓ {}\n", c.label))
                }
            }
        }
    }
    if !outcome.protected.is_empty() {
        out.push_str("➤ Protected\n");
        for p in &outcome.protected {
            out.push_str(&format!("  • {p}, skipped (protected)\n"));
        }
    }
    if !outcome.errors.is_empty() {
        out.push_str("➤ Errors\n");
        for RemovalError { path: p, error: e } in &outcome.errors {
            out.push_str(&format!("  ✗ {p}: {e}\n"));
        }
    }
    out.push('\n');
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Cleanup complete\n");
    // `if [[ $total_size_cleaned -gt 0 ]]` (`bin/clean.sh:1330`) gates the whole summary block.
    // bash only ever `rm -rf`s, so its one counter IS freed space; here the default path moves to
    // the Trash, and the line says so rather than calling recoverable bytes "cleanup". The
    // `Tracked cleanup:` key is kept in both cases because the app's `mergeSummaryFields`
    // (TaskReport.swift) keys on that literal phrase to find the value.
    if outcome.accounted_bytes() > 0 {
        let items = items_cleaned(outcome);
        let categories = category_count(outcome);
        out.push_str(&format!(
            "Tracked cleanup: {}",
            super::format::bytes_to_human(outcome.accounted_bytes())
        ));
        if outcome.moved_to_trash_bytes > 0 {
            out.push_str(" (moved to Trash)");
        }
        // The same three-way append as `bin/clean.sh:1356-1362`, kept literally even though the
        // two counters here can only be zero or non-zero together: they are independent
        // accumulators in the oracle and a future counting change should not silently start
        // printing ` | Items cleaned: 0`.
        match (items > 0, categories > 0) {
            (true, true) => out.push_str(&format!(
                " | Items cleaned: {items} | Categories: {categories}\n"
            )),
            (true, false) => out.push_str(&format!(" | Items cleaned: {items}\n")),
            (false, true) => out.push_str(&format!(" | Categories: {categories}\n")),
            (false, false) => out.push('\n'),
        }
    } else {
        out.push_str("Nothing to clean.\n");
    }
    out.push_str(RULE);
    out
}

/// Serialize a destructive clean outcome:
/// `{dry_run:false,freed_bytes,freed_human,moved_to_trash_bytes,moved_to_trash_human,removed:[{path,size,accounted}],errors:[{path,error}],protected:[…],text:S}`.
/// `moved_to_trash_bytes` is additive: on the default path `freed_bytes` is 0 and the verified
/// bytes are reported there, because a Trash move frees no space (RULEBOOK §3m).
/// This IS what `src/cli.rs`'s `clean --apply` path calls today (its `data` for both the streaming
/// and buffered destructive branches). `protected` is additive over the shape's earliest form —
/// `CleanOutcome` already carries it (purge's own `outcome_to_json` does the same) — extra fields
/// are free per RULEBOOK RULE 1.
///
/// `removed[].size` is what this run can PROVE it freed for that item, so it sums to `freed_bytes`
/// exactly; `accounted:false` marks the items where the true figure is unknown rather than zero
/// (a tool cleaned its own cache, or an ancestor in this same run already took the path), so a
/// consumer can tell "freed nothing" from "cannot say".
pub fn outcome_to_json(outcome: &CleanOutcome) -> String {
    let removed = outcome
        .removed
        .iter()
        .map(|c| {
            format!(
                "{{\"path\":{},\"size\":{},\"accounted\":{}}}",
                esc(&c.path),
                c.bytes(),
                c.is_auditable_deletion()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let errors = outcome
        .errors
        .iter()
        .map(|e| format!("{{\"path\":{},\"error\":{}}}", esc(&e.path), esc(&e.error)))
        .collect::<Vec<_>>()
        .join(",");
    let protected = outcome
        .protected
        .iter()
        .map(|p| esc(p))
        .collect::<Vec<_>>()
        .join(",");
    let text = render_outcome_text(outcome);
    format!(
        "{{\"dry_run\":false,\"freed_bytes\":{},\"freed_human\":{},\"moved_to_trash_bytes\":{},\"moved_to_trash_human\":{},\"removed\":[{removed}],\"errors\":[{errors}],\"protected\":[{protected}],\"text\":{}}}",
        outcome.freed_bytes,
        esc(&super::format::bytes_to_human(outcome.freed_bytes)),
        outcome.moved_to_trash_bytes,
        esc(&super::format::bytes_to_human(outcome.moved_to_trash_bytes)),
        esc(&text)
    )
}

#[cfg(test)]
mod tests {
    use super::super::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS;
    use super::*;

    // Some tests in this module are `#[cfg(unix)]`. They assert POSIX-shaped filesystem
    // behaviour, which is the only shape this engine's path vocabulary has: the clean target
    // table is entirely `~/Library/...`, the protection tables are macOS paths, the glob expander
    // splits on `/`, and `clean::validate::validate_path_for_deletion` refuses OUTRIGHT off unix
    // rather than pretending otherwise. Read the guard comment in that function before ungating
    // any of them — it is the reason these are gated rather than "fixed", and the reason making
    // them pass on Windows is a protection-table port, not a test change.

    fn candidate(path: &str, size: u64) -> CleanCandidate {
        CleanCandidate {
            path: path.into(),
            label: "t".into(),
            size,
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("burrow_clean_exec_{}_{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(unix)]
    #[test]
    fn inaccessible_after_removal_is_not_proof_that_bytes_were_freed() {
        use std::os::unix::fs::PermissionsExt;
        if crate::platform::is_privileged() {
            return; // Root can traverse the fixture despite its mode bits.
        }
        let root = scratch("unverifiable");
        let file = root.join("cache");
        fs::write(&file, b"still present").unwrap();
        let outcome = execute_clean_with_remover(
            &[candidate(file.to_str().unwrap(), 13)],
            &[],
            true,
            ProtectionMode::Cleanup,
            |_| {},
            |_, _| {
                fs::set_permissions(&root, fs::Permissions::from_mode(0o0)).unwrap();
                Ok(Removal::Removed)
            },
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(file.exists());
        assert_eq!(outcome.freed_bytes, 0);
        assert_eq!(outcome.removed[0].freed, Freed::Unverified);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn removes_files_and_dirs_and_tallies_freed() {
        let root = scratch("remove");
        let dir = root.join("cache");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.bin"), vec![b'x'; 10]).unwrap();
        let file = root.join("log.txt");
        fs::write(&file, vec![b'y'; 5]).unwrap();

        let plan = vec![
            candidate(dir.to_str().unwrap(), 100),
            candidate(file.to_str().unwrap(), 20),
        ];
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert_eq!(out.removed.len(), 2);
        assert_eq!(out.freed_bytes, 15); // current measured bytes, not stale plan estimates
        assert!(out.errors.is_empty());
        assert!(
            !dir.exists() && !file.exists(),
            "both were actually removed"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn execute_with_emits_an_event_per_candidate_in_order() {
        let root = scratch("emit");
        let gone = root.join("cache");
        fs::create_dir_all(&gone).unwrap();
        fs::write(gone.join("blob"), [b'x'; 50]).unwrap();
        let keep = root.join("keep");
        fs::create_dir_all(&keep).unwrap();
        let missing = root.join("nope");

        let plan = vec![
            candidate(gone.to_str().unwrap(), 50),
            candidate(keep.to_str().unwrap(), 10),
            candidate(missing.to_str().unwrap(), 5),
        ];
        let mut events = Vec::new();
        let out = execute_clean_with(
            &plan,
            &[keep.to_str().unwrap()],
            true,
            ProtectionMode::Cleanup,
            |e| {
                events.push(format!("{e:?}"));
            },
        );
        // One event per candidate the executor ACTED on, in plan order: removed, then protected
        // (whitelisted). The third candidate is not there, and bash's `[[ -e "$path" ]]`
        // (`bin/clean.sh:614`) drops such a path before every counter and every log line — it is
        // neither a failure nor a removal, so it produces no event at all.
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(events[0].starts_with("Removed"), "{:?}", events);
        assert!(events[1].starts_with("Protected"), "{:?}", events);
        assert!(
            !events.iter().any(|e| e.contains("size: 0")),
            "no zero-byte phantom removal is announced: {events:?}"
        );
        // The outcome matches the non-streaming path exactly.
        assert_eq!(out.removed.len(), 1);
        assert_eq!(out.protected.len(), 1);
        assert!(out.errors.is_empty(), "{out:?}");
        assert_eq!(out.freed_bytes, 50);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn re_check_protects_a_whitelisted_path_even_in_the_plan() {
        let root = scratch("protect");
        let keep = root.join("keep");
        fs::create_dir_all(&keep).unwrap();
        fs::write(keep.join("important"), b"data").unwrap();

        // The path slipped into the plan, but the whitelist re-check must spare it.
        let plan = vec![candidate(keep.to_str().unwrap(), 999)];
        let out = execute_clean(
            &plan,
            &[keep.to_str().unwrap()],
            true,
            ProtectionMode::Cleanup,
        );
        assert!(out.removed.is_empty());
        assert_eq!(out.protected, vec![keep.to_string_lossy().to_string()]);
        assert!(keep.join("important").exists(), "protected path survives");
        let _ = fs::remove_dir_all(&root);
    }

    // -- the third rail at the removal site. `safe_clean`'s two filters pass these paths happily;
    // `safe_remove`'s `validate_path_for_deletion` is the only thing between them and `rm -rf`.

    #[cfg(unix)]
    #[test]
    fn the_third_rail_refuses_a_path_the_oracle_refuses_and_leaves_it_on_disk() {
        // A directory whose NAME embeds a newline. Not hypothetical: `~/Library/Logs` on the
        // machine this was written against holds four of them (some tool `mkdir -p`'d an unescaped
        // JSON fragment), all four are in the engine's live 321-path plan, and running that plan
        // through the REAL bash `validate_path_for_deletion` refuses exactly those four. Neither of
        // the other two rails looks at control characters, so without this one the engine deletes
        // what the oracle cannot.
        //
        // check_tests: no-golden — the oracle's verdict for this shape is pinned by
        // `validate.rs`'s fixture-loading tests; what this adds is that the EXECUTOR consults the
        // rail at all, which is a property of this loop and of no capture.
        let root = scratch("third_rail_newline");
        let weird = root.join("mole\n{\"name\": \"Arc\"}");
        fs::create_dir_all(&weird).unwrap();
        fs::write(weird.join("payload"), b"must survive").unwrap();

        let plan = vec![candidate(weird.to_str().unwrap(), 42)];
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert!(out.removed.is_empty(), "nothing may be removed: {out:?}");
        assert!(
            out.errors.is_empty(),
            "a policy refusal is not an error: {out:?}"
        );
        assert_eq!(out.protected.len(), 1);
        assert!(
            weird.join("payload").exists(),
            "the refused path must still be on disk"
        );
        assert_eq!(out.freed_bytes, 0);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_third_rail_refuses_the_critical_system_paths_the_planner_can_still_name() {
        // `plan.rs` carries `/Library/Apple/usr/share/rosetta/rosetta_update_bundle`, transcribed
        // from `lib/clean/user.sh:2109` — a `safe_clean` call that is DEAD CODE in the oracle
        // because `_mole_is_critical_deletion_path` matches `/Library/Apple/*`. These paths are not
        // created by the test (they are real system locations); the point is that the executor
        // declines them before any filesystem call, which is observable without touching anything.
        for p in [
            "/Library/Apple/usr/share/rosetta/rosetta_update_bundle",
            "/System/Library/whatever",
            "/usr/lib/libSystem.dylib",
            "/private/var/db/something",
        ] {
            let out = execute_clean(&[candidate(p, 1)], &[], true, ProtectionMode::Cleanup);
            assert!(out.removed.is_empty(), "{p} must not be removed");
            assert!(out.errors.is_empty(), "{p} is a refusal, not an error");
            assert_eq!(out.protected, vec![p.to_string()], "{p}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_third_rail_applies_to_uninstall_too_because_the_oracle_runs_it_there_as_well() {
        // `mole_delete` (`file_ops.sh:522`) validates before it deletes, so the uninstall path gets
        // the same rail — just under the weaker protection regime. A control character is refused
        // in BOTH modes; only the `should_protect_path` step inside it is mode-sensitive.
        let root = scratch("third_rail_uninstall");
        let weird = root.join("com.foo\nBar");
        fs::create_dir_all(&weird).unwrap();
        let plan = vec![candidate(weird.to_str().unwrap(), 7)];
        let out = execute_clean(&plan, &[], true, ProtectionMode::Uninstall);
        assert!(out.removed.is_empty());
        assert_eq!(out.protected.len(), 1);
        assert!(weird.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn the_mode_decides_whether_a_data_protected_leftover_survives_the_executor() {
        // The defect, at the layer it actually bit: the SAME plan through the SAME executor, with
        // only the mode differing. Cleanup protects a JetBrains cache; uninstall removes it.
        let root = scratch("mode_decides");
        let leftover = root.join("Library/Caches/com.jetbrains.goland");
        fs::create_dir_all(&leftover).unwrap();
        fs::write(leftover.join("blob"), b"cache").unwrap();
        let plan = vec![candidate(leftover.to_str().unwrap(), 5)];

        let cleanup = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert_eq!(
            cleanup.protected.len(),
            1,
            "cleanup must spare it: {cleanup:?}"
        );
        assert!(leftover.exists());

        let uninstall = execute_clean(&plan, &[], true, ProtectionMode::Uninstall);
        assert_eq!(
            uninstall.removed.len(),
            1,
            "uninstall must remove it: {uninstall:?}"
        );
        assert!(uninstall.protected.is_empty());
        assert!(!leftover.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_target_is_skipped_silently_and_never_a_panic() {
        // `bin/clean.sh:614` collects a path only `if [[ -e "$path" ]]`, and `safe_remove` returns
        // 0 for one that is not there (`file_ops.sh:230-232`) — before the only line in it that
        // writes `log_operation … "REMOVED"` (`:300`). Nothing about a missing path is a failure in
        // digger, and nothing about it is an EVENT either: it is filtered out ahead of both
        // counters (`files_cleaned` at `:962`, `total_items` at `:964`) and ahead of the log. So no
        // error, no bytes, no `removed` entry, and nothing an exit code could be derived from.
        let out = execute_clean(
            &[candidate("/no/such/burrow-xyz", 1)],
            &[],
            true,
            ProtectionMode::Cleanup,
        );
        assert!(out.errors.is_empty(), "{out:?}");
        assert_eq!(out.freed_bytes, 0);
        assert!(
            out.removed.is_empty(),
            "a path that was never there is counted nowhere and logged nowhere: {out:?}"
        );

        // Those three hold on EVERY platform, which is why this test is not `#[cfg(unix)]` like
        // its neighbours: "a missing target never panics and never bills" is not a POSIX claim.
        //
        // Where it lands when it is NOT skipped is platform-specific, and only because the rail
        // ORDER says so. `/no/such/burrow-xyz` is a POSIX literal; off unix
        // `crate::clean::validate`'s platform guard refuses it before the existence check below
        // ever runs, and this executor reports a candidate that fails validation as `protected`
        // rather than as already-gone — deliberately, because that is the order bash resolves the
        // two in (`file_ops.sh:224-231`: validate, THEN `[[ ! -e "$path" ]]`). So the refusal
        // showing up here is the documented ordering doing its job, not the missing-path rule
        // breaking.
        if RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            assert!(
                out.protected.is_empty(),
                "on unix the rails pass this path and it is then skipped for being absent: {out:?}"
            );
        } else {
            assert_eq!(
                out.protected,
                vec!["/no/such/burrow-xyz".to_string()],
                "off unix the platform guard refuses it before absence is ever tested: {out:?}"
            );
        }
    }

    // -- overlap: a coarse sweep (e.g. `~/Library/Caches/*`) and a specific sub-path nested under
    // it (e.g. `~/Library/Caches/com.foo.Bar/*`) can both name candidates for the SAME bytes. The
    // real target table added by this port contains exactly this shape (a generic children-only
    // sweep alongside hundreds of app-specific sub-paths it can subsume) — proven live against
    // the real compiled binary and a scratch HOME during this port's own manual verification
    // before this regression test was written.

    #[cfg(unix)]
    #[test]
    fn a_parent_removed_earlier_in_the_same_run_leaves_a_later_missing_child_billing_nothing() {
        let root = scratch("overlap_parent_then_child");
        let parent = root.join("Library/Caches/com.example.foo");
        fs::create_dir_all(&parent).unwrap();
        fs::write(parent.join("data"), vec![b'x'; 23]).unwrap();
        let child = parent.join("data");

        // Plan order matters and mirrors the real target table: the coarse sweep candidate
        // (the whole `com.example.foo` dir, as matched by `~/Library/Caches/*`) comes FIRST, the
        // specific sub-target (`com.example.foo/data`) comes SECOND — exactly like "User caches"
        // sits before "Figma cache" &c. in `plan::UNIVERSAL_TARGETS`.
        let plan = vec![
            candidate(parent.to_str().unwrap(), 23),
            candidate(child.to_str().unwrap(), 23),
        ];
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);

        assert_eq!(
            out.errors,
            Vec::new(),
            "the already-gone child must never be an error: {out:?}"
        );
        assert_eq!(
            out.removed.len(),
            1,
            "one filesystem call happened, so exactly one item may be reported — bash re-scans on \
             every `safe_clean` call, so its second call never collects the child at all: {out:?}"
        );
        assert_eq!(
            out.freed_bytes, 23,
            "the child's bytes must NOT be double-counted on top of the parent's: {out:?}"
        );
        // …and nothing carries the child's stale plan size, so `sum(removed[].bytes())` equals
        // `freed_bytes` instead of exceeding it — which is also what stops `cli.rs` writing a
        // `REMOVED` operations row and a `trash 23KB ok` audit line for a path this step never
        // touched.
        assert_eq!(out.removed[0].freed, Freed::Bytes(23));
        assert_eq!(out.removed[0].path, parent.to_string_lossy());
        let summed: u64 = out.removed.iter().map(|r| r.bytes()).sum();
        assert_eq!(summed, out.freed_bytes, "{out:?}");
        assert!(!parent.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_remover_that_reports_success_without_deleting_is_billed_nothing() {
        // "Verified after the fact" (RULEBOOK §3m) as a property of the CODE: the executor bills
        // `c.size` only once the path is confirmed gone. A remover that returns `Ok` while the
        // path is demonstrably still on disk — which is precisely what a tool-delegation shim did
        // — gets zero bytes and no auditable deletion, whatever it claimed.
        let root = scratch("unverified_removal");
        let target = root.join("still_here");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("data"), vec![b'z'; 4096]).unwrap();

        let plan = vec![candidate(target.to_str().unwrap(), 999_999)];
        let lying_remover =
            |_p: &Path, _permanent: bool| -> Result<Removal, String> { Ok(Removal::Removed) };
        let out = execute_clean_with_remover(
            &plan,
            &[],
            true,
            ProtectionMode::Cleanup,
            |_| {},
            lying_remover,
        );
        assert_eq!(out.freed_bytes, 0, "{out:?}");
        assert_eq!(out.removed.len(), 1);
        assert_eq!(out.removed[0].freed, Freed::Unverified);
        assert!(!out.removed[0].is_auditable_deletion());
        assert!(
            target.join("data").exists(),
            "fixture sanity: the remover really did leave it there"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_partial_sweep_bills_only_what_the_sweep_measured() {
        // `Removal::Swept` carries its own measurement because the parent's planned size counts
        // children the sweep deliberately spared. A remover reporting `Swept { bytes: 40 }` for a
        // candidate planned at 10 MB must bill 40, not 10 MB.
        let root = scratch("swept_billing");
        let dir = root.join("cache");
        fs::create_dir_all(&dir).unwrap();
        let plan = vec![candidate(dir.to_str().unwrap(), 10 * 1024 * 1024)];
        let sweeper = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            Ok(Removal::Swept { bytes: 40 })
        };
        let out =
            execute_clean_with_remover(&plan, &[], true, ProtectionMode::Cleanup, |_| {}, sweeper);
        assert_eq!(out.freed_bytes, 40, "{out:?}");
        assert_eq!(out.removed[0].freed, Freed::Bytes(40));
        assert!(
            out.removed[0].is_auditable_deletion(),
            "a real (if partial) removal by this engine IS auditable"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_deleted_by_something_else_between_plan_and_apply_does_not_fail_the_run() {
        // THE RACE THIS EXISTS FOR. `~/Library/Caches` is live — apps delete their own cache
        // subdirectories while `clean` is running — and the plan phase walks the whole tree with
        // `dir_size` before the removal loop starts, so a planned candidate can be gone by the time
        // the loop reaches it, through nothing this run did.
        //
        // The plan is built by the real planner against a real fixture (not hand-assembled), then
        // an out-of-band deletion stands in for the other process, exactly as the filesystem would
        // present it to the executor. digger tolerates this by construction: `safe_remove` returns
        // success for a path that is not there (`file_ops.sh:230-232`), and `bin/clean.sh` ends
        // `exit 0` regardless. `cli.rs` derives its exit code from `outcome.errors`, so the
        // assertion that matters is that `errors` stays EMPTY.
        //
        // What it must NOT do is report the vanished path as something it cleaned. bash's own
        // filter is `[[ -e "$path" ]]` at `bin/clean.sh:614`, before the counters, and its only
        // `log_operation … "REMOVED"` (`file_ops.sh:300`) sits past `safe_remove`'s early return —
        // so a path that is not there is counted nowhere and logged nowhere.
        let home = scratch("external_deletion_race");
        let doomed = home.join("Library/Caches/com.example.evaporates");
        fs::create_dir_all(&doomed).unwrap();
        fs::write(doomed.join("blob"), vec![b'x'; 2048]).unwrap();
        let survivor = home.join("Library/Caches/com.example.stays");
        fs::create_dir_all(&survivor).unwrap();
        fs::write(survivor.join("blob"), vec![b'y'; 1024]).unwrap();

        let targets = &[super::super::plan::CleanTarget {
            path: "~/Library/Caches/*",
            label: "User caches",
        }];
        let plan = super::super::plan::plan_clean(
            targets,
            home.to_str().unwrap(),
            &[],
            super::super::plan::PlanMode::Apply,
        );
        assert_eq!(plan.len(), 2, "fixture sanity: both were planned: {plan:?}");

        // …and now the other process wins the race.
        fs::remove_dir_all(&doomed).unwrap();

        let mut events = Vec::new();
        let out = execute_clean_with(&plan, &[], true, ProtectionMode::Cleanup, |e| {
            events.push(format!("{e:?}"));
        });
        assert!(
            out.errors.is_empty(),
            "a path that vanished under us must not fail the run: {out:?}"
        );
        assert_eq!(
            out.removed.len(),
            1,
            "the vanished path is reported nowhere, like bash: {out:?}"
        );
        assert!(
            !out.removed
                .iter()
                .any(|r| r.path == doomed.to_string_lossy()),
            "{out:?}"
        );
        assert_eq!(
            events.len(),
            1,
            "and it produces no stream event either, so a GUI counting lines and one reading \
             done.removed agree: {events:?}"
        );
        let summed: u64 = out.removed.iter().map(|r| r.bytes()).sum();
        assert_eq!(summed, out.freed_bytes, "{out:?}");
        assert!(
            out.freed_bytes > 0,
            "the survivor was really removed: {out:?}"
        );
        assert!(!survivor.exists());
        let _ = fs::remove_dir_all(&home);
    }

    // -- defect 2: permanent vs recoverable dispatch. These use an INJECTED remover (via
    // execute_clean_with_remover) rather than the real Trash, so they're hermetic and
    // deterministic on every CI runner — see remove_one's doc comment for why the real recoverable
    // path is proven elsewhere (crate::trash's own tests + manual verification) instead of here.

    #[cfg(unix)]
    #[test]
    fn permanent_false_is_the_default_and_reaches_the_remover_as_false() {
        // Must be a REAL, existing path — not a placeholder string — because the loop checks
        // existence before ever calling `remover`: a nonexistent candidate is recorded as already
        // gone and never reaches the remover at all, which would defeat this test's own point.
        let root = scratch("permanent_flag_false");
        let target = root.join("target");
        fs::write(&target, b"x").unwrap();
        let plan = vec![candidate(target.to_str().unwrap(), 10)];
        let seen: std::cell::RefCell<Vec<(std::path::PathBuf, bool)>> =
            std::cell::RefCell::new(Vec::new());
        let remover = |p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push((p.to_path_buf(), permanent));
            Ok(Removal::Removed)
        };
        let out =
            execute_clean_with_remover(&plan, &[], false, ProtectionMode::Cleanup, |_| {}, remover);
        assert_eq!(out.removed.len(), 1);
        assert_eq!(seen.into_inner(), vec![(target.clone(), false)]);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permanent_true_reaches_the_remover_as_true() {
        // Same real-path requirement as the test above.
        let root = scratch("permanent_flag_true");
        let target = root.join("target");
        fs::write(&target, b"x").unwrap();
        let plan = vec![candidate(target.to_str().unwrap(), 1)];
        let seen: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
        let remover = |_p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(permanent);
            Ok(Removal::Removed)
        };
        let _ =
            execute_clean_with_remover(&plan, &[], true, ProtectionMode::Cleanup, |_| {}, remover);
        assert_eq!(seen.into_inner(), vec![true]);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_recoverable_delete_is_reported_as_an_error_never_a_fallback_hard_delete() {
        // The core defect-2 guarantee: if the Trash move fails, the item is reported as an error
        // and left exactly where it was — never retried via fs::remove_dir_all/remove_file.
        let root = scratch("recover_fail");
        let target = root.join("still_here");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("data"), b"do not delete me").unwrap();

        let plan = vec![candidate(target.to_str().unwrap(), 1)];
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            Err("trash unavailable — no GUI session".into())
        };
        let out =
            execute_clean_with_remover(&plan, &[], false, ProtectionMode::Cleanup, |_| {}, remover);

        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].path, target.to_str().unwrap());
        assert!(
            target.exists() && target.join("data").exists(),
            "a failed recoverable delete must leave the path untouched, not fall back to removing \
             it a different way"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn one_items_trash_failure_does_not_abort_the_rest_of_the_run() {
        let root = scratch("partial_fail");
        let a = root.join("a");
        let b = root.join("b"); // this one's remover call will fail
        let c = root.join("c");
        for d in [&a, &b, &c] {
            fs::create_dir_all(d).unwrap();
        }
        let plan = vec![
            candidate(a.to_str().unwrap(), 1),
            candidate(b.to_str().unwrap(), 1),
            candidate(c.to_str().unwrap(), 1),
        ];
        let b_str = b.to_str().unwrap().to_string();
        let remover = move |p: &Path, _permanent: bool| -> Result<Removal, String> {
            if p.to_str() == Some(b_str.as_str()) {
                Err("simulated trash failure".into())
            } else {
                Ok(Removal::Removed)
            }
        };
        let out =
            execute_clean_with_remover(&plan, &[], false, ProtectionMode::Cleanup, |_| {}, remover);
        assert_eq!(out.removed.len(), 2, "{out:?}");
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].path, b.to_str().unwrap());
        let removed_paths: Vec<&str> = out.removed.iter().map(|c| c.path.as_str()).collect();
        assert!(removed_paths.contains(&a.to_str().unwrap()));
        assert!(removed_paths.contains(&c.to_str().unwrap()));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn permanent_true_still_uses_the_real_hard_delete_via_remove_one() {
        // remove_one itself (not just the dispatch) — permanent:true must still be the exact
        // fs::remove_dir_all/remove_file this module always used, with no Trash involved.
        let root = scratch("remove_one_permanent");
        let dir = root.join("d");
        fs::create_dir_all(&dir).unwrap();
        let file = root.join("f");
        fs::write(&file, b"x").unwrap();
        assert!(remove_one(&dir, true).is_ok());
        assert!(remove_one(&file, true).is_ok());
        assert!(!dir.exists() && !file.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn outcome_json_shape_is_additive_over_clis_current_inline_fields() {
        let out = CleanOutcome {
            removed: vec![RemovedItem {
                path: "/a/cache".into(),
                label: "User caches".into(),
                freed: Freed::Bytes(100),
            }],
            freed_bytes: 100,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/b/log".into(),
                error: "boom".into(),
            }],
            protected: vec!["/c/keep".into()],
        };
        let j = outcome_to_json(&out);
        // Every field src/cli.rs's clean() currently inlines for --apply, unchanged:
        assert!(j.contains("\"dry_run\":false"));
        assert!(j.contains("\"freed_bytes\":100"));
        assert!(j.contains("\"freed_human\":\"100B\""));
        assert!(
            j.contains("\"removed\":[{\"path\":\"/a/cache\",\"size\":100,\"accounted\":true}]"),
            "{j}"
        );
        assert!(j.contains("\"errors\":[{\"path\":\"/b/log\",\"error\":\"boom\"}]"));
        // Additive beyond what cli.rs currently inlines:
        assert!(j.contains("\"protected\":[\"/c/keep\"]"));
        assert!(j.contains("\"moved_to_trash_bytes\":0"), "{j}");
        assert!(j.contains("\"moved_to_trash_human\":\"0B\""), "{j}");
        assert!(j.contains("\"text\":\""), "text field is present: {j}");
    }

    #[test]
    // check_tests: no-golden — `accounted` has no oracle counterpart to anchor to. The bash's
    // `clean --json` emits a single `text` blob with no per-item byte accounting at all (see
    // clean.golden.json), which is the defect §3m exists to fix: this field is the engine SAYING it
    // cannot vouch for a delegated tool's bytes, so a capture of the oracle could never contain it.
    // The shape asserted below is this engine's own contract, pinned here because the Swift side
    // reads it.
    fn a_delegated_item_serializes_with_no_bytes_and_accounted_false() {
        // The JSON half of RULEBOOK §3m: a tool cleaned its own cache, so the item is reported —
        // the action happened — but with zero claimed bytes and an explicit "cannot say", never a
        // borrowed plan figure. `freed_bytes` and the sum of `removed[].size` agree.
        let out = CleanOutcome {
            removed: vec![
                RemovedItem {
                    path: "/a/uv".into(),
                    label: "uv cache".into(),
                    freed: Freed::Delegated,
                },
                RemovedItem {
                    path: "/a/real".into(),
                    label: "User caches".into(),
                    freed: Freed::Bytes(64),
                },
            ],
            freed_bytes: 64,
            moved_to_trash_bytes: 0,
            errors: Vec::new(),
            protected: Vec::new(),
        };
        let j = outcome_to_json(&out);
        assert!(
            j.contains("{\"path\":\"/a/uv\",\"size\":0,\"accounted\":false}"),
            "{j}"
        );
        assert!(
            j.contains("{\"path\":\"/a/real\",\"size\":64,\"accounted\":true}"),
            "{j}"
        );
        let summed: u64 = out.removed.iter().map(|r| r.bytes()).sum();
        assert_eq!(summed, out.freed_bytes);
    }

    /// RULEBOOK §3m, the Trash half: a Trash move frees NOTHING — the bytes sit in the Trash until
    /// the user empties it — so the default path must never report them as `freed_bytes`. They are
    /// still verified absent from the original path and reported, under their own name.
    #[cfg(unix)]
    #[test]
    fn trash_mode_bills_moved_to_trash_bytes_and_never_freed_bytes() {
        let root = scratch("trash_billing");
        let target = root.join("cache");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("blob"), vec![b'x'; 512]).unwrap();
        let plan = vec![candidate(target.to_str().unwrap(), 512)];
        // Stands in for a real Trash move: the path leaves its original location.
        let mover = |p: &Path, permanent: bool| -> Result<Removal, String> {
            assert!(!permanent, "the default path is the recoverable one");
            fs::remove_dir_all(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let out =
            execute_clean_with_remover(&plan, &[], false, ProtectionMode::Cleanup, |_| {}, mover);
        assert_eq!(out.freed_bytes, 0, "a Trash move frees no space: {out:?}");
        assert_eq!(out.moved_to_trash_bytes, 512, "{out:?}");
        assert_eq!(out.accounted_bytes(), 512);
        assert_eq!(out.removed[0].freed, Freed::Bytes(512));
        let j = outcome_to_json(&out);
        assert!(j.contains("\"freed_bytes\":0"), "{j}");
        assert!(j.contains("\"moved_to_trash_bytes\":512"), "{j}");
        let text = render_outcome_text(&out);
        assert!(
            text.contains("Tracked cleanup: 512B (moved to Trash)"),
            "the human line must say the bytes went to the Trash: {text}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permanent_mode_bills_freed_bytes_and_never_moved_to_trash_bytes() {
        let root = scratch("permanent_billing");
        let target = root.join("cache");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("blob"), [b'x'; 64]).unwrap();
        let plan = vec![candidate(target.to_str().unwrap(), 64)];
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert_eq!(out.freed_bytes, 64, "{out:?}");
        assert_eq!(out.moved_to_trash_bytes, 0);
        let text = render_outcome_text(&out);
        assert!(text.contains("Tracked cleanup: 64B |"), "{text}");
        assert!(!text.contains("moved to Trash"), "{text}");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_lying_remover_bills_nothing_in_trash_mode_either() {
        let root = scratch("trash_lying");
        let target = root.join("still_here");
        fs::create_dir_all(&target).unwrap();
        let plan = vec![candidate(target.to_str().unwrap(), 4096)];
        let lying =
            |_p: &Path, _permanent: bool| -> Result<Removal, String> { Ok(Removal::Removed) };
        let out =
            execute_clean_with_remover(&plan, &[], false, ProtectionMode::Cleanup, |_| {}, lying);
        assert_eq!(out.freed_bytes, 0, "{out:?}");
        assert_eq!(out.moved_to_trash_bytes, 0, "{out:?}");
        assert_eq!(out.removed[0].freed, Freed::Unverified);
        let _ = fs::remove_dir_all(&root);
    }

    // -- the dedup fence. `register_dry_run_cleanup_target` is registered ONLY under
    // `if [[ "$DRY_RUN" == "true" ]]` (`bin/clean.sh:614-618`, repeated verbatim at
    // `lib/clean/caches.sh:404-408` — the only two call sites in the tree). A real run has no
    // registry, so every aliased spelling reaches `safe_remove`. These prove the difference is
    // measured in BYTES LEFT ON DISK, not in report lines.

    /// Recursive REAL on-disk byte total — the fixture's own answer, read back from the filesystem
    /// rather than inferred from the plan's arithmetic.
    ///
    /// Never follows symlinks, and counts each INODE once: a hardlink pair is one set of bytes with
    /// two names, so summing per directory entry would report 800KB of "freed" space the moment one
    /// of the two names is unlinked and nothing at all was actually released. Getting that wrong is
    /// the exact accounting error these tests exist to catch, so the measuring stick may not repeat
    /// it.
    /// unix-only: the inode-once accounting below IS `(dev, ino)`, and the three tests it serves
    /// build their fixtures out of symlinks and hardlinks. There is no non-unix version of this
    /// measurement to write — see `plan::path_identity` for why the identity itself has none.
    #[cfg(unix)]
    fn bytes_on_disk(root: &Path) -> u64 {
        fn walk(root: &Path, seen: &mut std::collections::HashSet<(u64, u64)>) -> u64 {
            use std::os::unix::fs::MetadataExt;
            let mut total = 0;
            let Ok(entries) = fs::read_dir(root) else {
                return 0;
            };
            for e in entries.flatten() {
                let Ok(md) = e.path().symlink_metadata() else {
                    continue;
                };
                if md.is_dir() {
                    total += walk(&e.path(), seen);
                } else if md.is_file() && seen.insert((md.dev(), md.ino())) {
                    total += md.len();
                }
            }
            total
        }
        walk(root, &mut std::collections::HashSet::new())
    }

    /// The two shapes where deleting the surviving spelling does NOT free the identity's bytes.
    /// Both are ordinary: a cache directory symlinked onto another disk, and a hardlink pair.
    /// `~/Library/Caches/*` expands lexically (`expand_pattern` sorts), so `aa_aliasdir` is planned
    /// before `zz_realdir` and `hardlink_one` before `hardlink_two` — first-wins therefore keeps
    /// the two spellings whose removal frees nothing.
    #[cfg(unix)]
    fn aliased_caches(home: &Path) -> std::path::PathBuf {
        let caches = home.join("Library/Caches");
        let real = caches.join("zz_realdir");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("blob"), vec![b'x'; 300 * 1024]).unwrap();
        std::os::unix::fs::symlink(&real, caches.join("aa_aliasdir")).unwrap();
        let one = caches.join("hardlink_one");
        fs::write(&one, vec![b'y'; 400 * 1024]).unwrap();
        fs::hard_link(&one, caches.join("hardlink_two")).unwrap();
        caches
    }

    /// Gated with the three tests that use it: unused elsewhere means `dead_code`, and `ci.yml`
    /// runs `clippy --all-targets -- -D warnings` on every leg.
    #[cfg(unix)]
    const USER_CACHES: &[super::super::plan::CleanTarget] = &[super::super::plan::CleanTarget {
        path: "~/Library/Caches/*",
        label: "User app cache",
    }];

    #[cfg(unix)]
    #[test]
    fn applying_a_dry_run_deduped_plan_would_strand_the_bytes_it_billed_for() {
        // THE BEFORE. This is what the executor was fed until the fence was ported: the plan the
        // PREVIEW is built from. It bills `aa_aliasdir` and `hardlink_one`, and removing those two
        // names frees nothing — `remove_dir_all` on a symlink-to-directory unlinks the LINK
        // (verified by the last assertion, not assumed), and unlinking one of two hardlinks leaves
        // the inode referenced. This test is the regression's shape, kept green deliberately: if it
        // ever starts freeing everything, the two plans have stopped differing and the real one
        // below has stopped proving anything.
        use super::super::plan::{plan_clean, PlanMode};
        let home = scratch("fence_dryrun_plan_applied");
        let caches = aliased_caches(&home);
        let before = bytes_on_disk(&caches);

        let plan = plan_clean(USER_CACHES, home.to_str().unwrap(), &[], PlanMode::DryRun);
        assert_eq!(
            plan.len(),
            2,
            "fixture sanity: the preview collapses four spellings to two identities: {plan:?}"
        );
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert!(out.errors.is_empty(), "{out:?}");

        let after = bytes_on_disk(&caches);
        assert_eq!(
            after, before,
            "the deduped plan removes two names and frees NOTHING: {before} -> {after}"
        );
        assert!(
            caches.join("zz_realdir/blob").exists(),
            "the symlink's target survived being 'cleaned'"
        );
        assert!(caches.join("hardlink_two").exists());
        let _ = fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn the_apply_plan_keeps_every_spelling_and_the_bytes_actually_leave_the_disk() {
        // THE AFTER, and the reason the fence exists. Same fixture, same targets, same executor —
        // only `PlanMode::Apply` differs, which is bash's `DRY_RUN != true` branch collecting every
        // path that passes `[[ -e ]]` with no registry consulted. All four names are removed and
        // the directory is empty afterwards, measured off the filesystem.
        use super::super::plan::{plan_clean, PlanMode};
        let home = scratch("fence_apply_plan");
        let caches = aliased_caches(&home);
        assert!(
            bytes_on_disk(&caches) >= 700 * 1024,
            "fixture sanity: there are real bytes to free"
        );

        let plan = plan_clean(USER_CACHES, home.to_str().unwrap(), &[], PlanMode::Apply);
        assert_eq!(
            plan.len(),
            4,
            "the destructive path sees every spelling, like bash: {plan:?}"
        );
        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert!(out.errors.is_empty(), "{out:?}");

        assert_eq!(
            bytes_on_disk(&caches),
            0,
            "every byte the identity held is gone: {:?}",
            fs::read_dir(&caches)
                .map(|d| d.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
                .unwrap_or_default()
        );
        assert!(!caches.join("zz_realdir").exists());
        assert!(!caches.join("hardlink_two").exists());
        let _ = fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_billed_as_itself_because_that_is_all_its_removal_frees() {
        // `get_cleanup_path_size_kb` (`bin/clean.sh:471-491`) tests `-L` before anything else and
        // answers with `stat -f%z`, which is `lstat` on macOS — the length of the stored target
        // path, not the target's contents; the batch path agrees by gating `du` on
        // `[[ -d "$path" && ! -L "$path" ]]` (`:721`). Sizing THROUGH the link billed a user the
        // full weight of a directory that `remove_dir_all` leaves standing.
        use super::super::plan::{plan_clean, PlanMode};
        let home = scratch("symlink_billed_as_itself");
        let caches = aliased_caches(&home);
        let link_len = fs::symlink_metadata(caches.join("aa_aliasdir"))
            .unwrap()
            .len();
        let target_bytes = bytes_on_disk(&caches.join("zz_realdir"));
        assert!(
            link_len < target_bytes,
            "fixture sanity: {link_len} vs {target_bytes}"
        );

        let plan = plan_clean(USER_CACHES, home.to_str().unwrap(), &[], PlanMode::Apply);
        let link = plan
            .iter()
            .find(|c| c.path.ends_with("aa_aliasdir"))
            .expect("the symlink is a candidate");
        assert_eq!(
            link.size, link_len,
            "the link is sized as itself, not as what it points at: {link:?}"
        );

        // …and the bill matches, because that is genuinely all its removal freed.
        let out = execute_clean(
            std::slice::from_ref(link),
            &[],
            true,
            ProtectionMode::Cleanup,
        );
        assert_eq!(out.freed_bytes, link_len, "{out:?}");
        assert!(
            caches.join("zz_realdir/blob").exists(),
            "the target is untouched by unlinking the link"
        );
        let _ = fs::remove_dir_all(&home);
    }

    // -- text field: matched against bin/clean.sh's real live-run wording and the actual Swift
    // parser's behavior (mergeSummaryFields keys on "tracked cleanup" — see render_outcome_text's
    // doc and the repoint-redo Gate 1 harness).

    /// Replaces a one-item version of this test that asserted `Items cleaned: 1 | Categories: 1`
    /// against a hand-built outcome. On a fixture where the two counters are EQUAL, printing
    /// `removed.len()` for both passes — so it could not fail on the defect it was named for, and
    /// did not: the dry-run half of `Items`/`Categories` was fixed while this path kept printing
    /// the same number twice.
    ///
    /// This one runs the REAL planner and the REAL executor over a fixture built so the counters
    /// must differ, and takes both expected values from the fixture rather than from a literal:
    /// `files_cleaned` (`bin/clean.sh:962`) counts PATHS and `total_items` (`:964`) counts
    /// `safe_clean` CALLS — ported as distinct labels — so four directories under two labels is
    /// `4 | 2`, and any collapse of one counter into the other goes red.
    #[cfg(unix)]
    #[test]
    fn outcome_text_prints_items_and_categories_as_the_two_counters_they_are() {
        use super::super::plan::{plan_clean, CleanTarget, PlanMode};
        let home = scratch("outcome_text_counters");
        for (dir, n) in [
            ("Library/Caches/com.example.one", 700_000usize),
            ("Library/Caches/com.example.two", 400_000),
            ("Library/Logs/com.example.one", 300_000),
            ("Library/Logs/com.example.two", 100_000),
        ] {
            let d = home.join(dir);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("blob"), vec![b'x'; n]).unwrap();
        }
        let targets = &[
            CleanTarget {
                path: "~/Library/Caches/*",
                label: "User app cache",
            },
            CleanTarget {
                path: "~/Library/Logs/*",
                label: "User app logs",
            },
        ];
        let plan = plan_clean(targets, home.to_str().unwrap(), &[], PlanMode::Apply);
        let expected_items = plan.len();
        let expected_categories = targets
            .iter()
            .map(|t| t.label)
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            expected_items != expected_categories,
            "fixture sanity: the whole point is that these differ ({expected_items} paths across \
             {expected_categories} labels)"
        );

        let out = execute_clean(&plan, &[], true, ProtectionMode::Cleanup);
        assert!(out.errors.is_empty(), "{out:?}");
        let text = render_outcome_text(&out);
        assert!(text.contains("Cleanup complete"));
        // bin/clean.sh: `summary_line="Tracked cleanup: ${freed}"` then, when both counts are
        // positive, `summary_line+=" | Items cleaned: $files_cleaned | Categories: $total_items"`.
        assert!(
            text.contains(&format!(
                "Tracked cleanup: {} | Items cleaned: {expected_items} | Categories: \
                 {expected_categories}",
                super::super::format::bytes_to_human(out.freed_bytes)
            )),
            "matches bin/clean.sh's live summary line: {text}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// The protected/errored buckets still reach the text, and a DELEGATED item is printed but
    /// counted in neither counter — `clean_tool_cache` (`lib/clean/dev.sh:10-42`) echoes its
    /// description and never touches `files_cleaned` or `total_items`.
    #[test]
    fn a_tool_that_cleaned_its_own_cache_is_listed_but_counted_in_neither_counter() {
        let out = CleanOutcome {
            removed: vec![
                RemovedItem {
                    path: "/a/cache".into(),
                    label: "User app cache".into(),
                    freed: Freed::Bytes(1_500_000),
                },
                RemovedItem {
                    path: "/a/.cache/uv".into(),
                    label: "uv cache".into(),
                    freed: Freed::Delegated,
                },
            ],
            freed_bytes: 1_500_000,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/b/log".into(),
                error: "boom".into(),
            }],
            protected: vec!["/c/keep".into()],
        };
        let text = render_outcome_text(&out);
        assert!(
            text.contains("Tracked cleanup: 1.5MB | Items cleaned: 1 | Categories: 1"),
            "the delegated item raises neither counter: {text}"
        );
        assert!(
            text.contains("uv cache"),
            "…but it is still listed, like clean_tool_cache's own line: {text}"
        );
        assert!(text.contains("User app cache"));
        assert!(
            text.contains("/c/keep"),
            "protected paths are surfaced: {text}"
        );
        assert!(
            text.contains("/b/log"),
            "errored paths are surfaced: {text}"
        );
    }

    #[test]
    fn outcome_text_matches_clean_sh_wording_when_nothing_removed() {
        let text = render_outcome_text(&CleanOutcome::default());
        assert!(text.contains("Nothing to clean."));
        assert!(!text.contains("Tracked cleanup"));
    }
}
