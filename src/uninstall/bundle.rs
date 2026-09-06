//! The `.app` bundle half of `uninstall` — the part [`super`] used to leave on disk.
//!
//! `uninstall --apply` removed an app's `~/Library` leftovers and left the application itself in
//! `/Applications`, which is not what "uninstall" means to anyone who clicks Remove. This module is
//! the port of what `lib/uninstall/batch.sh` does with `$app_path`, which is a lot more than one
//! `rm -rf`:
//!
//! ```text
//! _batch_execute_removals()                              batch.sh:700
//!   if is_brew_cask:   brew_uninstall_cask …             batch.sh:760   → brew.sh:197
//!       on failure, a THREE-WAY ladder on the cask state batch.sh:766-787
//!   elif needs_sudo:   mole_delete "$app_path" "true"    batch.sh:820
//!   else:              mole_delete "$app_path" "false"   batch.sh:829
//!   if [[ -z "$reason" ]]:  remove_file_list …           batch.sh:840
//! ```
//!
//! # Four things the oracle does here that a from-scratch design would not
//!
//! **The bundle goes FIRST and the leftovers are gated on it.** `batch.sh:840` is
//! `if [[ -z "$reason" ]]` — the leftover sweep, the system-file sweep, the `defaults delete`, the
//! login-item bootout, ALL of it only runs when the bundle came away. An app whose bundle could not
//! be removed keeps its support files too. That is surprising (you would expect a best-effort sweep)
//! and it is reproduced: half-uninstalling an app you could not uninstall leaves it broken rather
//! than merely present. See [`Plan::leftovers_follow_the_bundle`].
//!
//! **A bundle that is already gone is a SUCCESS, not a failure.** `mole_delete` returns 0 for a path
//! that does not exist (`file_ops.sh:511-513`), so `reason` stays empty and the leftovers are still
//! swept. [`BundleState::Absent`] is that case, and it is deliberately not an error.
//!
//! **Trash vs permanent is not a separate decision for the bundle.** `mole_delete` routes on
//! `MOLE_DELETE_MODE`, which `bin/uninstall.sh:1322` sets to `trash` for the whole command and
//! `--permanent` (`:1339-1341`) flips. So the `.app` lands in the Trash on the default path exactly
//! like the caches do, and a user who removed the wrong app can Put Back a 4 GB bundle. The engine
//! reuses the same `permanent` flag for the same reason — there is no bundle-specific override, in
//! either program.
//!
//! **Homebrew casks are uninstalled BY BREW, with `--zap`, or not at all.** `brew.sh:230` is
//! `brew uninstall --cask --zap "$cask_name"` — the brief's "`brew uninstall --cask`" is missing the
//! `--zap`, and `--zap` is the whole problem: it runs the cask's own zap stanza, which deletes paths
//! no enumeration here can predict. The oracle's preview says so out loud (`batch.sh:585`,
//! "Homebrew apps will be fully cleaned, --zap removes configs and data") and this port carries the
//! same declaration into the dry run's `external_commands`, because a preview that silently omits an
//! unbounded delete is worse than one that names it. Falling back to deleting the bundle by hand
//! when brew is merely UNHAPPY is refused for the reason `batch.sh:764-766` gives: it "would recreate
//! the mismatch where brew still reports the app as installed after Mole removes the bundle
//! manually".
//!
//! # Sudo, and the one thing this engine cannot do
//!
//! The oracle computes `needs_sudo` (`batch.sh:491-497`) and, when set, deletes through
//! `sudo -n rm -rf`. This engine has no elevated path of its own — the app runs the whole binary
//! under `do shell script … with administrator privileges` when it needs one. So [`needs_admin`] is
//! computed the same way and REPORTED (the caller decides whether to re-launch elevated), and the
//! removal is attempted regardless: refusing up front would break the one context that can actually
//! succeed, and attempting costs nothing but an `EPERM` that is reported as a per-app failure with
//! the oracle's own `diagnose_removal_failure` wording (`file_ops.sh:992-1027`).
//!
//! Running elevated has a trap of its own, and it is not this module's to fix: `$HOME` becomes
//! `/var/root`, so the leftover enumeration looks in root's `~/Library` and finds nothing while the
//! bundle removal succeeds. That is a report that says "removed the application, it had no support
//! files" about an app with 400 MB of them. [`elevated_home_warning`] detects the shape and says so.

use crate::analyze::scanner::dir_size;
use crate::clean::plan::CleanCandidate;
use std::path::Path;
use std::time::Duration;

/// The label a bundle candidate carries into `items[]`/`removed[]`. `UninstallPreview.classify`
/// (`UninstallPreview.swift:107-109`) already maps any path ending in `.app` to its `.application`
/// kind, so the GUI renders this correctly the moment the path appears — the label is for the
/// text/agent readers.
pub const BUNDLE_LABEL: &str = "Application";

/// How the oracle would remove THIS bundle — decided before anything is touched, so a dry run can
/// state it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleAction {
    /// `mole_delete "$app_path" "$needs_sudo"` (`batch.sh:820`, `:829`). Routed through the same
    /// Trash-or-permanent switch as every other path this command removes.
    Delete,
    /// `brew uninstall --cask --zap <token>` (`brew.sh:230`), for an app the inventory resolved to a
    /// Homebrew cask. Removes bytes outside the enumerated set — see the module docs.
    BrewZap(String),
}

/// One app's bundle, as it looks before anything is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleTarget {
    pub path: String,
    /// Bytes on disk, `0` when the bundle is not there. The oracle's `total_kb` is
    /// `app_size_kb + related_size_kb` (`batch.sh:521`), so this belongs in the preview total.
    pub size: u64,
    pub present: bool,
    /// The oracle's `needs_sudo` (`batch.sh:491-497`). Advisory here — see the module docs.
    pub needs_admin: bool,
    pub action: BundleAction,
    /// `Some(reason)` when the third rail (`validate_path_for_deletion`) already refuses this path.
    /// Computed for the DRY RUN too, because the oracle runs `mole_delete` even in dry-run mode on
    /// the sudo branch precisely to surface `"dry-run path validation failed"` (`batch.sh:816-818`).
    /// A preview that promised to remove a bundle the apply will refuse is the class of lie this
    /// port exists to stop.
    ///
    /// **Every removal arm must consult it**, not only the one that happens to re-run the rail.
    /// `remove_bundle`'s `Delete` arm goes through `execute_clean`, which checks the rail per item;
    /// its `BrewZap` arm spawns `brew uninstall --cask --zap` and checks nothing. So a preview that
    /// reported `refusal` and `removes_applications: 0` was followed by an apply that zapped the
    /// cask anyway — the preview and the apply disagreeing about the same run.
    pub refusal: Option<String>,
    /// `Some(target)` when the `.app` is itself a SYMLINK. Removing it unlinks the name and leaves
    /// the target installed, so this is the difference between "the application is gone" and "a
    /// shortcut to it is gone", and a report that does not carry it cannot tell a user which
    /// happened. [`BundleTarget::size`] is the LINK's own bytes for this case — see [`inspect`].
    pub symlink_target: Option<String>,
}

impl BundleTarget {
    /// The bundle as a removal candidate, so it goes through `execute_clean`'s three rails and the
    /// same Trash/permanent routing as everything else. Deliberately NOT removed by a private code
    /// path: `validate_path_for_deletion` is the third rail and the `.app` must pass it like any
    /// other path.
    pub fn candidate(&self) -> CleanCandidate {
        CleanCandidate {
            path: self.path.clone(),
            label: BUNDLE_LABEL.to_string(),
            size: self.size,
        }
    }

    /// Is the directory entry actually gone? Both probes, for the reason `execute_clean` gives
    /// (`execute.rs:279-285`): `exists()` follows symlinks so a dangling link satisfies it, and
    /// `symlink_metadata` failing would be satisfied by a link whose target went away. "The name we
    /// were asked to remove is no longer there" needs both.
    pub fn gone_from_disk(&self) -> bool {
        let p = Path::new(&self.path);
        !p.exists() && p.symlink_metadata().is_err()
    }
}

/// What actually happened to a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleState {
    /// Gone, and this engine is what removed it. `bytes` is verified-after-the-fact by
    /// `execute_clean` (or, for `Brew`, by re-`stat`ing the path), never the planned figure.
    Removed { via: RemovedVia, bytes: u64 },
    /// The path was not there when this run reached it. `mole_delete` calls that success and sweeps
    /// the leftovers anyway (`file_ops.sh:511-513`), so this does NOT set `reason`.
    Absent,
    /// A protection rail declined to touch it. Distinct from [`BundleState::Failed`] because
    /// "we refuse" and "we tried and the filesystem said no" are different facts about the machine.
    Refused { reason: String },
    /// Tried, and it did not work. `suggestion` carries the oracle's own remediation text where it
    /// has one (`diagnose_removal_failure`, `brew.sh` ladder).
    Failed {
        reason: String,
        suggestion: Option<String>,
    },
}

impl BundleState {
    /// Whether the leftover sweep may run — the port of `batch.sh:840`'s `[[ -z "$reason" ]]`.
    /// `Removed` and `Absent` are the two states that leave `reason` empty in bash.
    pub fn clears_the_leftover_gate(&self) -> bool {
        matches!(self, BundleState::Removed { .. } | BundleState::Absent)
    }

    /// The word a report uses for this state.
    pub fn word(&self) -> &'static str {
        match self {
            BundleState::Removed { .. } => "removed",
            BundleState::Absent => "absent",
            BundleState::Refused { .. } => "refused",
            BundleState::Failed { .. } => "failed",
        }
    }
}

/// Which mechanism took the bundle away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovedVia {
    /// The real macOS Trash — recoverable, the default (`MOLE_DELETE_MODE=trash`).
    Trash,
    /// `fs::remove_dir_all` — irreversible, only under `--permanent`.
    Permanent,
    /// `brew uninstall --cask --zap`. NOT recoverable: brew unlinks, it does not Trash, and `--zap`
    /// removes more than the bundle. Reported as its own mechanism so a caller never tells a user
    /// their brew-managed app is sitting in the Trash.
    Brew,
}

impl RemovedVia {
    pub fn word(self) -> &'static str {
        match self {
            RemovedVia::Trash => "trash",
            RemovedVia::Permanent => "permanent",
            RemovedVia::Brew => "brew",
        }
    }
}

// -------------------------------------------------------------------------------------------
// Inspection
// -------------------------------------------------------------------------------------------

/// Size the bundle and decide how it would be removed. Pure reporting — touches nothing.
///
/// `cask` comes from the inventory rather than being re-detected: `list::build_row` already resolves
/// the Homebrew token (`list.rs:954-956`, `source: "Homebrew"` / `uninstall_name: <token>`) through
/// the full four-stage port of `get_brew_cask_name`. Re-running that here would be a second,
/// divergent detector for the same fact.
pub fn inspect(
    app_path: &str,
    cask: Option<&str>,
    mode: crate::clean::protect::ProtectionMode,
) -> BundleTarget {
    let p = Path::new(app_path);
    // `symlink_metadata`, not `exists()`: a bundle that is a dangling symlink is still a directory
    // entry the oracle removes (`mole_delete`'s guard is `[[ ! -e "$path" && ! -L "$path" ]]`).
    let meta = p.symlink_metadata().ok();
    let present = meta.is_some();
    let symlink_target = meta
        .as_ref()
        .filter(|m| m.file_type().is_symlink())
        .map(|_| {
            std::fs::read_link(p)
                .map(|t| t.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
    // **A SYMLINKED `.app` IS SIZED BY THE LINK, NOT BY WHAT IT POINTS AT.** `is_dir()` and
    // `dir_size()` both follow symlinks; `remove_dir_all` does not (verified — the target survives,
    // and that non-following behaviour is correct and deliberate). Sizing through the link therefore
    // promised bytes the removal cannot free, and `execute_clean` then CLAIMED them: a `.app`
    // symlinked at a 4 GB bundle reported `freed_bytes: 4 GB` and `state: "removed"` while the
    // application was still installed and launchable. The link's own bytes are what goes away.
    let size = match &meta {
        None => 0,
        Some(m) if m.file_type().is_symlink() => m.len(),
        Some(m) if m.is_dir() => dir_size(p).max(0) as u64,
        Some(m) => m.len(),
    };
    let action = match cask {
        Some(token) if !token.is_empty() => BundleAction::BrewZap(token.to_string()),
        _ => BundleAction::Delete,
    };
    // The third rail, run at PREVIEW time. `execute_clean` runs it again at removal time (it must —
    // it is the rail, and it is checked per item there for every remover), so this is a report of
    // what that will say, not a substitute for it.
    let refusal = crate::clean::validate::validate_path_for_deletion(app_path, mode)
        .err()
        .or_else(|| {
            crate::clean::protect::should_protect_path(app_path, mode)
                .then(|| format!("protected path skipped: {app_path}"))
        });
    BundleTarget {
        path: app_path.to_string(),
        size,
        present,
        needs_admin: needs_admin(app_path),
        action,
        refusal,
        symlink_target,
    }
}

/// The oracle's `needs_sudo` (`batch.sh:491-497`), which is three clauses OR'd together:
///
/// ```text
/// if [[ ! -w "$(dirname "$app_path")" ]] ||
///     [[ "$app_owner" == "root" ]] ||
///     [[ -n "$app_owner" && "$app_owner" != "$current_user" ]]; then
/// ```
///
/// Identity comes from `id -u` / `id -G`, which is what the oracle does too (`whoami` at
/// `batch.sh:475`). The first draft of this took "current user" to be the owner of `$HOME`; that is
/// wrong the moment `$HOME` is somewhere the process cannot `stat` — including `/var/root` — and it
/// cannot answer the group half of the writability clause at all.
///
/// **The writability clause needs GROUPS or it is wrong on every Mac.** `[[ -w ]]` is `access(2)`
/// for the effective user INCLUDING its supplementary groups, and `/Applications` on stock macOS is
/// `drwxrwxr-x root:admin` — so an admin user really can write it, and the oracle really does answer
/// `needs_sudo=false` for a user-owned app in `/Applications`. A mode-bits-only reading (owner-write
/// if I own it, else other-write) answers `true` for EVERY app on the machine. Measured, not
/// theorised: with that reading, `/Applications/Inkscape.app` — owned by the logged-in user —
/// reported `needs_admin: true`, and a GUI acting on that would elevate for an uninstall that needs
/// no elevation, which is precisely the path that lands `$HOME` on `/var/root` and silently drops the
/// user's leftovers (see [`elevated_home_warning`]). Over-reporting here is not the safe direction.
///
/// ACLs are still not consulted, so this remains an approximation of `access(2)` — but of the same
/// shape and the same order as the oracle's, rather than a different question.
#[cfg(unix)]
fn needs_admin(app_path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(app_path) else {
        return false;
    };
    let me = current_uid();
    // Root writes anything, so nothing needs further elevation. This is also the elevated-launch
    // case, where reporting "needs admin" while ALREADY admin would be actively misleading.
    if me == Some(0) {
        return false;
    }
    let owner = meta.uid();
    if owner == 0 {
        return true;
    }
    if me.is_some_and(|me| me != owner) {
        return true;
    }
    let parent = Path::new(app_path).parent().unwrap_or(Path::new("/"));
    !dir_is_writable(parent, me)
}

/// `access(W_OK)` for a directory, resolved the way the kernel resolves it: owner bits if I own it,
/// else group bits if I am in its group, else other bits.
#[cfg(unix)]
fn dir_is_writable(dir: &Path, me: Option<u32>) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::metadata(dir) else {
        return false;
    };
    let mode = m.mode();
    if me.is_some_and(|u| u == m.uid()) {
        return mode & 0o200 != 0;
    }
    if current_groups().contains(&m.gid()) {
        return mode & 0o020 != 0;
    }
    mode & 0o002 != 0
}

/// The budget for `id`. It is a tiny built-in that returns immediately; this only exists so a wedged
/// filesystem underneath `/usr/bin` cannot hang a destructive command.
#[cfg(unix)]
const ID_TIMEOUT: Duration = Duration::from_secs(5);

/// The effective uid, via `id -u` — the same shell-out family the oracle uses (`whoami`), memoised
/// because identity cannot change inside one process and a multi-app request would otherwise spawn
/// one per app.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    static UID: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
    *UID.get_or_init(|| {
        crate::status::collect::run_command_with_timeout("id", &["-u"], ID_TIMEOUT)
            .and_then(|s| s.trim().parse().ok())
    })
}

/// The supplementary group list, via `id -G`. Empty when it cannot be read, which makes
/// [`dir_is_writable`] fall through to the other-bits check — the conservative answer, and the one
/// that was the ONLY answer before this existed.
#[cfg(unix)]
fn current_groups() -> &'static [u32] {
    static GROUPS: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    GROUPS.get_or_init(|| {
        crate::status::collect::run_command_with_timeout("id", &["-G"], ID_TIMEOUT)
            .map(|s| {
                s.split_whitespace()
                    .filter_map(|t| t.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Off unix there is no owner to compare and no elevated path to ask for, so this is honestly
/// `false` rather than a guess. `uninstall` is macOS-only in practice (`list::collect` scans
/// `/Applications`), so this arm exists to keep the crate compiling for the Windows and Linux clippy
/// targets, not because it will run.
#[cfg(not(unix))]
fn needs_admin(_app_path: &str) -> bool {
    false
}

/// The warning for the elevated-launch trap, or `None`. See the module docs: under
/// `do shell script … with administrator privileges` the engine's `$HOME` is `/var/root`, so the
/// leftover enumeration answers for root's library and reports "no support files" about an app that
/// has plenty. Detected by shape (`home` is root's) rather than by reading `SUDO_USER`, because
/// AppleScript's elevation is not `sudo` and sets no such variable.
pub fn elevated_home_warning(home: &str) -> Option<String> {
    (home == "/var/root" || home == "/private/var/root").then(|| {
        format!(
            "running as root: leftover support files were looked for under {home}, not the \
             logged-in user's home, so this run can only see root's own ~/Library. The application \
             bundle is unaffected; re-run unelevated to enumerate the user's leftovers."
        )
    })
}

// -------------------------------------------------------------------------------------------
// Homebrew
// -------------------------------------------------------------------------------------------

/// A bounded subprocess, injected so every brew decision in this module is testable without a
/// Homebrew on the machine — and, far more importantly, without any test being one bad fixture away
/// from running `brew uninstall --cask --zap` for real. Mirrors
/// `crate::status::collect::run_command_with_timeout`'s contract: `Some(stdout)` on a zero exit
/// inside the budget, `None` on anything else.
pub type Runner<'a> = &'a dyn Fn(&str, &[&str], Duration) -> Option<String>;

/// The real one.
pub fn system_runner(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    crate::status::collect::run_command_with_timeout(program, args, timeout)
}

/// `is_brew_cask_installed` (`brew.sh:42-51`) — and its THREE exit codes, which the failure ladder
/// at `batch.sh:766-787` reads individually. Collapsing "not installed" and "cannot tell" into one
/// boolean is exactly what would turn a refusal into a silent hand-deletion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaskState {
    /// `brew list --cask` still lists it. Oracle exit 0.
    Installed,
    /// `brew list --cask` ran and did not list it. Oracle exit 1.
    NotInstalled,
    /// No brew, or the listing failed. Oracle exit 2 — and NOT the same as "not installed".
    Unknown,
}

/// `brew list --cask` is not bounded by the oracle at all; this budget is the same class
/// `list.rs`'s `BREW_INFO_TIMEOUT` documents ("package manager listing"), generous enough that a
/// cold Homebrew is not mistaken for a broken one.
const BREW_LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Ask Homebrew whether the cask is still installed.
///
/// There is deliberately no `is_homebrew_available` pre-check (`brew.sh:35`, `:46`): with no `brew`
/// on `PATH` the `env` prefix exits 127, the runner answers `None`, and this returns `Unknown` —
/// which is the oracle's exit 2 for that case anyway. Folding it into the one code path is what
/// makes every brew decision in this module reachable from an injected runner, so no test is ever
/// one bad fixture away from a real `brew uninstall --cask --zap`.
pub fn cask_state(token: &str, run: Runner) -> CaskState {
    if token.is_empty() {
        return CaskState::Unknown;
    }
    // The oracle's env-prefix idiom (`brew.sh:48`, and `list.rs`'s `capture_env_bounded` for the
    // same reason): the timeout helper takes a command line, not an environment.
    let Some(out) = run(
        "env",
        &["HOMEBREW_NO_ENV_HINTS=1", "brew", "list", "--cask"],
        BREW_LIST_TIMEOUT,
    ) else {
        return CaskState::Unknown;
    };
    // `grep -qxF "$cask_name"` — a WHOLE-LINE fixed-string match, not a substring one.
    if out.lines().any(|l| l == token) {
        CaskState::Installed
    } else {
        CaskState::NotInstalled
    }
}

/// The oracle's size-scaled timeout (`brew.sh:214-224`): 5 minutes, 10 for an app over 5 GB, 15 for
/// one over 15 GB. Xcode-class casks really do take that long to zap.
pub fn brew_timeout(size_bytes: u64) -> Duration {
    let gb = size_bytes / (1024 * 1024 * 1024);
    if gb > 15 {
        Duration::from_secs(900)
    } else if gb > 5 {
        Duration::from_secs(600)
    } else {
        Duration::from_secs(300)
    }
}

/// The argv for `brew uninstall --cask --zap <token>`, spelled the way the oracle spells it
/// (`brew.sh:227-240`) — the three `HOMEBREW_*`/`NONINTERACTIVE` variables via an `env` prefix, and
/// a `sudo -u "$SUDO_USER"` hop when the process was reached through `sudo` so the zap does not run
/// against root's Homebrew.
///
/// Returned as owned strings rather than run here so the shape is assertable in a test without a
/// Homebrew — this is the one argv in the engine that deletes an application, and it should be
/// pinned by something other than reading it.
pub fn brew_zap_argv(token: &str, sudo_user: Option<&str>) -> (String, Vec<String>) {
    let env_args = |mut v: Vec<String>| {
        v.extend(
            [
                "HOMEBREW_NO_ENV_HINTS=1",
                "HOMEBREW_NO_AUTO_UPDATE=1",
                "NONINTERACTIVE=1",
                "brew",
                "uninstall",
                "--cask",
                "--zap",
                token,
            ]
            .iter()
            .map(|s| (*s).to_string()),
        );
        v
    };
    match sudo_user.filter(|u| !u.is_empty()) {
        Some(user) => (
            "sudo".to_string(),
            env_args(vec!["-u".to_string(), user.to_string(), "env".to_string()]),
        ),
        None => ("env".to_string(), env_args(Vec::new())),
    }
}

/// What the brew attempt decided. The middle arm is the one a boolean would destroy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrewOutcome {
    /// brew ran, the cask is gone from `brew list`, and the bundle is gone from disk — all three,
    /// per `brew.sh:252-266`.
    Removed { bytes: u64 },
    /// brew failed AND Homebrew no longer tracks the cask (`cask_state` exit 1). This is the ONE
    /// arm where `batch.sh:777-780` permits deleting the bundle by hand, because a cask brew has
    /// already forgotten cannot produce the "brew still reports it installed" mismatch the comment
    /// at `:762-766` exists to prevent. The caller runs the ordinary delete and, if THAT fails,
    /// reports `brew cleanup incomplete, manual removal failed`.
    FallBackToDelete,
    /// brew failed and the cask is still installed, or its state could not be determined
    /// (`batch.sh:781-786`). No hand-delete: the user gets the zap command instead.
    Failed {
        reason: String,
        suggestion: Option<String>,
    },
}

/// `brew_uninstall_cask` (`brew.sh:197-266`) plus the caller's ladder (`batch.sh:760-787`), as one
/// decision. Never reached on the dry-run path — `brew.sh:201-204` returns success without running
/// anything when `MOLE_DRY_RUN=1`, and so does this port, by not being called.
///
/// The verification step is the oracle's and it matters, in BOTH directions:
///
///  - brew exiting zero is not enough. The cask must be gone from `brew list` AND the bundle must be
///    gone from disk (`brew.sh:252-266`). A cask whose zap stanza silently no-ops leaves the app in
///    place, and reporting that as removed is the failure mode this whole module corrects.
///  - **brew exiting NON-zero is not a failure either.** `brew.sh:262` is `if $cask_gone &&
///    $app_gone` — `uninstall_ok` is not one of its terms. Requiring it here turned a run that
///    really did remove the cask and the bundle into `FallBackToDelete`, which then found nothing to
///    delete and reported `absent` with `applications_removed: 0` — under-reporting a removal that
///    happened, about the one command whose whole job is removing applications. The exit status is
///    therefore deliberately not read.
///
/// bash short-circuits to failure without verifying on a TIMEOUT only (exit 124, `brew.sh:246-249`).
/// This runner collapses every non-zero exit into `None` and cannot tell a timeout apart, so it
/// verifies unconditionally — which is the right side to err on, since a timed-out zap that
/// nonetheless completed leaves exactly the state the verification tests for.
///
/// One deliberate reduction: bash reads `is_brew_cask_installed` twice (once inside
/// `brew_uninstall_cask` to verify, once in the ladder to classify), and this reads it once and uses
/// the answer for both. Nothing can change between two adjacent reads of the same listing, and the
/// second read costs another 30-second budget on a path that is already failing.
pub fn uninstall_cask(target: &BundleTarget, token: &str, run: Runner) -> BrewOutcome {
    let (program, args) = brew_zap_argv(token, std::env::var("SUDO_USER").ok().as_deref());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    // Run it, and read the STATE rather than the status — see above.
    let _ = run(&program, &argv, brew_timeout(target.size));

    let state = cask_state(token, run);
    if state == CaskState::NotInstalled && target.gone_from_disk() {
        return BrewOutcome::Removed { bytes: target.size };
    }

    let suggestion = Some(format!("Run brew uninstall --cask --zap {token}"));
    match state {
        CaskState::NotInstalled => BrewOutcome::FallBackToDelete,
        CaskState::Installed => BrewOutcome::Failed {
            reason: "brew uninstall failed, package still installed".to_string(),
            suggestion,
        },
        CaskState::Unknown => BrewOutcome::Failed {
            reason: "brew uninstall failed, package state unknown".to_string(),
            suggestion,
        },
    }
}

/// `diagnose_removal_failure` (`file_ops.sh:992-1027`), reduced to the two things this engine can
/// actually observe. bash switches on `mole_delete`'s exit code, which encodes SIP / auth / readonly
/// because it went through `sudo -n rm -rf` and parsed sudo's stderr; this engine's failures come
/// from `std::io::Error`, so the mapping is on the message rather than on an invented exit code.
/// The `suggestion` strings are the oracle's own, minus the `mole touchid` one — this engine has no
/// such command and pointing a user at it would be a fabrication.
pub fn diagnose(err: &str, needs_admin: bool) -> (String, Option<String>) {
    let lower = err.to_ascii_lowercase();
    if lower.contains("read-only") || lower.contains("read only") {
        return (
            "filesystem is read-only".to_string(),
            Some("Check if disk needs repair".to_string()),
        );
    }
    if lower.contains("operation not permitted") {
        return ("protected by macOS (SIP/MDM)".to_string(), None);
    }
    if lower.contains("permission denied") || needs_admin {
        return (
            "permission denied".to_string(),
            Some("Re-run with administrator privileges".to_string()),
        );
    }
    (format!("remove failed: {err}"), None)
}

// -------------------------------------------------------------------------------------------
// The per-app plan
// -------------------------------------------------------------------------------------------

/// One resolved app's whole removal: the bundle, and the leftovers that are gated behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub bundle: BundleTarget,
    pub leftovers: Vec<CleanCandidate>,
}

/// The `kind` an `items[]` / `removed[]` entry carries, so a caller can tell "we removed 3 support
/// directories" from "we removed the application and 3 support directories" without pattern-matching
/// on a path suffix.
pub const KIND_APPLICATION: &str = "application";
pub const KIND_LEFTOVER: &str = "leftover";

impl Plan {
    /// Everything a dry run must NAME, bundle first — the order the oracle prints it in
    /// (`batch.sh:610` prints `$app_path`, then the related files).
    ///
    /// The bundle is listed even when a rail already refuses it, because the oracle's preview lists
    /// `$app_path` unconditionally and because a caller has to be able to see that the application
    /// is in scope and will not come away. Whether its BYTES count is a separate question — see
    /// [`Plan::preview_bytes`].
    pub fn preview_items(&self) -> Vec<(&'static str, CleanCandidate)> {
        let mut v = Vec::with_capacity(self.leftovers.len() + 1);
        if self.bundle.present {
            v.push((KIND_APPLICATION, self.bundle.candidate()));
        }
        v.extend(self.leftovers.iter().map(|c| (KIND_LEFTOVER, c.clone())));
        v
    }

    /// Bytes the apply can be expected to actually free.
    ///
    /// The oracle's `total_kb` is `app_size_kb + related_size_kb` unconditionally (`batch.sh:521`),
    /// and this matches it — with ONE deliberate subtraction: **a bundle a rail already refuses
    /// frees NOTHING AT ALL, leftovers included.** Not "everything but the app": `batch.sh:840`'s
    /// `if [[ -z "$reason" ]]` gates the entire leftover sweep on the bundle having come away, this
    /// port reproduces that gate (`cli.rs`'s `gate_open`), and so a refused bundle's leftovers are
    /// never touched either. Promising them was measurable: dry run `total_bytes 9000`, apply
    /// `freed_bytes 0`, the leftover still on disk.
    ///
    /// bash cannot make the subtraction at preview time — it discovers the refusal inside
    /// `mole_delete`, during the apply. Its own correction at `batch.sh:930-935` is a DIFFERENT one
    /// and not a precedent for this: that block lives in the SUCCESS branch, subtracts leftover files
    /// `rm` failed on, never the app's own bytes, and never runs for a refused bundle. What licenses
    /// the subtraction here is simply that this engine evaluates the rail while building the preview
    /// and therefore already knows the answer bash has to wait for.
    ///
    /// Does NOT include whatever a `--zap` stanza will take — that is unbounded, and it is declared
    /// as an external command rather than guessed at.
    pub fn preview_bytes(&self) -> u64 {
        if self.bundle.refusal.is_some() {
            return 0;
        }
        self.preview_items().iter().map(|(_, c)| c.size).sum()
    }

    /// `batch.sh:840` — the gate, named so the ordering is a function a reviewer can find rather
    /// than an `if` buried in the command.
    pub fn leftovers_follow_the_bundle(state: &BundleState) -> bool {
        state.clears_the_leftover_gate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clean::protect::ProtectionMode;
    use std::fs;
    use std::sync::Mutex;

    // Some tests in this module are `#[cfg(unix)]`. They assert POSIX-shaped filesystem
    // behaviour, which is the only shape this engine's path vocabulary has: the clean target
    // table is entirely `~/Library/...`, the protection tables are macOS paths, the glob expander
    // splits on `/`, and `clean::validate::validate_path_for_deletion` refuses OUTRIGHT off unix
    // rather than pretending otherwise. Read the guard comment in that function before ungating
    // any of them — it is the reason these are gated rather than "fixed", and the reason making
    // them pass on Windows is a protection-table port, not a test change.

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("burrow_bundle_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fake `.app` with real bytes in it — the ONLY kind of application bundle any test in this
    /// crate is allowed to point a removal at.
    fn fake_app(root: &Path, name: &str, bytes: usize) -> String {
        let app = root.join(name);
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(app.join("Contents/Info.plist"), b"<plist/>").unwrap();
        fs::write(app.join("Contents/MacOS/stub"), vec![b'x'; bytes]).unwrap();
        app.to_string_lossy().to_string()
    }

    /// A runner that records what it was asked to run and answers from a script. Nothing here ever
    /// reaches a real `brew`.
    struct Recorder {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        answers: Mutex<Vec<Option<String>>>,
    }
    impl Recorder {
        fn new(answers: Vec<Option<String>>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                answers: Mutex::new(answers),
            }
        }
        fn run(&self, program: &str, args: &[&str], _t: Duration) -> Option<String> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| (*s).to_string()).collect(),
            ));
            let mut a = self.answers.lock().unwrap();
            if a.is_empty() {
                None
            } else {
                a.remove(0)
            }
        }
        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_bundle_is_sized_and_planned_as_a_plain_delete_when_no_cask_owns_it() {
        let root = scratch("plain");
        let app = fake_app(&root, "Fake.app", 4096);
        let t = inspect(&app, None, ProtectionMode::Uninstall);
        assert!(t.present);
        assert!(
            t.size >= 4096,
            "the bundle's own bytes are measured: {}",
            t.size
        );
        assert_eq!(t.action, BundleAction::Delete);
        assert_eq!(
            t.refusal, None,
            "a scratch bundle is not refused by any rail"
        );
        assert_eq!(t.candidate().label, BUNDLE_LABEL);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bundle_that_is_not_there_is_absent_and_sizes_zero() {
        let root = scratch("missing");
        let t = inspect(
            root.join("Nope.app").to_str().unwrap(),
            None,
            ProtectionMode::Uninstall,
        );
        assert!(!t.present);
        assert_eq!(t.size, 0);
        // And absence is a SUCCESS in the oracle: `mole_delete` returns 0 for a path that is not
        // there, so `reason` stays empty and the leftovers are still swept (`file_ops.sh:511-513`,
        // `batch.sh:840`).
        assert!(BundleState::Absent.clears_the_leftover_gate());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn an_inventory_cask_token_makes_the_action_a_brew_zap_not_a_delete() {
        let root = scratch("cask");
        let app = fake_app(&root, "Casky.app", 512);
        let t = inspect(&app, Some("casky"), ProtectionMode::Uninstall);
        assert_eq!(t.action, BundleAction::BrewZap("casky".to_string()));
        // An empty token must NOT become a `brew uninstall --cask --zap ''`.
        let empty = inspect(&app, Some(""), ProtectionMode::Uninstall);
        assert_eq!(empty.action, BundleAction::Delete);
        let _ = fs::remove_dir_all(&root);
    }

    /// The oracle-captured deletion-rail fixture, LOADED (RULEBOOK §3e) rather than transcribed. It
    /// already carries the `.app` rows this module needs — `/Applications/Finder.app`,
    /// `/Applications/Safari.app` and `/Applications/Other.app`, each with what the REAL bash
    /// `validate_path_for_deletion` answered for it under `MOLE_UNINSTALL_MODE=1`. Read from
    /// `clean/`'s copy: it is the same file `clean::validate`'s own conformance tests grade against,
    /// so there is no second copy to drift.
    #[cfg(unix)]
    const RAILS: &str = include_str!("../clean/deletion_rails.golden.json");

    /// What the oracle said about `path` under uninstall mode, or `None` if the fixture has no such
    /// row.
    #[cfg(unix)]
    fn oracle_allows(path: &str) -> Option<bool> {
        crate::json::Json::parse(RAILS)
            .expect("fixture parses")
            .get("paths")?
            .as_array()?
            .iter()
            .find(|r| r.get("path").and_then(crate::json::Json::as_str) == Some(path))
            .and_then(|r| {
                r.get("validate_uninstall")
                    .and_then(crate::json::Json::as_bool)
            })
    }

    /// **The third rail applies to a `.app` like any other path**, and the verdicts come from the
    /// oracle capture rather than from this test's opinion.
    ///
    /// Read the shape of the answer as carefully as the answer: `_mole_is_critical_deletion_path`
    /// covers exactly two application bundles — `/Applications/Finder.app` and
    /// `/Applications/Safari.app`, plus their subtrees — and NOT `/Applications` itself. So the rail
    /// is a filter over the directory `uninstall` targets, not a blanket refusal of it, and every
    /// other search root (`~/Applications`, both `Input Methods` folders, `/Volumes/*/Applications`)
    /// passes it untouched. Confirmed against the real bash for all seven shapes; the three the
    /// fixture carries are asserted here.
    #[cfg(unix)]
    #[test]
    fn a_critical_application_bundle_is_refused_at_preview_time_not_only_at_removal_time() {
        assert_eq!(
            oracle_allows("/Applications/Safari.app"),
            Some(false),
            "the fixture must carry Safari's bundle or this test asserts nothing"
        );
        assert_eq!(oracle_allows("/Applications/Finder.app"), Some(false));
        assert_eq!(
            oracle_allows("/Applications/Other.app"),
            Some(true),
            "and an ordinary bundle in the same directory, so this is a filter not a blanket refusal"
        );
        for (path, allowed) in [
            ("/Applications/Safari.app", false),
            ("/Applications/Finder.app", false),
            ("/Applications/Other.app", true),
        ] {
            // The rail itself — the same function `execute_clean` calls per item.
            assert_eq!(
                crate::clean::validate::validate_path_for_deletion(path, ProtectionMode::Uninstall)
                    .is_ok(),
                allowed,
                "{path} disagrees with the oracle capture"
            );
            // …and `inspect`, so a DRY RUN already says "refused" rather than promising a removal
            // the apply will decline.
            assert_eq!(
                inspect(path, None, ProtectionMode::Uninstall)
                    .refusal
                    .is_none(),
                allowed,
                "{path}: the preview's refusal must track the rail's verdict"
            );
        }
    }

    #[test]
    fn the_brew_argv_is_uninstall_cask_zap_with_the_oracles_environment() {
        let (program, args) = brew_zap_argv("bitwarden", None);
        assert_eq!(program, "env");
        assert_eq!(
            args,
            vec![
                "HOMEBREW_NO_ENV_HINTS=1",
                "HOMEBREW_NO_AUTO_UPDATE=1",
                "NONINTERACTIVE=1",
                "brew",
                "uninstall",
                "--cask",
                "--zap",
                "bitwarden",
            ],
            "`--zap` is not optional: brew.sh:230 is the oracle and it zaps"
        );
        // The `sudo -u $SUDO_USER` hop (`brew.sh:227-231`).
        let (program, args) = brew_zap_argv("bitwarden", Some("alice"));
        assert_eq!(program, "sudo");
        assert_eq!(&args[..3], &["-u", "alice", "env"]);
        assert_eq!(args.last().unwrap(), "bitwarden");
    }

    #[test]
    fn the_brew_timeout_scales_with_the_bundle_exactly_as_the_oracle_scales_it() {
        let gb = 1024 * 1024 * 1024;
        assert_eq!(brew_timeout(0), Duration::from_secs(300));
        assert_eq!(brew_timeout(5 * gb), Duration::from_secs(300));
        assert_eq!(brew_timeout(6 * gb), Duration::from_secs(600));
        assert_eq!(brew_timeout(15 * gb), Duration::from_secs(600));
        assert_eq!(brew_timeout(16 * gb), Duration::from_secs(900));
    }

    #[test]
    fn cask_state_reads_a_whole_line_match_never_a_substring_one() {
        // `grep -qxF` (`brew.sh:50`). "bitwarden-cli" must not answer for "bitwarden".
        let rec = Recorder::new(vec![Some("bitwarden-cli\nother\n".to_string())]);
        assert_eq!(
            cask_state("bitwarden", &|p, a, t| rec.run(p, a, t)),
            CaskState::NotInstalled
        );
        let rec = Recorder::new(vec![Some("bitwarden-cli\nbitwarden\n".to_string())]);
        assert_eq!(
            cask_state("bitwarden", &|p, a, t| rec.run(p, a, t)),
            CaskState::Installed
        );
        // A failed listing is "unknown", NOT "not installed" — the distinction the ladder reads.
        let rec = Recorder::new(vec![None]);
        assert_eq!(
            cask_state("bitwarden", &|p, a, t| rec.run(p, a, t)),
            CaskState::Unknown
        );
    }

    /// The ladder's load-bearing arm: brew failed and STILL reports the cask installed, so the
    /// oracle refuses to delete the bundle by hand and hands the user the zap command
    /// (`batch.sh:781-782`). Reproducing this is what stops the engine recreating the
    /// "brew says installed, app is gone" mismatch that comment warns about.
    /// The ladder's three arms, each driven by an injected `brew list --cask` answer. This is the
    /// whole reason `CaskState` has three values instead of two: collapsing "not installed" and
    /// "cannot tell" into a boolean is what would turn a refusal into a silent hand-deletion.
    #[test]
    fn the_brew_failure_ladder_reads_the_cask_state_and_only_one_arm_permits_a_hand_delete() {
        let root = scratch("brewladder");
        let app = fake_app(&root, "Casky.app", 256);
        let t = inspect(&app, Some("casky"), ProtectionMode::Uninstall);

        // brew uninstall fails, and `brew list --cask` STILL lists it (`batch.sh:781-782`).
        let rec = Recorder::new(vec![None, Some("casky\nother\n".to_string())]);
        assert_eq!(
            uninstall_cask(&t, "casky", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::Failed {
                reason: "brew uninstall failed, package still installed".to_string(),
                suggestion: Some("Run brew uninstall --cask --zap casky".to_string()),
            }
        );
        // The zap really was attempted, with `--zap`, before the listing was consulted.
        let calls = rec.calls();
        assert!(calls[0].1.contains(&"--zap".to_string()), "{:?}", calls[0]);

        // brew uninstall fails and the listing cannot be read at all (`batch.sh:784-785`).
        let rec = Recorder::new(vec![None, None]);
        assert_eq!(
            uninstall_cask(&t, "casky", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::Failed {
                reason: "brew uninstall failed, package state unknown".to_string(),
                suggestion: Some("Run brew uninstall --cask --zap casky".to_string()),
            }
        );

        // brew no longer tracks it — the ONE arm where the hand-delete is allowed
        // (`batch.sh:777-780`).
        let rec = Recorder::new(vec![None, Some("something-else\n".to_string())]);
        assert_eq!(
            uninstall_cask(&t, "casky", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::FallBackToDelete
        );

        assert!(
            Path::new(&app).exists(),
            "none of the three arms may delete the bundle from inside this function"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_brew_run_that_exits_zero_but_leaves_the_app_on_disk_is_not_a_success() {
        let root = scratch("brewliar");
        let app = fake_app(&root, "Liar.app", 128);
        let t = inspect(&app, Some("liar"), ProtectionMode::Uninstall);
        // brew "succeeds" and the cask is gone from the listing — but the bundle is still there,
        // so `brew.sh:252-266`'s three-way verification refuses to call it removed.
        let rec = Recorder::new(vec![
            Some(String::new()),
            Some("something-else\n".to_string()),
        ]);
        assert_eq!(
            uninstall_cask(&t, "liar", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::FallBackToDelete,
            "the app is still on disk, so nothing was removed"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// And the success path: the listing forgot the token and the bundle really is gone — the two
    /// conditions `brew.sh:262` actually tests.
    #[test]
    fn brew_reports_removed_only_when_both_of_the_oracles_conditions_hold() {
        let root = scratch("brewok");
        let app = fake_app(&root, "Gone.app", 1024);
        let t = inspect(&app, Some("gone"), ProtectionMode::Uninstall);
        let size = t.size;
        // Stand in for what brew would have done.
        fs::remove_dir_all(&app).unwrap();
        let rec = Recorder::new(vec![
            Some(String::new()),
            Some("something-else\n".to_string()),
        ]);
        assert_eq!(
            uninstall_cask(&t, "gone", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::Removed { bytes: size }
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_leftover_gate_is_the_oracles_reason_check_and_only_two_states_clear_it() {
        assert!(Plan::leftovers_follow_the_bundle(&BundleState::Removed {
            via: RemovedVia::Trash,
            bytes: 1
        }));
        assert!(Plan::leftovers_follow_the_bundle(&BundleState::Absent));
        assert!(!Plan::leftovers_follow_the_bundle(&BundleState::Refused {
            reason: "x".into()
        }));
        assert!(!Plan::leftovers_follow_the_bundle(&BundleState::Failed {
            reason: "x".into(),
            suggestion: None
        }));
    }

    #[cfg(unix)]
    #[test]
    fn the_preview_names_the_bundle_first_and_totals_it_with_the_leftovers() {
        let root = scratch("preview");
        let app = fake_app(&root, "Fake.app", 4096);
        let bundle = inspect(&app, None, ProtectionMode::Uninstall);
        let leftovers = vec![
            CleanCandidate {
                path: "/x/Library/Caches/com.foo".into(),
                label: "Cache".into(),
                size: 100,
            },
            CleanCandidate {
                path: "/x/Library/Logs/com.foo".into(),
                label: "Logs".into(),
                size: 20,
            },
        ];
        let bundle_size = bundle.size;
        let plan = Plan { bundle, leftovers };
        let items = plan.preview_items();
        assert_eq!(items[0].0, KIND_APPLICATION, "bundle first (batch.sh:610)");
        assert_eq!(items[0].1.label, BUNDLE_LABEL);
        assert_eq!(items.len(), 3);
        assert_eq!(
            plan.preview_bytes(),
            bundle_size + 120,
            "total_kb = app_size_kb + related_size_kb (batch.sh:521)"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A refused bundle is still NAMED in the preview — a caller must see that the application is in
    /// scope — but the run promises NO BYTES AT ALL, leftovers included, because `batch.sh:840`
    /// gates the leftover sweep on the bundle having come away. Built from the real `inspect` on a
    /// real refused path rather than by hand, so the refusal is the rail's own.
    #[test]
    fn a_refused_bundle_promises_no_bytes_at_all_not_merely_none_of_its_own() {
        let bundle = inspect("/Applications/Safari.app", None, ProtectionMode::Uninstall);
        assert!(
            bundle.refusal.is_some(),
            "the rail must refuse Safari's bundle or this test asserts nothing"
        );
        let plan = Plan {
            bundle: BundleTarget {
                // The only field forced: a size, so "the bundle's own bytes are dropped" is
                // distinguishable from "there were none".
                size: 999,
                present: true,
                ..bundle
            },
            leftovers: vec![CleanCandidate {
                path: "/x/Library/Caches/com.foo".into(),
                label: "Cache".into(),
                size: 7,
            }],
        };
        assert_eq!(plan.preview_items().len(), 2, "both are named");
        assert_eq!(plan.preview_items()[0].0, KIND_APPLICATION);
        assert_eq!(
            plan.preview_bytes(),
            0,
            "the leftovers are gated behind the bundle, so a refused bundle frees nothing"
        );
    }

    /// **A symlinked `.app` is sized by the LINK.** `dir_size`/`is_dir` follow symlinks and
    /// `remove_dir_all` does not, so sizing through the link promised — and `execute_clean` then
    /// claimed — bytes belonging to an application that is still installed.
    // cfg(unix): the body creates a real symlink, and `std::os::unix::fs::symlink` does not
    // exist on Windows — where the equivalent needs a privilege an unelevated CI runner does
    // not have. The BEHAVIOUR under test (a symlinked bundle must be sized by the link, not by
    // the application it points at) is unix-only in the same way, so this is scoping the test
    // to where the case exists rather than hiding a failure.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_bundle_is_sized_by_the_link_not_by_the_application_it_points_at() {
        let root = scratch("symlink");
        let real = fake_app(&root, "Real.app", 200_000);
        let link = root.join("Linked.app");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let target = inspect(link.to_str().unwrap(), None, ProtectionMode::Uninstall);
        assert!(
            target.present,
            "a symlinked bundle is still a directory entry"
        );
        assert_eq!(
            target.symlink_target.as_deref(),
            Some(real.as_str()),
            "the report has to carry what it points at"
        );
        assert!(
            target.size < 1024,
            "the LINK's own bytes, not the 200 KB application: {}",
            target.size
        );

        // And the removal really does leave the application behind, which is what makes the size
        // above the honest one rather than merely the conservative one.
        std::fs::remove_dir_all(&link).unwrap();
        assert!(
            Path::new(&real).join("Contents/MacOS/stub").exists(),
            "remove_dir_all unlinks the name and leaves the target — the whole point"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// `brew.sh:262` verifies by STATE (`cask_gone && app_gone`), not by exit status. A zap that
    /// exits non-zero yet fully succeeded is a removal there, and reporting it as `absent` with
    /// `applications_removed: 0` under-reports a deletion that really happened.
    #[test]
    fn a_brew_run_that_exits_nonzero_but_removed_everything_is_still_a_removal() {
        let root = scratch("brewnonzero");
        let app = fake_app(&root, "Gone.app", 1024);
        let t = inspect(&app, Some("gone"), ProtectionMode::Uninstall);
        let size = t.size;
        fs::remove_dir_all(&app).unwrap(); // stand in for what brew did
                                           // `None` for the zap — a non-zero exit — then a listing that no longer carries the token.
        let rec = Recorder::new(vec![None, Some("something-else\n".to_string())]);
        assert_eq!(
            uninstall_cask(&t, "gone", &|p, a, tm| rec.run(p, a, tm)),
            BrewOutcome::Removed { bytes: size },
            "the exit status is not one of brew.sh:262's terms"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// `needs_admin` is graded against the REAL filesystem and the REAL `id`, never against a
    /// hand-typed table: a bundle the running user owns in a directory they can write needs no
    /// elevation; one owned by root does.
    ///
    /// The `/Applications` row is the one that caught the first draft. That directory is
    /// `drwxrwxr-x root:admin` on stock macOS, so an admin user CAN write it and a user-owned app
    /// there needs no admin — a mode-bits-only reading answered `true` for every app on the machine.
    /// Skipped when the machine's own layout does not present that case, rather than asserted into
    /// existence.
    #[cfg(unix)]
    #[test]
    fn needs_admin_answers_the_kernels_question_not_a_mode_bit_approximation_of_it() {
        use std::os::unix::fs::MetadataExt;
        let root = scratch("admin");
        let mine = fake_app(&root, "Mine.app", 16);
        assert!(
            !needs_admin(&mine),
            "a bundle I own, in a directory I own, needs no elevation"
        );
        // Root-owned: `/System/Library/CoreServices/Finder.app` exists on every Mac this runs on.
        let finder = "/System/Library/CoreServices/Finder.app";
        if std::fs::symlink_metadata(finder).is_ok() {
            assert!(needs_admin(finder), "a root-owned bundle needs elevation");
        }
        // The group-writable case, read off the real machine rather than assumed.
        if let Ok(apps) = std::fs::metadata("/Applications") {
            let group_writable = apps.mode() & 0o020 != 0;
            let in_group = current_groups().contains(&apps.gid());
            let i_am_root = current_uid() == Some(0);
            if group_writable && in_group && !i_am_root {
                assert!(
                    dir_is_writable(Path::new("/Applications"), current_uid()),
                    "/Applications is {:o} and this user is in gid {} — `[[ -w ]]` is true here \
                     and so must this be",
                    apps.mode() & 0o777,
                    apps.gid()
                );
            }
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_elevated_home_trap_is_reported_rather_than_silently_producing_an_empty_leftover_list() {
        assert!(elevated_home_warning("/var/root").is_some());
        assert!(elevated_home_warning("/private/var/root").is_some());
        assert!(elevated_home_warning("/Users/alice").is_none());
    }

    #[test]
    fn a_permission_failure_is_diagnosed_with_the_oracles_own_vocabulary() {
        let (reason, sug) = diagnose("Permission denied (os error 13)", false);
        assert_eq!(reason, "permission denied");
        assert!(sug.is_some());
        let (reason, _) = diagnose("Operation not permitted (os error 1)", false);
        assert_eq!(reason, "protected by macOS (SIP/MDM)");
        let (reason, sug) = diagnose("Read-only file system (os error 30)", false);
        assert_eq!(reason, "filesystem is read-only");
        assert_eq!(sug.as_deref(), Some("Check if disk needs repair"));
    }
}
