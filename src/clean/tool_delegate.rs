//! Dev-tool caches the original PREFERS to clean via the tool's own cache-clean subcommand, falling
//! back to raw path removal only where `lib/clean/dev.sh` does — ported from `clean_corepack_cache`,
//! `clean_uv_cache`, `clean_dev_npm`'s pnpm/bun branches, `clean_dev_go`, `clean_dev_mise`,
//! `clean_conda_metadata_caches`, `clean_dev_nix`, and `clean_dev_python`'s pip branch.
//!
//! This is a DIFFERENT primitive from [`super::plan::UNIVERSAL_TARGETS`], deliberately: a static
//! `CleanTarget` is a pure pattern with no IO until plan time. Every target here needs, in some
//! combination, an env-var override with a safety guard on the resolved value, an optional
//! shell-out to ask the tool for its actual cache directory, install-location variants (conda), and
//! — the part that actually matters — a live decision about whether the TOOL cleans itself or this
//! engine touches the files directly. Folding that into the static table would either lose the
//! delegation preference entirely or silently turn every dry-run into a tool-detection pass with no
//! way to express "this tool has no safe raw fallback." Keeping it separate mirrors bash's own
//! architecture: `clean_tool_cache` is not `safe_clean`, and never was.
//!
//! # Which tools have a raw fallback, WHEN — this is not a detail, it is the guard
//!
//! Read directly off `dev.sh`, not inferred, and it is a three-way distinction rather than a
//! boolean — see [`RawSweep`], which names each case against its bash line. The short version:
//! `corepack`/`uv` sweep only on the tool-MISSING branch (their `safe_clean` is the `else` of
//! `command -v`); `bun` also sweeps after a FAILED clean command; `mise` sweeps UNCONDITIONALLY (its
//! `safe_clean` sits outside the `if command -v mise` block); `pnpm`/`go`/`conda`/`nix`/`pip` never
//! sweep at all — if the tool is missing the original does *nothing* to that cache, and the multi-GB
//! directory is left alone.
//!
//! Collapsing "missing" and "failed" into one flag is not a simplification, it is a behaviour
//! change in the destructive direction: it converts a failed or timed-out `uv cache prune` — a
//! prune of UNUSED entries — into deleting the entire uv cache, which the oracle does on no branch.
//!
//! # A PREVIEW SPAWNS NOTHING — the one deliberate deviation from `dev.sh`
//!
//! `dev.sh` probes its tools on the dry-run path as well, and those probes are not free: measured on
//! this machine, `HOME=<fresh> mo clean --dry-run` leaves 37 MB behind. [`Detection`] carries the
//! full accounting and the reasoning; the short version is that `clean` without `--apply` resolves
//! presence with a `PATH` lookup and every cache path from env vars and the oracle's own fallback
//! literals, and `clean --apply` keeps the oracle's probes verbatim.
//!
//! # Every delegated command carries the oracle's OWN ceiling, including "none"
//!
//! `dev.sh` wraps each of these calls in `run_with_timeout <bucket>` — or deliberately does not.
//! `go clean -modcache`, `pip3 cache purge`, `mise cache clear` and `nix-collect-garbage` have NO
//! wrapper, because on a real machine they run for minutes and killing one part-way leaves a
//! half-deleted cache. A single probe-sized budget applied to all of them is the same defect twice
//! over: it SIGKILLs long deletes, and for the tools that DO have a sweep it then escalates the
//! timeout into a whole-cache delete. See [`Delegation::budget`].

use super::execute::Removal;
use super::plan::{size_if_exists, CleanCandidate};
use super::protect::{should_protect_path, ProtectionMode};
use super::whitelist::is_path_whitelisted;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Bounded budget for the PROBES in this module — `--version` / `cache dir` / `store path` /
/// `env GOCACHE`-style questions, per RULEBOOK §3d ("audit every shell-out … then measure the WORST
/// case"). None of these perform name resolution or network IO the way `netstat`/`nettop` do, but a
/// wedged or download-prompting tool shim (see `pnpm`'s `COREPACK_ENABLE_DOWNLOAD_PROMPT` guard
/// below) is a real, if rarer, version of the same hazard class, so every probe is bounded.
///
/// It applies to PROBES ONLY. The oracle's own probe ceiling is `MOLE_TIMEOUT_QUICK_DETECT_SEC`
/// (2s, `lib/core/timeouts.sh:60`), so 5s is the more permissive of the two, which is the safe
/// direction: a slow probe that bash would have given up on can only make this engine MORE willing
/// to delegate (and delegating is what bash does), never more willing to delete files itself.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// `MOLE_TIMEOUT_PKG_CLEANUP_SEC` (`lib/core/timeouts.sh:64`) — "cache cleanup commands that walk
/// disks". `corepack cache clean` (`dev.sh:54`), `uv cache prune` (`:68`), `pnpm store prune`
/// (`:181`).
const PKG_CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);

/// `MOLE_TIMEOUT_PKG_LIST_SEC` (`lib/core/timeouts.sh:63`) — what `dev.sh:213` actually wraps
/// `bun pm cache rm` in. Deliberately NOT the cleanup bucket: transcribed from the call site, not
/// from what the bucket's name suggests it ought to be.
const PKG_LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// `MOLE_TIMEOUT_DISK_VERIFY_SEC` (`lib/core/timeouts.sh:65`) — `conda clean --yes --index-cache
/// --tarballs --logfiles` (`dev.sh:105`), the one delegated command the oracle gives a longer
/// ceiling than PKG_CLEANUP.
const DISK_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// How a bounded subprocess ended. Distinguished (rather than collapsed to `Option`) because a
/// destructive command that was KILLED at its budget left the cache half-removed, and saying so is
/// the difference between an actionable error and "it failed".
enum RunOutcome {
    /// Exited zero; trimmed stdout.
    Ok(String),
    /// Never started, or exited non-zero.
    Failed,
    /// Still running at the budget, so it was killed.
    TimedOut,
}

/// Run `program args…` (with `envs` applied on top of the inherited environment) under `budget`.
/// `budget: None` means UNBOUNDED — not an oversight but a transcription: `dev.sh` wraps some
/// delegated commands in `run_with_timeout` and deliberately does not wrap others (`go clean
/// -modcache`, `pip3 cache purge`, `mise cache clear`, `nix-collect-garbage`), because those
/// legitimately run for minutes on a real machine and killing one mid-flight leaves a half-deleted
/// cache. See [`Delegation::budget`].
///
/// Self-contained rather than reusing `status::collect::run_command_with_timeout` so this module can
/// pass extra env vars without widening that function's signature for one caller — but it borrows
/// the SAME drain-on-a-thread shape that function's doc comment explains is required: reading stdout
/// only after the child exits can deadlock a child that fills its pipe before exiting, turning a
/// healthy-but-verbose command into a permanent timeout.
fn run_bounded(
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
    budget: Option<Duration>,
) -> RunOutcome {
    // Resolved rather than spawned by name — see [`resolve_tool`]. Unprivileged this is the same
    // `PATH` walk `Command::new(program)` would do; under elevation it is the difference between
    // "the user's `uv`" and "whatever a writable `PATH` entry calls `uv`", run as root.
    let Some(exe) = resolve_tool(program) else {
        return RunOutcome::Failed;
    };
    let mut cmd = Command::new(exe);
    cmd.args(args).envs(envs.iter().map(|(k, v)| (*k, *v)));
    match crate::platform::run_configured_command(cmd, budget) {
        Ok(out) => RunOutcome::Ok(out.trim().to_string()),
        Err(crate::platform::CommandFailure::TimedOut(_)) => RunOutcome::TimedOut,
        Err(_) => RunOutcome::Failed,
    }
}

/// A PROBE: trimmed stdout on a zero exit within [`PROBE_TIMEOUT`], `None` otherwise.
fn run(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Option<String> {
    match run_bounded(program, args, envs, Some(PROBE_TIMEOUT)) {
        RunOutcome::Ok(s) => Some(s),
        RunOutcome::Failed | RunOutcome::TimedOut => None,
    }
}

/// True when `program` is on `PATH` and responds to `--version` — the engine's equivalent of bash's
/// `command -v X > /dev/null && X --version > /dev/null` liveness check.
///
/// Use this ONLY where the oracle also runs the `--version` half, and only under
/// [`Detection::MayInvoke`]. Three of `dev.sh`'s cleaners (`go`, `mise`, `nix-collect-garbage`) gate
/// on `command -v` ALONE — see [`tool_on_path`], and read its doc comment before "simplifying" the
/// two into one, because for `go` they are not equivalent.
///
/// The `command -v` half is kept as a real, separate step rather than folded into the spawn (an
/// earlier revision noted that a missing binary already fails `Command::spawn`, which is true but
/// makes the PATH lookup invisible). It has to be visible because [`tool_present`] runs that half on
/// BOTH paths and the `--version` half on only one of them.
fn tool_available(program: &str, envs: &[(&str, &str)]) -> bool {
    run(program, &["--version"], envs).is_some()
}

/// Whether this resolution pass is allowed to SPAWN the tools it is resolving.
///
/// # Why this exists — the oracle is not the guide here, and that is deliberate
///
/// `dev.sh` runs its tool probes on the dry-run path too. `clean_dev_npm` reaches
/// `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 pnpm --version` (`dev.sh:171`) and `bun pm cache` (`:192`),
/// `clean_dev_go` reaches `go env GOCACHE`/`GOMODCACHE` (`:284-285`), and `get_mise_cache_path`
/// reaches `mise cache path` (`:320`) — none of them guarded by `DRY_RUN`, which only ever fences
/// the *clean* command inside `clean_tool_cache` (`:24`). Measured, not inferred:
/// `HOME=<fresh> mo clean --dry-run` on this machine leaves **37 MB** behind —
/// `~/.cache/node/corepack` (a corepack-shimmed `pnpm --version` downloads and unpacks a full pnpm
/// tarball), `~/.bun/install/cache`, `~/.local/share/mise`, `~/Library/Application Support/go`,
/// plus `~/.npm/_logs` and `~/Library/pnpm` from `npm config get cache` and `pnpm store path`.
///
/// So a faithful port reproduces a preview that creates tens of megabytes under `$HOME` while
/// printing "no deletions". This module deviates on that one point, in the conservative direction:
/// the preview asks the operating system what is on `PATH` and computes each cache location from the
/// env vars and defaults the oracle itself falls back to, and spawns nothing at all.
/// [`Detection::MayInvoke`] — reached only from `clean --apply` — is byte-for-byte the oracle's
/// behaviour, probes included, because that is the path where the exact resolved location decides
/// what gets deleted, and where a tool creating its own cache directory is harmless (it is about to
/// be cleaned).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Detection {
    /// Preview (`clean` without `--apply`). Presence is a `PATH` lookup; every cache path is the
    /// value `dev.sh` itself uses when the tool's probe yields nothing — its own probe-less branch,
    /// not a location this port invented. Nothing is spawned, so a preview cannot create a file.
    PathOnly,
    /// Apply (`clean --apply`). The oracle's full predicate per tool: `command -v` plus the
    /// `--version` liveness check where `dev.sh` runs one, and the tool's own cache-path probe where
    /// `dev.sh` runs one.
    MayInvoke,
}

/// bash's `command -v X` — plus its `X --version` half only where the oracle writes one AND we are
/// allowed to spawn. The two halves are not interchangeable and the caller picks per tool: `go`,
/// `mise` and `nix-collect-garbage` gate on `command -v` alone in `dev.sh` and so call
/// [`tool_on_path`] directly, never this.
fn tool_present(program: &str, envs: &[(&str, &str)], detection: Detection) -> bool {
    if !tool_on_path(program) {
        return false;
    }
    match detection {
        // The `--version` half has a documented job in the oracle — `dev.sh:170` ("not just Corepack
        // shim") and `:256` ("not just macOS stub that triggers CLT install dialog") — so it is kept
        // wherever spawning is allowed rather than dropped for uniformity.
        Detection::MayInvoke => tool_available(program, envs),
        Detection::PathOnly => true,
    }
}

/// [`detect_path`] under [`Detection`]: `None` in `PathOnly` mode, so the caller's default — which
/// is the oracle's own `[[ -z "$x" ]]` fallback literal — stands unchanged.
fn detect_path_when_allowed(
    detection: Detection,
    program: &str,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Option<String> {
    match detection {
        Detection::MayInvoke => detect_path(program, args, envs),
        Detection::PathOnly => None,
    }
}

/// True when `program` resolves to an executable file on `PATH` — bash's `command -v X`, with NO
/// `--version` follow-up and no spawn at all.
///
/// This exists because collapsing `command -v go` into `go --version` is not a simplification, it is
/// a behaviour change that silently disables the whole Go cleaner: **`go --version` exits 2** ("flag
/// provided but not defined: -version" — Go spells it `go version`, as a subcommand). Verified on
/// this machine against go 1.x at `/opt/homebrew/bin/go`. `dev.sh:281` is
/// `command -v go > /dev/null 2>&1 || return 0` and nothing else, so the oracle cleans both Go
/// caches on every machine with Go installed while a `--version` probe finds Go "unavailable" on all
/// of them. `mise` (`dev.sh:318`, `:334`) and `nix-collect-garbage` (`:440`) are gated the same way;
/// their `--version` happens to work today, but matching the oracle's actual predicate removes the
/// dependency on that continuing to be true.
///
/// Every half of "resolves on PATH" is a platform fact — the separator, the spelling, and what
/// counts as executable — so the whole lookup is [`crate::platform::find_on_path`] rather than
/// re-spelled here. That module's doc comment carries the three facts and what each one costs when
/// it is assumed instead of asked; the short version is that the unix spelling written once returns
/// `false` for every tool on Windows (`go` is on disk as `go.exe`) and silently disables every
/// dev-cache cleaner rather than reporting that it could not find the tool.
///
/// This wrapper stays because the PREDICATE is the thing with the doc comment above, not the lookup:
/// three of `dev.sh`'s cleaners gate on `command -v` alone, and the name is what says so at the call
/// site. It discards the resolved path because bash's `command -v X > /dev/null` does too; the
/// spawn in `run_bounded` resolves again through the same [`resolve_tool`], so the two halves
/// cannot disagree about which binary they mean.
fn tool_on_path(program: &str) -> bool {
    resolve_tool(program).is_some()
}

/// Where `program` — a developer tool this module may SPAWN (`uv`, `go`, `pnpm`, `pip3`, …) —
/// may be run from, or `None` if nowhere. The one resolution every spawn in this module goes
/// through, in both of its halves: [`tool_on_path`] asks it whether the tool is present, and
/// [`run_bounded`] spawns the path it returns rather than the bare name.
///
/// Unprivileged this is `crate::platform::find_on_path`: the user's own `PATH`, the way bash's
/// `command -v` and the oracle's own spawns read it. Under elevation
/// (`crate::platform::is_privileged`) `PATH` is inherited from whoever launched the process and an
/// engine running as root that spawns whatever it names is an arbitrary-exec vector with a
/// friendly name — so the lookup goes through [`crate::platform::resolve_helper`]'s trusted
/// directories and never `PATH` (BUR-130). The dry-run's `PathOnly` probing is unaffected on the
/// path it actually runs on: an unelevated preview resolves exactly as before.
fn resolve_tool(program: &str) -> Option<std::path::PathBuf> {
    crate::platform::resolve_helper(program, None, &[])
}

/// Ask a tool where it thinks its cache lives; `None` unless the answer is a single absolute path —
/// mirrors every `dev.sh` detector's own guard (`[[ -n "$x" && "$x" == /* ]]`).
fn detect_path(program: &str, args: &[&str], envs: &[(&str, &str)]) -> Option<String> {
    run(program, args, envs).filter(|p| p.starts_with('/') && !p.contains('\n'))
}

/// The tool's own cache-clean command, with the wall-clock ceiling `dev.sh` puts on THAT call site.
#[derive(Clone, Copy)]
struct Delegation {
    program: &'static str,
    args: &'static [&'static str],
    /// `Some(d)` mirrors a `run_with_timeout <bucket>` wrapper in `dev.sh`; `None` mirrors a call
    /// site with no wrapper at all.
    ///
    /// This is per-command and not one shared constant because the oracle's ceilings differ by an
    /// order of magnitude and the extremes are the whole point: `go clean -modcache` over a
    /// multi-GB module cache and `nix-collect-garbage` over a real store both routinely run for
    /// MINUTES, and `dev.sh` gives them no ceiling for exactly that reason. Applying a probe-sized
    /// budget to them SIGKILLs a delete half-way through — and for the two tools that do have a raw
    /// sweep, a timeout would then escalate into sweeping the whole cache the tool was in the
    /// middle of pruning selectively.
    budget: Option<Duration>,
}

/// When the oracle removes the resolved path's children DIRECTLY, instead of (or in addition to)
/// letting the tool clean itself. Read off `dev.sh` per tool — the shape of the surrounding `if`
/// matters as much as the presence of a `safe_clean` call, and collapsing this to one bool is how a
/// port ends up deleting a whole cache the oracle would have left alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RawSweep {
    /// Never. `pnpm` (`dev.sh:182-184`), `go` (`:281`), `conda` (`:110-114`), `nix` (`:439-449`),
    /// `pip` (`:255-265`): when the tool is missing the oracle leaves the (often multi-GB) cache
    /// alone entirely, and when the tool's clean command fails it does nothing further either.
    Never,
    /// Only when the tool is UNAVAILABLE. `corepack` (`dev.sh:53-57`) and `uv` (`:62-71`) write
    /// their `safe_clean` as the `else` of `command -v …`, so it is reachable ONLY on the
    /// tool-missing branch. A present tool whose clean command fails or times out leaves bash doing
    /// **nothing at all** — sweeping there would turn a failed `uv cache prune` (a prune of UNUSED
    /// entries) into "delete the entire uv cache", strictly more destructive than the oracle.
    WhenToolAbsent,
    /// When the tool is unavailable OR its clean command failed. `bun` alone: `dev.sh:245` is the
    /// unavailable branch and `:241-243` is an explicit `if [[ "$bun_cache_cleaned" != "true" ]]`
    /// fallback after a failed `bun pm cache rm`.
    WhenToolAbsentOrFailed,
    /// Always, including after a SUCCESSFUL delegation. `mise` alone: `safe_clean
    /// "$mise_cache_path"/* "mise cache"` (`dev.sh:347`) sits OUTSIDE the `if command -v mise`
    /// block, so it runs on every path through `clean_dev_mise`.
    Always,
}

/// Whether the freed byte count for this target is knowable at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SizeMode {
    /// Size the resolved path (and use its existence as the plan-time gate), like every other
    /// candidate.
    Measure,
    /// Do not size it, and do not walk it. `/nix/store` is a whitelist-check HINT, not a deletion
    /// target: `nix-collect-garbage --delete-older-than 30d` frees whatever is unreferenced, which
    /// is a fraction of the store that cannot be known without running it — and the oracle's own
    /// dry-run branch (`dev.sh:443-446`) deliberately prints no size. Walking it to produce a
    /// number would be minutes of IO at PLAN time to compute a figure that is wrong by
    /// construction.
    NotMeasurable,
}

/// One resolved dev-tool cache: where to point the planner/executor, and how it may be removed.
struct ResolvedTarget {
    label: &'static str,
    path: String,
    /// The tool's own clean command, to try FIRST at apply time. `None` when the tool wasn't
    /// available at resolution time (plan and apply re-resolve independently, so a tool
    /// installed/removed between the two calls is re-detected each time, exactly like bash).
    delegate: Option<Delegation>,
    /// Whether `remover_for` may remove the path's children directly, and in which of the three
    /// situations. See the module doc comment — this is the guard, not a detail.
    sweep: RawSweep,
    size: SizeMode,
}

// ---------------------------------------------------------------------------------------------
// Per-tool resolution — one function per `dev.sh` cleaner, each read against its exact bash source.
// ---------------------------------------------------------------------------------------------

/// `clean_corepack_cache` (`dev.sh:44`). `COREPACK_HOME` is user-settable; without the guard below a
/// port deletes whatever the user pointed it at, including `/`.
fn corepack_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    let default = format!("{home}/.cache/node/corepack");
    let resolved = std::env::var("COREPACK_HOME").unwrap_or(default);
    if !resolved.starts_with('/') {
        return None; // dev.sh:46 — `[[ -n "$x" && "$x" == /* ]] || return 0`
    }
    if is_unsafe_corepack_home(&resolved, home) {
        return None; // dev.sh:47-52 — the exact `case` this port must not widen past
    }
    // The path never needed a probe (`COREPACK_HOME` or the literal default, `dev.sh:45`), so only
    // presence detection differs between the two modes here.
    let available = tool_present("corepack", &[], detection);
    Some(ResolvedTarget {
        label: "Corepack cache",
        path: resolved,
        delegate: available.then_some(Delegation {
            program: "corepack",
            args: &["cache", "clean"],
            budget: Some(PKG_CLEANUP_TIMEOUT), // dev.sh:54
        }),
        sweep: RawSweep::WhenToolAbsent, // dev.sh:56 — the `else` of `command -v corepack`
        size: SizeMode::Measure,
    })
}

/// `dev.sh:47-52`, verbatim: `case "$corepack_home" in / | "$HOME" | "$HOME/" | "$HOME/Library" |
/// "$HOME/Library/") … return 0 ;; esac`. Every user-controlled cache-dir resolution in this module
/// is checked against its OWN oracle guard, not a generic "looks like HOME" heuristic — this one
/// exists because corepack is the one the brief's example is drawn from, and it is exactly this
/// literal, no more and no less.
fn is_unsafe_corepack_home(path: &str, home: &str) -> bool {
    path == "/"
        || path == home
        || path == format!("{home}/")
        || path == format!("{home}/Library")
        || path == format!("{home}/Library/")
}

/// `clean_uv_cache` (`dev.sh:60`).
fn uv_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    let default = format!("{home}/.cache/uv");
    let available = tool_present("uv", &[], detection);
    let path = if available {
        // `uv cache dir` (dev.sh:64) — skipped in preview, where `dev.sh`'s own
        // `[[ -n "$detected_cache" && … ]]` fallback value (`$HOME/.cache/uv`, `:61`) stands.
        detect_path_when_allowed(detection, "uv", &["cache", "dir"], &[]).unwrap_or(default)
    } else {
        default
    };
    Some(ResolvedTarget {
        label: "uv cache",
        path,
        delegate: available.then_some(Delegation {
            program: "uv",
            args: &["cache", "prune"],
            budget: Some(PKG_CLEANUP_TIMEOUT), // dev.sh:68
        }),
        sweep: RawSweep::WhenToolAbsent, // dev.sh:70 — the `else` of `command -v uv`
        size: SizeMode::Measure,
    })
}

/// `clean_dev_npm`'s pnpm branch (`dev.sh:168-184`). No raw fallback at all: the `else` branch is a
/// `debug_log` only — an unusable pnpm leaves the (potentially large) store untouched. Also the one
/// tool whose OWN liveness check needs an env var (`COREPACK_ENABLE_DOWNLOAD_PROMPT=0`), because a
/// corepack-shimmed `pnpm` that isn't actually installed can otherwise prompt interactively.
///
/// This is also the single worst offender behind [`Detection`]: on a machine where `pnpm` IS the
/// corepack shim, `pnpm --version` does not merely answer — it downloads and unpacks a ~38 MB pnpm
/// tarball into `COREPACK_HOME`. `COREPACK_ENABLE_DOWNLOAD_PROMPT=0` suppresses the *prompt*, not
/// the download. In preview neither that probe nor `pnpm store path` runs at all.
fn pnpm_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    let envs: &[(&str, &str)] = &[("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")];
    if !tool_present("pnpm", envs, detection) {
        return None;
    }
    let default = format!("{home}/Library/pnpm/store");
    // `pnpm store path` (dev.sh:174); preview keeps `$pnpm_default_store` (`:169`), the value
    // `dev.sh` uses whenever that probe returns nothing.
    let path =
        detect_path_when_allowed(detection, "pnpm", &["store", "path"], envs).unwrap_or(default);
    Some(ResolvedTarget {
        label: "pnpm cache",
        path,
        delegate: Some(Delegation {
            program: "pnpm",
            args: &["store", "prune"],
            budget: Some(PKG_CLEANUP_TIMEOUT), // dev.sh:181
        }),
        sweep: RawSweep::Never,
        size: SizeMode::Measure,
    })
}

/// `clean_dev_npm`'s bun branch (`dev.sh:186-246`), the delegate-with-fallback half only. The
/// oracle's extra "orphaned default cache when the detected path differs from the default" sweep
/// (dev.sh:236-238) is NOT ported — a second, independently-sized candidate for a rare
/// custom-cache-location edge case, left for a follow-up rather than rushed. Noted in the port
/// report, not silently dropped.
fn bun_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    let available = tool_present("bun", &[], detection);
    let default = format!("{home}/.bun/install/cache");
    let path = if available {
        // `bun pm cache` (dev.sh:192) CREATES the directory it reports, so preview keeps
        // `$bun_default_cache` (`:186`) — again `dev.sh`'s own empty-answer fallback.
        detect_path_when_allowed(detection, "bun", &["pm", "cache"], &[]).unwrap_or(default)
    } else {
        default
    };
    Some(ResolvedTarget {
        label: "Bun cache",
        path,
        delegate: available.then_some(Delegation {
            program: "bun",
            args: &["pm", "cache", "rm"],
            budget: Some(PKG_LIST_TIMEOUT), // dev.sh:213 — PKG_LIST, not PKG_CLEANUP
        }),
        // dev.sh:245 (unavailable) and :241-243 (delegation failed) both sweep — the only tool
        // whose oracle sweeps after a FAILED clean command.
        sweep: RawSweep::WhenToolAbsentOrFailed,
        size: SizeMode::Measure,
    })
}

/// `clean_dev_go` (`dev.sh:280-310`) — TWO independent caches, each whitelist-gated on its OWN path
/// (bash checks `is_path_whitelisted` on each before deciding which delegation call(s) to make), and
/// neither has a raw fallback: the function returns at its very first line if `go` isn't on `PATH`,
/// before any cache is even resolved.
fn go_targets(home: &str, whitelist: &[&str], detection: Detection) -> Vec<ResolvedTarget> {
    // `command -v go` ONLY — `dev.sh:281`. NOT `tool_available`: `go --version` exits 2 on every
    // real Go install, so probing it disables this entire cleaner. See [`tool_on_path`]. This
    // predicate is identical in both [`Detection`] modes for that reason.
    if !tool_on_path("go") {
        return Vec::new();
    }
    // `go env GOCACHE` / `GOMODCACHE` (dev.sh:284-285). Merely ASKING creates
    // `~/Library/Application Support/go/telemetry`, so preview uses the `|| echo` defaults `dev.sh`
    // writes on the same two lines and asks nothing.
    let build = detect_path_when_allowed(detection, "go", &["env", "GOCACHE"], &[])
        .unwrap_or_else(|| format!("{home}/Library/Caches/go-build"));
    let modc = detect_path_when_allowed(detection, "go", &["env", "GOMODCACHE"], &[])
        .unwrap_or_else(|| format!("{home}/go/pkg/mod"));
    let mut out = Vec::new();
    if !is_path_whitelisted(&build, whitelist) {
        out.push(ResolvedTarget {
            label: "Go build cache",
            path: build,
            delegate: Some(Delegation {
                program: "go",
                args: &["clean", "-cache"],
                // dev.sh:301/:306 — bare `clean_tool_cache … bash -c 'go clean -cache'`, no
                // `run_with_timeout` wrapper anywhere. Unbounded on purpose.
                budget: None,
            }),
            sweep: RawSweep::Never,
            size: SizeMode::Measure,
        });
    }
    if !is_path_whitelisted(&modc, whitelist) {
        out.push(ResolvedTarget {
            label: "Go module cache",
            path: modc,
            delegate: Some(Delegation {
                program: "go",
                args: &["clean", "-modcache"],
                budget: None, // dev.sh:301/:303 — unbounded, and it walks a multi-GB tree
            }),
            sweep: RawSweep::Never,
            size: SizeMode::Measure,
        });
    }
    out
}

/// `get_mise_cache_path` + `clean_dev_mise` (`dev.sh:312-348`). The ONE tool whose raw sweep runs
/// UNCONDITIONALLY — `safe_clean "$mise_cache_path"/* "mise cache"` sits OUTSIDE the
/// `if command -v mise` block in the oracle, so it always applies regardless of whether delegation
/// also ran (harmless when delegation already emptied the directory).
fn mise_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    let env_override = std::env::var("MISE_CACHE_DIR")
        .ok()
        .filter(|p| p.starts_with('/'));
    // `command -v mise` alone — `dev.sh:318`, `:334`. No `--version` half to mirror, in either mode.
    let available = tool_on_path("mise");
    let path = env_override.unwrap_or_else(|| {
        // `mise cache path` (dev.sh:320) creates `~/.local/share/mise` as a side effect of being
        // asked, so preview falls straight through to `dev.sh:327`'s literal default. The
        // `MISE_CACHE_DIR` branch above is checked FIRST in both modes because `dev.sh:313-316`
        // checks it before it ever consults the tool.
        if available {
            detect_path_when_allowed(detection, "mise", &["cache", "path"], &[])
                .unwrap_or_else(|| format!("{home}/Library/Caches/mise"))
        } else {
            format!("{home}/Library/Caches/mise")
        }
    });
    Some(ResolvedTarget {
        label: "mise cache",
        path,
        delegate: available.then_some(Delegation {
            program: "mise",
            args: &["cache", "clear"],
            budget: None, // dev.sh:336 — bare `bash -c 'mise cache clear'`, no timeout wrapper
        }),
        sweep: RawSweep::Always, // dev.sh:347 — outside the `if`, so it runs on every path
        size: SizeMode::Measure,
    })
}

/// `conda_cache_whitelisted` + `clean_conda_metadata_caches` (`dev.sh:74-115`) — FIVE install-location
/// variants, protected as a GROUP: if ANY of the five (or its `.mole-cache-guard` sentinel) is
/// whitelisted, the oracle skips ALL of them, not just the matched one. No raw fallback: when conda
/// isn't on `PATH`, the oracle explicitly leaves the (often multi-GB) package cache "for manual
/// review" — verified by reading `clean_conda_metadata_caches`'s tail, which only `debug_log`s.
fn conda_target(home: &str, whitelist: &[&str], detection: Detection) -> Option<ResolvedTarget> {
    let roots = [
        format!("{home}/.conda/pkgs"),
        format!("{home}/anaconda3/pkgs"),
        format!("{home}/miniconda3/pkgs"),
        format!("{home}/miniforge3/pkgs"),
        format!("{home}/mambaforge/pkgs"),
    ];
    let protected = roots.iter().any(|r| {
        is_path_whitelisted(r, whitelist)
            || is_path_whitelisted(&format!("{r}/.mole-cache-guard"), whitelist)
    });
    if protected {
        return None;
    }
    if !tool_present("conda", &[], detection) {
        return None; // no raw fallback — see doc comment
    }
    // `clean_tool_cache`'s whitelist re-check inside dev.sh is keyed on the FIRST root
    // (`$HOME/.conda/pkgs`) as a representative hint; sizing/existence use the same root, and the
    // remaining four are covered structurally by the group-protection check above, not sized
    // individually (conda's own `--index-cache --tarballs --logfiles` clean spans all of them).
    Some(ResolvedTarget {
        label: "conda index/tarball/log caches",
        path: roots[0].clone(),
        delegate: Some(Delegation {
            program: "conda",
            args: &[
                "clean",
                "--yes",
                "--index-cache",
                "--tarballs",
                "--logfiles",
            ],
            budget: Some(DISK_VERIFY_TIMEOUT), // dev.sh:105 — 30s, not the 20s cleanup bucket
        }),
        sweep: RawSweep::Never,
        size: SizeMode::Measure,
    })
}

/// `clean_dev_nix` (`dev.sh:439-450`) — pure tool delegation, no path to size at all: garbage
/// collection frees whatever `nix-collect-garbage` decides is unreferenced, which is not knowable
/// (and not measured by the oracle either — its own dry-run branch shows no byte count) without
/// actually running it. `/nix/store` is used ONLY as the whitelist-check hint, matching the oracle.
///
/// [`SizeMode::NotMeasurable`] is what makes the sentence above TRUE rather than merely written: an
/// earlier revision said "reported with `size: 0` rather than sizing the whole store" while
/// [`finish`] called `size_if_exists` on it, i.e. `dir_size("/nix/store")` — a full recursive walk
/// of the entire store at PLAN time, whose total then landed in `freed_bytes` the moment
/// `nix-collect-garbage` exited zero. Doc comments do not constrain code; the enum does.
fn nix_target(whitelist: &[&str]) -> Option<ResolvedTarget> {
    if is_path_whitelisted("/nix/store", whitelist) {
        return None;
    }
    // `command -v nix-collect-garbage` alone — `dev.sh:440`.
    if !tool_on_path("nix-collect-garbage") {
        return None; // no raw fallback — nothing to remove without the tool
    }
    Some(ResolvedTarget {
        label: "Nix garbage collection",
        path: "/nix/store".to_string(),
        delegate: Some(Delegation {
            program: "nix-collect-garbage",
            args: &["--delete-older-than", "30d"],
            // dev.sh:442 — no `run_with_timeout`. A real store GC runs for minutes; SIGKILLing it
            // mid-collection is how you get a half-collected store.
            budget: None,
        }),
        sweep: RawSweep::Never,
        size: SizeMode::NotMeasurable,
    })
}

/// `clean_dev_python`'s pip branch (`dev.sh:255-265`) — no raw fallback: `clean_dev_python`'s other
/// (unconditional) `safe_clean` calls are separate tools' caches, never pip's; if `pip3` isn't
/// functional, pip's own cache is left untouched entirely.
fn pip_target(home: &str, detection: Detection) -> Option<ResolvedTarget> {
    if !tool_present("pip3", &[], detection) {
        return None;
    }
    let default = format!("{home}/Library/Caches/pip");
    // `pip3 cache dir` (dev.sh:259); preview keeps `dev.sh:261`'s fallback literal.
    let path =
        detect_path_when_allowed(detection, "pip3", &["cache", "dir"], &[]).unwrap_or(default);
    Some(ResolvedTarget {
        label: "pip cache",
        path,
        delegate: Some(Delegation {
            program: "pip3",
            args: &["cache", "purge"],
            budget: None, // dev.sh:263 — bare `bash -c 'pip3 cache purge'`, no timeout wrapper
        }),
        sweep: RawSweep::Never,
        size: SizeMode::Measure,
    })
}

/// A resolved, whitelist-surviving, EXISTING dev-tool cache — bundles the ordinary [`CleanCandidate`]
/// shape (so it flows through the same JSON rendering as every other target) with how it should
/// actually be removed.
pub struct DelegatedCandidate {
    pub candidate: CleanCandidate,
    delegate: Option<Delegation>,
    sweep: RawSweep,
}

fn finish(t: ResolvedTarget, whitelist: &[&str]) -> Option<DelegatedCandidate> {
    // The same two rails [`super::plan::cleanable_paths`] applies, in the same order — a
    // tool-delegated candidate is still a path the oracle's `safe_clean` would run through
    // `should_protect_path` before touching. These paths are env-var-resolved (`GOMODCACHE`,
    // `UV_CACHE_DIR`, `MISE_CACHE_DIR`, …), so they are the ones MOST likely to point somewhere
    // unexpected, which makes skipping the check here worse than skipping it on a static target.
    // `dev.sh` is only ever reached from `bin/clean.sh`, which never exports `MOLE_UNINSTALL_MODE`,
    // so the regime here is always `Cleanup`.
    if should_protect_path(&t.path, ProtectionMode::Cleanup)
        || is_path_whitelisted(&t.path, whitelist)
    {
        return None;
    }
    let size = match t.size {
        SizeMode::Measure => size_if_exists(&t.path)?,
        // Existence still gates the candidate (a machine with no `/nix/store` has nothing to
        // report), but the path is never walked and never carries a byte figure.
        SizeMode::NotMeasurable => {
            if !Path::new(&t.path).exists() {
                return None;
            }
            0
        }
    };
    Some(DelegatedCandidate {
        candidate: CleanCandidate {
            path: t.path,
            label: t.label.to_string(),
            size,
        },
        delegate: t.delegate,
        sweep: t.sweep,
    })
}

/// Resolve every applicable dev-tool cache for THIS machine: env-var overrides applied and guarded,
/// install-location variants checked, tool availability probed, and the user's whitelist applied —
/// exactly like [`super::plan::plan_clean`], just for a shape the static target table can't express.
/// A tool that's unavailable AND has no raw fallback contributes nothing at all (never appears in
/// the plan), matching the oracle doing nothing for that cache in the same situation.
///
/// `detection` is the fence that keeps a PREVIEW from writing to the disk it is previewing — see
/// [`Detection`], which explains why the oracle is deliberately not followed on this one point and
/// what it costs (a preview names each tool's default cache location rather than a custom one the
/// tool would have reported).
pub fn resolve_candidates(
    home: &str,
    whitelist: &[&str],
    detection: Detection,
) -> Vec<DelegatedCandidate> {
    let mut out = Vec::new();
    let singles = [
        corepack_target(home, detection),
        uv_target(home, detection),
        pnpm_target(home, detection),
        bun_target(home, detection),
        mise_target(home, detection),
        conda_target(home, whitelist, detection),
        nix_target(whitelist),
        pip_target(home, detection),
    ];
    for t in singles.into_iter().flatten() {
        if let Some(dc) = finish(t, whitelist) {
            out.push(dc);
        }
    }
    for t in go_targets(home, whitelist, detection) {
        if let Some(dc) = finish(t, whitelist) {
            out.push(dc);
        }
    }
    out
}

/// Attempt one candidate's delegation command under ITS OWN budget (see [`Delegation::budget`]).
/// `Ok(())` = the tool's clean command exited zero; `Err(msg)` = it failed or was killed at its
/// ceiling, with the two distinguished in `msg` because a SIGKILLed cache delete and a refused one
/// need different responses from whoever reads the error.
fn try_delegate(d: Delegation) -> Result<(), String> {
    match run_bounded(d.program, d.args, &[], d.budget) {
        RunOutcome::Ok(_) => Ok(()),
        RunOutcome::Failed => Err(format!(
            "`{} {}` failed or is unavailable",
            d.program,
            d.args.join(" ")
        )),
        RunOutcome::TimedOut => Err(format!(
            "`{} {}` was killed after {}s and may have left the cache half-removed",
            d.program,
            d.args.join(" "),
            d.budget.map(|b| b.as_secs()).unwrap_or(0)
        )),
    }
}

/// The raw fallback, as bash actually writes it: EVERY raw-fallback call in `dev.sh` is
/// `safe_clean "$dir"/*` — `dev.sh:56` (corepack), `:70` (uv), `:242`/`:245` (bun), `:347` (mise) —
/// never `safe_clean "$dir"`. The shell expands that glob before `safe_clean` ever sees it, so bash
/// evaluates its rails PER CHILD and removes the children one at a time, leaving the directory
/// itself in place. Removing the tree instead destroys any child the oracle would have spared: a
/// protected one, a whitelisted one, or a hidden one (`dotglob` is unset, so `dir/*` never matches
/// a dotfile — `~/.cache/uv/.gitignore` is not swept by bash and must not be swept here).
///
/// So the fallback expands `dir/*` through the same [`expand_pattern`] the static planner uses, runs
/// all three rails on each child exactly as `safe_clean` + `safe_remove` do, and removes the
/// survivors individually. A child that every rail refuses is skipped silently, matching bash's
/// `log_operation … SKIPPED`; failures are collected and reported as one error for the parent
/// candidate, because the executor's unit of reporting is the candidate it was handed.
///
/// It reports [`Removal::Swept`] with the bytes it MEASURED going away — sized per child just
/// before removing it and counted only once the child is confirmed gone. Not the parent's planned
/// total: this sweep deliberately spares protected, whitelisted and hidden children, so the
/// directory's plan-time size is an over-count of what it frees by exactly the amount it spared
/// (RULEBOOK §3m — a byte count means bytes that are gone).
fn sweep_children(
    dir: &Path,
    permanent: bool,
    whitelist: &[&str],
    default_remover: &impl Fn(&Path, bool) -> Result<Removal, String>,
) -> Result<Removal, String> {
    // Enumerated directly rather than through [`super::plan::expand_pattern`], because bash writes
    // `safe_clean "$dir"/*` with `$dir` QUOTED: only the trailing `*` is a glob, and any `*`, `?` or
    // `[` inside the resolved cache path stays a literal. Feeding the whole thing to a pattern
    // expander would glob the directory name too — and these paths come from `MISE_CACHE_DIR`,
    // `uv cache dir` and friends, so an unusual character in one is a user-supplied input, not a
    // hypothetical. Hidden entries are excluded because `dotglob` is unset everywhere in
    // `lib/clean/*.sh`; sorted so the sweep order is deterministic.
    let Ok(entries) = std::fs::read_dir(dir) else {
        // Nothing to sweep — matches a glob that expands to no matches. Zero bytes, stated as a
        // measurement rather than inherited from the parent candidate's planned size.
        return Ok(Removal::Swept { bytes: 0 });
    };
    let mut children: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .map(|name| format!("{}/{name}", dir.to_string_lossy()))
        .collect();
    children.sort();
    let mut failures = Vec::new();
    let mut bytes: u64 = 0;
    for child in children {
        use super::execute::{remove_guarded, Freed, Guarded};
        match remove_guarded(
            &child,
            0,
            whitelist,
            permanent,
            ProtectionMode::Cleanup,
            default_remover,
        ) {
            Guarded::Removed(Freed::Bytes(n)) => bytes = bytes.saturating_add(n),
            Guarded::Failed(e) => failures.push(format!("{child}: {e}")),
            _ => {}
        }
    }
    if failures.is_empty() {
        Ok(Removal::Swept { bytes })
    } else {
        Err(failures.join("; "))
    }
}

/// Build a remover for [`super::execute::execute_clean_with_remover`] that, for any candidate path
/// resolved by [`resolve_candidates`], tries that candidate's delegation command FIRST — preserving
/// the oracle's preference for "the tool knows what's safe to drop from its own cache" — and only
/// falls through to a raw removal where `raw_fallback` allows it. That fallback is
/// [`sweep_children`], NOT `default_remover` on the directory itself; see its doc comment for why
/// the difference is the whole point. Every other path (the static
/// [`super::plan::UNIVERSAL_TARGETS`] candidates) is untouched: they never match any entry in
/// `resolved` and go straight to `default_remover`, unchanged.
///
/// `whitelist` is the same list [`resolve_candidates`] was given — the per-child rails need it, and
/// taking it here rather than storing it on the candidate keeps `DelegatedCandidate` a plain value.
///
/// The three situations [`RawSweep`] distinguishes are kept distinct HERE, which is the point: an
/// earlier revision used one `raw_fallback: bool` for both "the tool is missing" and "the tool ran
/// and failed", so a 5-second timeout on `uv cache prune` — a prune of UNUSED entries — turned into
/// deleting the whole uv cache, which the oracle never does on that branch.
pub fn remover_for<'a>(
    resolved: &'a [DelegatedCandidate],
    whitelist: &'a [&'a str],
    default_remover: impl Fn(&Path, bool) -> Result<Removal, String> + 'a,
) -> impl Fn(&Path, bool) -> Result<Removal, String> + 'a {
    move |p: &Path, permanent: bool| {
        let path_str = p.to_string_lossy();
        let Some(dc) = resolved.iter().find(|dc| dc.candidate.path == path_str) else {
            return default_remover(p, permanent);
        };
        let sweep = || sweep_children(p, permanent, whitelist, &default_remover);
        match dc.delegate {
            Some(d) => match try_delegate(d) {
                // The tool cleaned its own cache. This engine touched nothing, so it can claim
                // neither a byte count nor a Trash it can point at — `Removal::Delegated` is what
                // stops the caller inventing both (RULEBOOK §3m).
                Ok(()) if dc.sweep == RawSweep::Always => sweep(),
                Ok(()) => Ok(Removal::Delegated),
                // mise (`Always`) and bun (`WhenToolAbsentOrFailed`). Bash's
                // `if [[ "$bun_cache_cleaned" != "true" ]]` fallback (`dev.sh:241-243`) does not
                // care WHY the clean command failed, so neither does this; the error text is
                // dropped because the sweep now speaks for itself, succeeding on its own terms or
                // reporting its own per-child failures.
                Err(_)
                    if matches!(
                        dc.sweep,
                        RawSweep::Always | RawSweep::WhenToolAbsentOrFailed
                    ) =>
                {
                    sweep()
                }
                // corepack/uv (`WhenToolAbsent`) and pnpm/go/conda/nix/pip (`Never`): a present
                // tool whose clean command fails leaves bash doing nothing at all, so this reports
                // the failure rather than escalating it into a delete the oracle never performs.
                Err(e) => Err(e),
            },
            None => match dc.sweep {
                RawSweep::Never => {
                    Err("tool unavailable; the original has no raw fallback for this cache".into())
                }
                _ => sweep(),
            },
        }
    }
}

/// Serializes every test that mutates a process-wide env var this module resolves through (`PATH`,
/// `COREPACK_HOME`, `MISE_CACHE_DIR`, and now `BURROW_PRIVILEGED`) with every test that READS one.
/// `cargo test` runs tests on multiple threads by default, and env vars are process-global state —
/// two tests that set/read/unset the SAME var concurrently can each observe the other's value
/// mid-flight. This is not hypothetical: without this lock covering `MISE_CACHE_DIR` too,
/// `mise_falls_back_to_default_cache_dir_without_the_tool` (which requires the var UNSET)
/// intermittently failed by reading the override `mise_env_override_wins_over_detection_and_default`
/// had concurrently set. `PATH` additionally affects subprocess spawns crate-wide, so a residual,
/// narrow window against OTHER modules' subprocess tests remains — bounded to the stock `PATH`
/// entries those tests need, which `isolated_path` deliberately keeps.
///
/// At module level rather than inside `tests` because `platform_tests` below resolves a real
/// binary on the real `PATH`, and a privileged-mode test running beside it would have
/// [`resolve_tool`] looking in the trusted directories instead (where `/bin/sh` is not).
///
/// The lock is the FLOOR, not the fix: it serializes env MUTATIONS and nothing else, so it never
/// covered the fixture directories those mutations point at (see `tests::scratch`) and it cannot
/// survive a panic on its own (see `tests::EnvFence`). Both of those were live bugs while this lock
/// was in place and correct.
#[cfg(test)]
static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The one predicate in this module that has to answer on every target — including the one where
/// the code below cannot run.
///
/// The big `tests` module underneath is `#[cfg(unix)]` because every fixture in it is a `#!/bin/sh`
/// script on a `:`-joined `PATH`, so it compiles nowhere else and would prove nothing if it did.
/// That leaves [`tool_on_path`] — the gate on whether this module cleans anything at all — with no
/// coverage on the platform it was written for, which is the shape of bug this change is about. The
/// resolution MECHANICS now live in `crate::platform` and are tested there, per platform and without
/// touching the process environment; what is left here is that this module still asks the question
/// and still reads the answer the right way round.
#[cfg(test)]
mod platform_tests {
    use super::*;

    #[test]
    fn a_real_interpreter_on_the_real_path_is_found_and_a_nonexistent_name_is_not() {
        let _env = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Driven off the machine's own PATH and a binary the platform actually ships, rather than a
        // fabricated directory: on Windows that means finding `cmd` only because `cmd.exe` exists
        // and PATHEXT names `.EXE`, which is the exact resolution step that did not exist before.
        let real = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(
            tool_on_path(real),
            "{real} must resolve on this platform's PATH"
        );
        assert!(
            !tool_on_path("burrow_engine_definitely_not_a_real_program"),
            "a name that is on no PATH entry must not resolve"
        );
    }
}

/// unix-only, and not incidentally: every fixture below writes a `#!/bin/sh` script and marks it
/// executable with a mode bit, then puts it on a `:`-joined `PATH`. None of that exists on Windows,
/// so these tests cannot compile there and would be vacuous if they did — the delegation surface
/// they cover (`go clean -modcache`, `mise cache clear`, `nix-collect-garbage`) is macOS behaviour
/// ported from `dev.sh`. The platform-varying half is covered by `platform_tests` above instead.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    /// Every `tag` [`scratch`] has already been handed out in this process, so a second test asking
    /// for one fails loudly instead of quietly sharing a directory. See [`scratch`] for why that is
    /// enforced rather than documented, and [`Scratch`] for why a tag is handed back on an unwind.
    static SCRATCH_TAGS: std::sync::Mutex<std::collections::BTreeSet<String>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());

    /// A scratch directory together with the CLAIM on its tag. Dereferences to the directory, so a
    /// holder reads exactly like the `PathBuf` this used to be.
    ///
    /// The claim is handed back **when the holder unwinds, and only then** — which is the whole
    /// reason this is a type rather than a bare `insert`. [`stock_path_mirror`] takes a tag inside a
    /// `OnceLock` initializer, and a `OnceLock` whose initializer panics is left UNINITIALIZED, so
    /// the next caller runs that initializer again. With the tag still held from the first attempt,
    /// the second run tripped the duplicate-tag assertion instead of re-raising the real error: on
    /// Linux CI a single genuine panic turned into every other test in this module failing with a
    /// misleading "tag was already handed to another test", which buried the one failure that
    /// mattered. That is the same fanout [`EnvFence`] exists to prevent, arriving through the other
    /// piece of shared state this module keeps.
    ///
    /// Handing the tag back on a NORMAL drop would be the simpler rule and is the wrong one. Two
    /// tests sharing a tag is a real bug (see [`scratch`]), but two tests that never overlap are
    /// harmless — so a release-always registry only catches the bug when the runner's thread pool
    /// happens to interleave them, making the detector exactly as intermittent as the flake it was
    /// written to kill. Retiring a tag permanently keeps that detection deterministic; releasing on
    /// unwind keeps one real failure from becoming twenty.
    struct Scratch {
        tag: String,
        dir: std::path::PathBuf,
    }

    impl std::ops::Deref for Scratch {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.dir
        }
    }

    /// So a `Scratch` still reaches the `AsRef<Path>` generics (`fs::remove_dir_all`, `Path::join`)
    /// that deref coercion alone does not satisfy.
    impl AsRef<std::path::Path> for Scratch {
        fn as_ref(&self) -> &std::path::Path {
            &self.dir
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            if std::thread::panicking() {
                SCRATCH_TAGS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&self.tag);
            }
        }
    }

    /// A scratch directory unique to this TEST, not merely to this process. `std::process::id()`
    /// alone is shared by every test in the binary, so two tests handed the same `tag` get the same
    /// directory — and each one's first act is to `remove_dir_all` it.
    ///
    /// That was this module's flake, and it was invisible because the tag was buried in a helper:
    /// `side_effecting_tools` hardcoded ONE tag while three tests called it, so each wiped and
    /// repopulated the fake-tool `PATH` the other two were part-way through using. It failed roughly
    /// one run in eight, in two different disguises — an `unwrap` on `None` (the fakes vanished
    /// mid-resolution, so `pnpm`/`go`/`pip3` read as absent and their targets disappeared) and a
    /// dirtied HOME (one test spawned another's fakes, whose side-effect locations are baked in as
    /// literals pointing at the OTHER test's home, so the preview test watched files appear under a
    /// home it never invoked anything against). [`ENV_TEST_LOCK`] could not help with either:
    /// it serializes the USE of the fake `PATH`, and the wipe happens before the lock is taken.
    ///
    /// Uniqueness is enforced rather than left to a comment for the same reason it was missed the
    /// first time — getting it wrong shows up as a rare failure in a DIFFERENT test, which is the
    /// hardest kind to trace back to here.
    fn scratch(tag: &str) -> Scratch {
        assert!(
            SCRATCH_TAGS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(tag.to_string()),
            "scratch tag `{tag}` was already handed to another test: two tests sharing one \
             directory delete each other's fixtures mid-run. Give this one its own tag."
        );
        // Built BEFORE the filesystem work, so a claim is never held by nothing: if `create_dir_all`
        // fails, the guard below is already alive to hand the tag back on the way out.
        let s = Scratch {
            tag: tag.to_string(),
            dir: std::env::temp_dir()
                .join(format!("burrow_tool_delegate_{}_{tag}", std::process::id())),
        };
        let _ = fs::remove_dir_all(&s.dir);
        fs::create_dir_all(&s.dir).unwrap();
        s
    }

    /// Write `#!/bin/sh` + `script` to `at` and make it executable — the shape [`tool_on_path`]
    /// looks for (a regular file with an execute bit).
    fn write_fake(at: &std::path::Path, script: &str) {
        fs::write(at, format!("#!/bin/sh\n{script}\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(at).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(at, perms).unwrap();
    }

    /// A scratch `PATH` directory containing exactly one fake executable named `name`, whose body is
    /// `script` — lets a test simulate "tool is on PATH and responds" without depending on any real
    /// dev tool being installed on whatever machine runs `cargo test`. `tag` names the CALLING TEST,
    /// not the tool: see [`scratch`].
    fn fake_tool_path(tag: &str, name: &str, script: &str) -> Scratch {
        let dir = scratch(tag);
        write_fake(&dir.join(name), script);
        dir
    }

    /// Holds [`ENV_TEST_LOCK`] and restores every variable it touched when it DROPS, including on an
    /// unwind. The helpers here used to write `set_var(new); f(); set_var(old)`, which skips the
    /// restore when `f` panics: one genuinely failing test then left the process `PATH` pinned to its
    /// own fake directory for every test that ran after it, so a single real failure fanned out into
    /// a cascade of unrelated ones and buried which test was actually broken.
    struct EnvFence {
        _guard: std::sync::MutexGuard<'static, ()>,
        /// `(key, value before this fence touched it)`, replayed in reverse so repeated writes to
        /// one key unwind to the value the process started with.
        restore: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvFence {
        fn set(&mut self, key: &'static str, value: &str) {
            self.restore.push((key, std::env::var_os(key)));
            std::env::set_var(key, value);
        }

        fn unset(&mut self, key: &'static str) {
            self.restore.push((key, std::env::var_os(key)));
            std::env::remove_var(key);
        }
    }

    impl Drop for EnvFence {
        fn drop(&mut self) {
            for (key, old) in self.restore.drain(..).rev() {
                match old {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Every process-wide variable this module's resolution READS, besides `PATH`. A test that
    /// asserts one of the oracle's default cache locations has to assert it against a known-empty
    /// environment, not against whatever the developer running `cargo test` exports: with
    /// `MISE_CACHE_DIR` set in a real shell,
    /// `preview_resolution_uses_the_oracles_own_probe_less_defaults_for_every_path` grades against
    /// that value instead. Before [`EnvFence`] it happened to pass only because another test's
    /// `remove_var` had cleared the variable process-wide first — the same accident that had
    /// `whitelist.rs`'s defaults test reading the developer's real `~/.config/mole/whitelist`.
    const RESOLUTION_ENV: [&str; 2] = ["COREPACK_HOME", "MISE_CACHE_DIR"];

    /// Every tool this module probes. Absence has to be expressible for ALL of them, and for `go`,
    /// `mise` and `nix-collect-garbage` the only thing that expresses it is not resolving on `PATH`
    /// at all: those three gate on `command -v` alone (see [`tool_on_path`]), so there is no
    /// `--version` half for a stub to fail. That is why [`stock_path_mirror`] OMITS these names
    /// rather than shadowing them.
    const PROBED_TOOLS: [&str; 9] = [
        "corepack",
        "uv",
        "pnpm",
        "bun",
        "conda",
        "pip3",
        "go",
        "mise",
        "nix-collect-garbage",
    ];

    /// The system `PATH` directories [`stock_path_mirror`] reproduces entry by entry. This module's
    /// `PATH` mutation is process-wide, so whatever the fake `PATH` cannot resolve, nothing running
    /// concurrently can spawn either — and two things in this crate depend on that: the fakes in
    /// [`side_effecting_tools`] run `mkdir` (`/bin/sh` has no builtin for it), and
    /// [`platform_tests`] asks the live `PATH` for `sh` while these tests may be holding it.
    ///
    /// The comment this replaces justified the same two directories by OTHER modules' tests spawning
    /// `sysctl`/`vm_stat`/`pmset`/`top`/`mount`/`date` by bare name. That was never true of half the
    /// list — macOS keeps `sysctl` in `/usr/sbin` and `mount` in `/sbin`, so neither has been
    /// reachable inside this fence for as long as the fence has existed, and nothing noticed.
    /// Running the whole test binary with `PATH` emptied says the same thing from the other side:
    /// 609 of 610 tests still pass, and the one that fails is `platform_tests` asking about `sh`.
    const STOCK_PATH_DIRS: [&str; 2] = ["/usr/bin", "/bin"];

    fn is_executable(p: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }

    /// [`STOCK_PATH_DIRS`] rebuilt as one directory of symlinks, with every name in
    /// [`PROBED_TOOLS`] left out. This is the fake `PATH`'s only system entry: the stock directories
    /// themselves never go on it, so a tool this module probes resolves ONLY where a test planted
    /// it, on any machine and any platform.
    ///
    /// # Why a mirror, and not the `exit 1` stubs this replaces
    ///
    /// Keeping `/usr/bin:/bin` on the fake `PATH` was never free: **macOS ships `/usr/bin/pip3`**,
    /// the Command Line Tools stub, and `resolve_candidates` probes `pip3`, so the two
    /// `resolve_candidates_*` tests — which install no pip3 fake — ran the developer's real
    /// `pip3 --version` and `pip3 cache dir` on every `cargo test`. That is the exact spawn
    /// `dev.sh:256` writes its `--version` guard against ("not just macOS stub that triggers CLT
    /// install dialog"), and where `pip3` is a real pip it creates `~/Library/Caches/pip` under the
    /// developer's OWN `$HOME` — those tests pass a scratch home as a STRING, but the child reads
    /// the process's `HOME`.
    ///
    /// The previous answer put an `exit 1` stub ahead of each such tool, which works only for the
    /// six whose absence is decided by `command -v` PLUS `--version`. For `go`, `mise` and
    /// `nix-collect-garbage` a stub says the opposite of what it means — [`tool_on_path`] returns
    /// true for any executable file — so that case could only be asserted against, never fixed. On
    /// macOS the assertion never fired; on `ubuntu-latest`, where `/usr/bin/go` exists, it fired and
    /// took every test in the module down with it. A shadow directory cannot express "absent" for
    /// those three; only a `PATH` that never reaches the real one can, which is what this is.
    ///
    /// Mirroring per ENTRY rather than dropping the stock directories wholesale is what keeps the
    /// rest of the crate working: see [`STOCK_PATH_DIRS`] for the two things that still need `sh`
    /// and `mkdir` while this fence holds the process `PATH`. A name is linked only if no earlier
    /// stock directory supplied it, which is the same first-match rule `PATH` itself uses.
    /// The mirroring itself, over the stock directories it is given rather than the constant — so
    /// [`a_stock_directory_that_ships_go_is_mirrored_without_it`] can hand it a FIXTURE that ships
    /// `go`. That is the `ubuntu-latest` condition, and it exists on no macOS, so without this seam
    /// the one platform difference that took this module down is reachable only by pushing to CI.
    fn mirror_stock_dirs(dir: &std::path::Path, stock: &[&str]) {
        for s in stock {
            let Ok(entries) = fs::read_dir(s) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name();
                if PROBED_TOOLS
                    .iter()
                    .any(|t| name.as_os_str() == std::ffi::OsStr::new(t))
                {
                    continue;
                }
                // Errors are ignored, and `EEXIST` is the expected one: a later stock directory
                // must not overwrite a name an earlier one already supplied.
                let _ = std::os::unix::fs::symlink(entry.path(), dir.join(&name));
            }
        }
    }

    fn stock_path_mirror() -> &'static std::path::Path {
        static DIR: std::sync::OnceLock<Scratch> = std::sync::OnceLock::new();
        &DIR.get_or_init(|| {
            let dir = scratch("stock_path_mirror");
            mirror_stock_dirs(&dir, &STOCK_PATH_DIRS);
            // The guard, kept and widened. It used to say "a stub cannot express absence for these
            // three" and abort; now the mechanism CAN express it, so what is asserted is that it
            // did — for all nine, not just the three, and against the mirror rather than against
            // the platform. A probed tool reachable from here would put the host's own `go` (or
            // `pip3`, or `conda`) behind every "the tool is absent" test in this module, silently.
            for name in PROBED_TOOLS {
                assert!(
                    !is_executable(&dir.join(name)),
                    "`{name}` is reachable from the mirror of {STOCK_PATH_DIRS:?}, so the tests \
                     here that require it absent would probe the real binary instead. It must be \
                     omitted, not shadowed: for `go`/`mise`/`nix-collect-garbage` an executable \
                     stub reads as PRESENT, because their absence is decided by `command -v` alone."
                );
            }
            // Load-bearing in the other direction, and by name because both are: `sh` runs every
            // fake, and `mkdir` is what the fakes in `side_effecting_tools` call to prove a probe
            // wrote to disk. Losing either would turn this fence into a silent no-op for the tests
            // that matter most, rather than a failure.
            for needed in ["sh", "mkdir"] {
                assert!(
                    is_executable(&dir.join(needed)),
                    "the fake `PATH` must still resolve `{needed}` — the fixtures here are \
                     `#!/bin/sh` scripts that call it"
                );
            }
            dir
        })
        .dir
    }

    /// The `PATH` every env-fenced test resolves under: the caller's own fake tools first (so they
    /// win every lookup), then [`stock_path_mirror`] — and nothing else. The stock directories are
    /// reached only THROUGH the mirror, which is what leaves every probed tool absent unless a test
    /// planted it.
    ///
    /// It REPLACES `PATH` rather than prepending to it. A prepend leaves the developer's real `PATH`
    /// reachable, so an "absent" test passes by accident on a bare CI runner and then fails the
    /// moment it runs on a machine with pnpm/conda/mise/uv/nix installed — which is what happened
    /// while writing this port: four of these tests failed on first run, all for that reason, none
    /// for a logic bug.
    fn isolated_path(tools: Option<&std::path::Path>) -> String {
        let mut dirs: Vec<String> = Vec::new();
        if let Some(t) = tools {
            dirs.push(t.display().to_string());
        }
        dirs.push(stock_path_mirror().display().to_string());
        dirs.join(":")
    }

    /// Enter the hermetic resolution environment: [`isolated_path`] installed, every variable in
    /// [`RESOLUTION_ENV`] unset, [`ENV_TEST_LOCK`] held, and all of it restored on drop. `tools` is
    /// the caller's own fake-tool directory, or `None` when the test wants no tools at all.
    fn env_fence(tools: Option<&std::path::Path>) -> EnvFence {
        let mut fence = EnvFence {
            _guard: ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
            restore: Vec::new(),
        };
        for key in RESOLUTION_ENV {
            fence.unset(key);
        }
        fence.set("PATH", &isolated_path(tools));
        fence
    }

    /// Resolve under [`env_fence`] with `dir`'s fakes as the only tools on `PATH`.
    fn with_isolated_path<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let _fence = env_fence(Some(dir));
        f()
    }

    /// Resolve under [`env_fence`] with no tools at all and ONE of [`RESOLUTION_ENV`] set — for the
    /// tests whose subject is the env-var override itself.
    fn with_env<T>(key: &'static str, value: &str, f: impl FnOnce() -> T) -> T {
        let mut fence = env_fence(None);
        fence.set(key, value);
        f()
    }

    /// The claim [`isolated_path`] is built on, checked rather than asserted in prose: inside the
    /// fence, a tool this module probes resolves to a file THIS TEST wrote or to nothing at all, so
    /// the binary a spawn reaches is never the machine's own. (First-match is the right predicate
    /// because that is what `execvp` uses; `tool_on_path` answers yes for a match at any position,
    /// which is why the tools have to be missing rather than merely shadowed.)
    ///
    /// The caller's own directory is now the ONLY permitted answer. Under the `exit 1` stubs this
    /// replaces, the shadow directory counted as ours too, so the test passed while `pip3` still
    /// read as present on the `PATH`-only preview path. If a future macOS or a CI image ships
    /// `/usr/bin/go`, or `bun`, or `uv`, [`stock_path_mirror`] omits it and this stays green;
    /// if the omission is ever broken, both go red, loudly and deterministically.
    #[test]
    fn no_tool_this_module_probes_resolves_outside_the_fence() {
        let planted = scratch("fence_self_check");
        let _fence = env_fence(Some(&planted));
        let path = std::env::var("PATH").unwrap();
        let ours = planted.display().to_string();
        for name in PROBED_TOOLS {
            let first = path
                .split(':')
                .filter(|d| !d.is_empty())
                .find(|d| is_executable(&std::path::Path::new(d).join(name)));
            let Some(dir) = first else {
                continue; // reachable from nowhere on this PATH — which is the point
            };
            assert!(
                dir == ours,
                "`{dir}/{name}` is what a spawn inside the fence would reach — a test here could \
                 run the machine's real {name}"
            );
        }
    }

    /// The `ubuntu-latest` condition, reproduced on whatever machine runs this rather than only
    /// where it happens to be true: that runner ships `/usr/bin/go`, no macOS does, and the fence's
    /// answer to it must be checked somewhere a developer can see it fail.
    ///
    /// `go`, `mise` and `nix-collect-garbage` are the ones that matter — [`tool_on_path`] reads any
    /// executable file as PRESENT, so a stub in front of them says the opposite of "absent" — but
    /// the property is asserted for all nine, because which tools a base image ships is not this
    /// module's to predict.
    #[test]
    fn a_stock_directory_that_ships_go_is_mirrored_without_it() {
        let stock = scratch("mirror_fixture_stock");
        for name in PROBED_TOOLS {
            write_fake(&stock.join(name), "exit 0");
        }
        write_fake(&stock.join("keep-me"), "exit 0");
        let shadowed = scratch("mirror_fixture_stock_later");
        write_fake(&shadowed.join("keep-me"), "exit 0");

        let mirror = scratch("mirror_fixture_out");
        let (first, second) = (stock.to_str().unwrap(), shadowed.to_str().unwrap());
        mirror_stock_dirs(&mirror, &[first, second]);

        for name in PROBED_TOOLS {
            assert!(
                !is_executable(&mirror.join(name)),
                "`{name}` survived into the mirror from a stock directory that ships it — every \
                 test here that requires it absent would probe that binary instead"
            );
        }
        assert!(
            is_executable(&mirror.join("keep-me")),
            "everything that is not a probed tool must stay reachable, or this fence breaks the \
             tests that spawn `sh` and `mkdir` while it holds the process `PATH`"
        );
        assert_eq!(
            fs::read_link(mirror.join("keep-me")).unwrap(),
            stock.join("keep-me"),
            "the earlier stock directory must win a name the later one also has — `PATH` resolves \
             first-match, and the mirror is only faithful if it does too"
        );
    }

    /// The cascade this module shipped with, as a test rather than a comment: a genuine failure must
    /// stay one failure. See [`Scratch`] — a `OnceLock` initializer that panics runs again for the
    /// next caller, and while the tag registry kept the first attempt's claim forever, that second
    /// run reported a bogus duplicate-tag collision instead of the real error, for every remaining
    /// test in the module.
    ///
    /// The panic below is deliberate, so the test runner prints its message to stderr on a PASSING
    /// run. That is expected output, not a symptom.
    #[test]
    fn a_tag_held_by_a_panicking_test_is_handed_back() {
        let tag = "tag_released_on_unwind";
        let failed = std::panic::catch_unwind(|| {
            let _held = scratch(tag);
            panic!("a genuine test failure, while holding a scratch tag");
        });
        assert!(failed.is_err(), "the panic must actually have unwound");
        let again = scratch(tag);
        assert!(
            again.is_dir(),
            "a tag its holder unwound out of must be claimable again — otherwise one real failure \
             turns every later test in this module red for the wrong reason"
        );
    }

    /// The other half, and the reason the release is scoped to unwinds: a tag whose holder finished
    /// NORMALLY stays retired. Two tests sharing a tag is a real bug, and whether they overlap in
    /// wall-clock time is up to the runner's thread pool — so handing tags back on every drop would
    /// make this detector exactly as intermittent as the flake it was written to kill.
    #[test]
    fn a_tag_whose_holder_finished_normally_stays_retired() {
        let tag = "tag_retired_after_a_clean_run";
        drop(scratch(tag));
        let reused = std::panic::catch_unwind(|| drop(scratch(tag)));
        assert!(
            reused.is_err(),
            "a second test asking for `{tag}` must still be rejected"
        );
    }

    // -- the guard the brief is built around: COREPACK_HOME is user-controlled, and without this
    // exact rejection a port deletes whatever it points at, including "/".

    #[test]
    fn corepack_home_unsafe_values_are_rejected_exactly_like_dev_sh() {
        let home = "/Users/testuser";
        for bad in [
            "/",
            home,
            &format!("{home}/"),
            &format!("{home}/Library"),
            &format!("{home}/Library/"),
        ] {
            assert!(is_unsafe_corepack_home(bad, home), "must reject: {bad}");
        }
        // A real, narrower cache dir under Library is fine.
        assert!(!is_unsafe_corepack_home(
            &format!("{home}/Library/Caches/node/corepack"),
            home
        ));
        assert!(!is_unsafe_corepack_home(
            &format!("{home}/.cache/node/corepack"),
            home
        ));
    }

    #[test]
    fn corepack_home_env_override_reaching_an_unsafe_value_is_never_resolved() {
        let home = scratch("corepack_home_env");
        let home_str = home.to_str().unwrap();
        // The exact hostile-input shape the brief names: COREPACK_HOME=$HOME.
        let target = with_env("COREPACK_HOME", home_str, || {
            corepack_target(home_str, Detection::MayInvoke)
        });
        assert!(
            target.is_none(),
            "COREPACK_HOME=$HOME must resolve to nothing, never to a plan entry: {target:?}"
        );
    }

    impl std::fmt::Debug for ResolvedTarget {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ResolvedTarget{{path: {}}}", self.path)
        }
    }

    #[test]
    fn corepack_home_env_override_relative_path_is_rejected() {
        // dev.sh:46 — `"$corepack_home" == /*` — a relative override must not be silently
        // resolved against some other base.
        let home = scratch("corepack_relative");
        let home_str = home.to_str().unwrap();
        let target = with_env("COREPACK_HOME", "relative/path", || {
            corepack_target(home_str, Detection::MayInvoke)
        });
        assert!(target.is_none());
    }

    // -- conda: five install-location variants, protected as a GROUP by any one of them.

    #[test]
    fn conda_whitelisting_any_one_variant_protects_all_five() {
        let home = "/Users/testuser";
        let whitelist = [format!("{home}/miniforge3/pkgs")];
        let wl_refs: Vec<&str> = whitelist.iter().map(String::as_str).collect();
        // "Even if conda were available" is made TRUE here rather than argued: a fake conda is put
        // on the fenced `PATH`, so the whitelist is the only thing that can be suppressing this
        // target. Read against the real machine's `PATH` instead, the assertion held on any machine
        // WITHOUT conda for a reason that has nothing to do with the whitelist — `conda_target`
        // returns `None` at its availability check — so deleting the group-protection check
        // outright would not have turned it red. With the fake present, it does.
        let conda = fake_tool_path("conda_whitelisted_path", "conda", "exit 0");
        let target = with_isolated_path(&conda, || {
            conda_target(home, &wl_refs, Detection::MayInvoke)
        });
        assert!(target.is_none(), "{target:?}");
    }

    #[test]
    fn conda_is_absent_without_the_binary_even_when_pkgs_dir_exists() {
        // No raw fallback: if `conda` isn't on PATH, the multi-GB pkgs dir must be left alone,
        // never swept directly — proven with a PATH containing no `conda` at all.
        let home = scratch("conda_no_binary");
        fs::create_dir_all(home.join(".conda/pkgs")).unwrap();
        fs::write(home.join(".conda/pkgs/big.tar.bz2"), vec![b'x'; 4096]).unwrap();
        let home_str = home.to_str().unwrap();
        let empty_path_dir = scratch("empty_path_for_conda_test");
        let target = with_isolated_path(&empty_path_dir, || {
            conda_target(home_str, &[], Detection::MayInvoke)
        });
        assert!(
            target.is_none(),
            "conda absent must yield no candidate at all, not a raw sweep: {target:?}"
        );
    }

    #[test]
    fn conda_is_available_delegates_and_sizes_the_first_variant() {
        let home = scratch("conda_available");
        fs::create_dir_all(home.join(".conda/pkgs")).unwrap();
        fs::write(home.join(".conda/pkgs/pkg.tar.bz2"), vec![b'x'; 2048]).unwrap();
        let home_str = home.to_str().unwrap();
        let fake_dir = fake_tool_path("conda_available_path", "conda", "exit 0");
        let target = with_isolated_path(&fake_dir, || {
            conda_target(home_str, &[], Detection::MayInvoke)
        });
        let target = target.expect("conda on PATH must resolve a target");
        assert_eq!(target.path, format!("{home_str}/.conda/pkgs"));
        assert!(
            target.delegate.is_some(),
            "must prefer delegation when conda is available"
        );
        assert_eq!(
            target.sweep,
            RawSweep::Never,
            "conda must never fall back to a raw sweep"
        );
        assert_eq!(
            target.delegate.and_then(|d| d.budget),
            Some(DISK_VERIFY_TIMEOUT),
            "dev.sh:105 wraps conda clean in MOLE_TIMEOUT_DISK_VERIFY_SEC, not the cleanup bucket"
        );
    }

    // -- pnpm/go/nix/pip: no raw fallback when the tool is unavailable.

    #[test]
    fn pnpm_absent_contributes_nothing() {
        let empty_path_dir = scratch("empty_path_for_pnpm_test");
        let home = "/Users/testuser";
        let target =
            with_isolated_path(&empty_path_dir, || pnpm_target(home, Detection::MayInvoke));
        assert!(target.is_none());
    }

    #[test]
    fn nix_absent_contributes_nothing_and_needs_no_home() {
        let empty_path_dir = scratch("empty_path_for_nix_test");
        let target = with_isolated_path(&empty_path_dir, || nix_target(&[]));
        assert!(target.is_none());
    }

    #[test]
    fn nix_available_has_no_raw_fallback_and_zero_size_not_the_whole_store() {
        let fake_dir = fake_tool_path("nix_available_path", "nix-collect-garbage", "exit 0");
        let target =
            with_isolated_path(&fake_dir, || nix_target(&[])).expect("must resolve when available");
        assert_eq!(target.path, "/nix/store");
        assert_eq!(target.sweep, RawSweep::Never);
        assert!(target.delegate.is_some());
        // The claim the doc comment used to make while `finish` did the opposite: the store is
        // never walked and never carries a byte figure.
        assert_eq!(target.size, SizeMode::NotMeasurable);
        // `dev.sh:442` has no `run_with_timeout` — a real store GC runs for minutes.
        assert_eq!(target.delegate.and_then(|d| d.budget), None);
    }

    #[test]
    fn go_returns_nothing_at_all_when_go_is_absent() {
        let home = scratch("go_absent_home");
        let home_str = home.to_str().unwrap();
        let empty_path_dir = scratch("empty_path_for_go_test");
        let targets = with_isolated_path(&empty_path_dir, || {
            go_targets(home_str, &[], Detection::MayInvoke)
        });
        assert!(targets.is_empty());
    }

    // -- mise: the one tool whose raw sweep is unconditional even when the tool IS available.

    #[test]
    fn mise_env_override_wins_over_detection_and_default() {
        let home = scratch("mise_env_override");
        let override_dir = scratch("mise_env_override_target");
        let target = with_env("MISE_CACHE_DIR", override_dir.to_str().unwrap(), || {
            mise_target(home.to_str().unwrap(), Detection::MayInvoke)
        });
        let target = target.unwrap();
        assert_eq!(target.path, override_dir.to_str().unwrap());
        assert_eq!(
            target.sweep,
            RawSweep::Always,
            "dev.sh:347 sits outside the `if command -v mise` block"
        );
    }

    #[test]
    fn mise_falls_back_to_default_cache_dir_without_the_tool() {
        // Needs BOTH `MISE_CACHE_DIR` absent AND an isolated `PATH` at once. `env_fence` establishes
        // exactly that pair on every entry — an unset `MISE_CACHE_DIR` is not this test's special
        // request, it is the hermetic environment every test here resolves under — so this no longer
        // hand-rolls the lock, and no longer depends on some other test having removed the variable
        // process-wide first.
        let home = scratch("mise_no_tool");
        let empty_path_dir = scratch("empty_path_for_mise_test");
        let target = with_isolated_path(&empty_path_dir, || {
            mise_target(home.to_str().unwrap(), Detection::MayInvoke)
        });
        let target = target.unwrap();
        assert_eq!(
            target.path,
            format!("{}/Library/Caches/mise", home.to_str().unwrap())
        );
        assert!(target.delegate.is_none());
        assert_eq!(target.sweep, RawSweep::Always);
    }

    // -- the remover combinator: delegation preferred, fallback only where allowed, and an
    // unrelated (non-tool) path is untouched by any of this.

    /// A delegation to a stock binary with a generous budget — `/usr/bin/true` (always 0) or
    /// `/usr/bin/false` (always 1) — so the combinator's branching is exercised without depending
    /// on any dev tool being installed.
    ///
    /// Named by ABSOLUTE path, and that is load-bearing: the tests below exercise the combinator
    /// rather than tool detection, so they hold no [`EnvFence`] and run CONCURRENTLY with tests that
    /// have replaced the process `PATH`. A bare `true` would resolve against whatever `PATH` those
    /// happen to have installed at that instant.
    fn stock(program: &'static str) -> Delegation {
        Delegation {
            program,
            args: &[],
            budget: Some(Duration::from_secs(10)),
        }
    }

    fn dc(
        path: &Path,
        size: u64,
        delegate: Option<Delegation>,
        sweep: RawSweep,
    ) -> DelegatedCandidate {
        DelegatedCandidate {
            candidate: CleanCandidate {
                path: path.to_string_lossy().to_string(),
                label: "fake tool cache".into(),
                size,
            },
            delegate,
            sweep,
        }
    }

    #[test]
    fn remover_for_prefers_delegation_and_never_touches_the_real_filesystem_on_success() {
        let root = scratch("remover_delegation_success");
        let cache_dir = root.join("cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("data"), b"do not delete").unwrap();

        let resolved = vec![dc(
            &cache_dir,
            4,
            Some(stock("/usr/bin/true")),
            RawSweep::WhenToolAbsent,
        )];
        let calls: std::cell::RefCell<u32> = std::cell::RefCell::new(0);
        let default_remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            *calls.borrow_mut() += 1;
            Ok(Removal::Removed)
        };
        let remover = remover_for(&resolved, &[], default_remover);
        let result = remover(&cache_dir, false);
        assert_eq!(
            *calls.borrow(),
            0,
            "delegation succeeded — the raw remover must not run"
        );
        assert!(
            cache_dir.join("data").exists(),
            "a successful delegation must not touch the filesystem directly"
        );
        // …and because it touched nothing, it must SAY so. `Ok(())` here is what let the caller
        // bill the whole cache and log it as recoverable (RULEBOOK §3m).
        assert_eq!(
            result,
            Ok(Removal::Delegated),
            "a delegation that never touched the filesystem must not report a removal"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remover_for_falls_back_when_delegation_fails_and_the_oracle_sweeps_on_failure() {
        // bun's shape (`RawSweep::WhenToolAbsentOrFailed`, `dev.sh:241-243`). The fallback is
        // `safe_clean "$dir"/*`, so the remover is called once PER CHILD and never on the directory
        // itself — see `sweep_children`. Two visible children, two calls, parent never handed over.
        let root = scratch("remover_fallback_children");
        let cache = root.join("cache");
        fs::create_dir_all(cache.join("a")).unwrap();
        fs::create_dir_all(cache.join("b")).unwrap();
        let resolved = vec![dc(
            &cache,
            1,
            Some(stock("/usr/bin/false")), // `/usr/bin/false` always exits 1
            RawSweep::WhenToolAbsentOrFailed,
        )];
        let seen: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
        let default_remover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(p.to_string_lossy().to_string());
            fs::remove_dir_all(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let remover = remover_for(&resolved, &[], default_remover);
        let result = remover(&cache, false);
        assert!(result.is_ok(), "{result:?}");
        let mut got = seen.borrow().clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                cache.join("a").to_string_lossy().to_string(),
                cache.join("b").to_string_lossy().to_string()
            ],
            "a failed delegation must sweep the CHILDREN, not remove the tree"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_delegation_must_not_sweep_when_the_oracle_sweeps_only_on_a_missing_tool() {
        // corepack (`dev.sh:53-57`) and uv (`:62-71`) write their `safe_clean` as the `else` of
        // `command -v`, so it is reachable ONLY when the tool is absent. With the tool PRESENT and
        // its clean command failing — which is exactly what a timeout looks like — bash does
        // nothing at all. Collapsing "missing" and "failed" into one flag turns a failed
        // `uv cache prune` (a prune of UNUSED entries) into deleting the whole uv cache.
        let root = scratch("no_sweep_on_failure");
        let cache = root.join("cache");
        fs::create_dir_all(cache.join("keep-me-please")).unwrap();
        let resolved = vec![dc(
            &cache,
            1,
            Some(stock("/usr/bin/false")), // present, and its clean command fails
            RawSweep::WhenToolAbsent,
        )];
        let default_remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            panic!("bash does nothing on this branch — the sweep must not run");
        };
        let remover = remover_for(&resolved, &[], default_remover);
        let result = remover(&cache, false);
        assert!(
            result.is_err(),
            "a failed clean command is reported, not escalated into a delete: {result:?}"
        );
        assert!(
            cache.join("keep-me-please").exists(),
            "the cache the oracle leaves alone must still be there"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remover_for_errors_rather_than_falling_back_when_the_oracle_forbids_it() {
        let resolved = vec![dc(
            Path::new("/whatever/conda-like"),
            1,
            Some(stock("/usr/bin/false")),
            RawSweep::Never, // e.g. conda/pnpm/go/nix/pip
        )];
        let default_remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            panic!("must never be called when the oracle has no raw fallback");
        };
        let remover = remover_for(&resolved, &[], default_remover);
        let result = remover(Path::new("/whatever/conda-like"), false);
        assert!(
            result.is_err(),
            "must report an error, not silently succeed or hard-delete"
        );
    }

    #[test]
    fn mise_sweeps_even_after_a_successful_delegation() {
        // `safe_clean "$mise_cache_path"/* "mise cache"` (`dev.sh:347`) sits OUTSIDE the
        // `if command -v mise` block, so it runs on every path through `clean_dev_mise` — including
        // the one where `mise cache clear` already succeeded. `RawSweep::Always` is what makes that
        // true of the code; before it, the flag's comment said "always" and the combinator reached
        // the sweep only when delegation was absent or failed.
        let root = scratch("mise_always_sweeps");
        let cache = root.join("cache");
        fs::create_dir_all(cache.join("leftover")).unwrap();
        let resolved = vec![dc(
            &cache,
            1,
            Some(stock("/usr/bin/true")),
            RawSweep::Always,
        )];
        let seen: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
        let default_remover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(p.to_string_lossy().to_string());
            fs::remove_dir_all(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let remover = remover_for(&resolved, &[], default_remover);
        assert!(remover(&cache, true).is_ok());
        assert_eq!(
            seen.borrow().clone(),
            vec![cache.join("leftover").to_string_lossy().to_string()],
            "the unconditional sweep must still run after a successful `mise cache clear`"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_sweep_claims_only_the_bytes_it_measured_going_away_not_the_parents_planned_size() {
        // The parent candidate is planned at 10 MB, but the sweep spares the whitelisted child, so
        // only the swept child's bytes may be claimed. Billing `candidate.size` here would report
        // freeing the protected child's bytes too — the same disease as the delegation case, one
        // layer down (RULEBOOK §3m).
        let root = scratch("sweep_measures_what_it_removed");
        let cache = root.join("cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("swept"), vec![b'x'; 4096]).unwrap();
        fs::write(cache.join("keep-me"), vec![b'y'; 8192]).unwrap();
        let keep = cache.join("keep-me").to_string_lossy().to_string();
        let wl = [keep.as_str()];

        let resolved = vec![dc(&cache, 10 * 1024 * 1024, None, RawSweep::WhenToolAbsent)];
        let default_remover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            fs::remove_file(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let remover = remover_for(&resolved, &wl, default_remover);
        let result = remover(&cache, true);
        assert_eq!(
            result,
            Ok(Removal::Swept { bytes: 4096 }),
            "only the child actually removed counts, not the 10MB plan figure: {result:?}"
        );
        assert!(cache.join("keep-me").exists());
        assert!(!cache.join("swept").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_raw_fallback_spares_every_child_the_oracle_spares() {
        // `dev.sh:56/:70/:242/:245/:347` are all `safe_clean "$dir"/*`, so bash evaluates its rails
        // PER CHILD. Four kinds of child survive that and must survive here: a hidden one (bash runs
        // with `dotglob` unset, so `dir/*` never matches it), a whitelisted one, and two that
        // `should_protect_path` protects. Removing the tree — which this remover used to do —
        // destroys all four.
        //
        // This exact five-child shape was run through the REAL bash first, composing what
        // `safe_clean "$dir"/*` composes (shell glob expansion, then `should_protect_path` +
        // `is_path_whitelisted`, then `safe_remove`'s `validate_path_for_deletion`) with
        // `WHITELIST_PATTERNS=("$dir/keep-me")`. The oracle's answer was:
        //
        //     SKIP protected  com.apple.Safari
        //     SKIP protected  com.jetbrains.goland
        //     SKIP whitelist  keep-me
        //     REMOVE          plain
        //
        // `.hidden` never appeared at all — the glob does not produce it. This test asserts that
        // same single removal.
        //
        // check_tests: no-golden — the reproduction above is a one-off differential run, not a
        // captured artifact; the per-path VERDICTS it depends on are pinned against the real bash by
        // `protect.rs`'s and `validate.rs`'s fixture-loading tests. What this adds is which paths
        // the remover is invoked on, which is a property of this function and of no capture.
        let root = scratch("raw_fallback_child_rails");
        let cache = root.join("cache");
        fs::create_dir_all(cache.join("plain")).unwrap();
        fs::create_dir_all(cache.join(".hidden")).unwrap();
        fs::create_dir_all(cache.join("keep-me")).unwrap();
        // `com.apple.Safari` is a SYSTEM_CRITICAL_BUNDLES entry and `com.jetbrains.goland` a
        // DATA_PROTECTED_BUNDLES one, so should_protect_path protects a child named either —
        // exactly like the real `~/Library/Caches/com.apple.Safari`.
        fs::create_dir_all(cache.join("com.apple.Safari")).unwrap();
        fs::create_dir_all(cache.join("com.jetbrains.goland")).unwrap();

        let resolved = vec![dc(&cache, 1, None, RawSweep::WhenToolAbsent)];
        let keep = cache.join("keep-me").to_string_lossy().to_string();
        let seen: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
        let default_remover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(p.to_string_lossy().to_string());
            Ok(Removal::Removed)
        };
        let wl = [keep.as_str()];
        let remover = remover_for(&resolved, &wl, default_remover);
        assert!(remover(&cache, true).is_ok());

        let got = seen.borrow().clone();
        assert_eq!(
            got,
            vec![cache.join("plain").to_string_lossy().to_string()],
            "only the plain child may be swept: {got:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tool_that_exits_zero_deleting_nothing_is_billed_nothing_and_the_blob_stays_on_disk() {
        // THE reproduction behind RULEBOOK §3m, driven end-to-end through the real combinator AND
        // the real executor: a fake `uv` first on `PATH` whose `cache prune` exits 0 having
        // deleted nothing. Before this fix the same run reported 512000 bytes freed while the
        // 512000-byte blob was still sitting there.
        //
        // The assertion is deliberately "what the ACCOUNTING claims" vs "what the FILESYSTEM says
        // is still there", read back with `metadata().len()` after the run — not "delegation
        // returned Ok", which is what the old test asserted and is exactly the thing that was
        // true while the accounting lied.
        //
        // Hermetic by construction: the candidate is built here rather than through
        // `resolve_candidates`, which would probe the REAL `PATH` and could hand a live
        // `go clean -modcache` to a destructive executor.
        let root = scratch("accounting_vs_disk");
        let cache = root.join("uv");
        fs::create_dir_all(&cache).unwrap();
        let blob = cache.join("blob");
        fs::write(&blob, vec![b'x'; 512_000]).unwrap();
        let planned = size_if_exists(&cache.to_string_lossy()).unwrap();
        assert!(planned >= 512_000, "fixture sanity: {planned}");

        let fake_uv = fake_tool_path("accounting_vs_disk_path", "uv", "exit 0");
        let resolved = vec![dc(
            &cache,
            planned,
            Some(Delegation {
                program: "uv",
                args: &["cache", "prune"],
                budget: Some(PKG_CLEANUP_TIMEOUT),
            }),
            RawSweep::WhenToolAbsent,
        )];
        let plan = vec![resolved[0].candidate.clone()];
        let outcome = with_isolated_path(&fake_uv, || {
            let remover = remover_for(&resolved, &[], super::super::execute::remove_one_reported);
            super::super::execute::execute_clean_with_remover(
                &plan,
                &[],
                false, // the DEFAULT path — the one whose audit line claimed "trash"
                ProtectionMode::Cleanup,
                |_| {},
                remover,
            )
        });

        // What is actually on disk, measured after the run.
        assert!(
            blob.exists(),
            "the fake tool deleted nothing, by construction"
        );
        assert_eq!(fs::metadata(&blob).unwrap().len(), 512_000);

        // What the accounting claims about it.
        assert_eq!(
            outcome.freed_bytes, 0,
            "nothing was freed, so nothing may be billed: {outcome:?}"
        );
        assert_eq!(outcome.removed.len(), 1, "the action is still reported");
        assert_eq!(
            outcome.removed[0].freed,
            super::super::execute::Freed::Delegated
        );
        assert_eq!(outcome.removed[0].bytes(), 0);
        assert!(
            !outcome.removed[0].is_auditable_deletion(),
            "no `trash … ok` record may be written for bytes that never went to any Trash"
        );
        assert!(outcome.errors.is_empty(), "{outcome:?}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remover_for_leaves_unrelated_paths_to_the_default_remover_untouched() {
        let resolved: Vec<DelegatedCandidate> = Vec::new();
        let calls: std::cell::RefCell<u32> = std::cell::RefCell::new(0);
        let default_remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            *calls.borrow_mut() += 1;
            Ok(Removal::Removed)
        };
        let remover = remover_for(&resolved, &[], default_remover);
        let result = remover(Path::new("/some/universal/target"), true);
        assert!(result.is_ok());
        assert_eq!(*calls.borrow(), 1);
    }

    // -- resolve_candidates: the user's whitelist protects a resolved tool cache exactly like any
    // other candidate, and Trash-vs-permanent is a property of the SAME CleanCandidate type, not
    // something tool_delegate needs to re-implement — proven by construction (DelegatedCandidate
    // wraps the identical CleanCandidate execute.rs already Trash/permanent-dispatches).

    #[test]
    fn resolve_candidates_drops_a_whitelisted_tool_cache_entirely() {
        let home = scratch("resolve_whitelist");
        fs::create_dir_all(home.join(".cache/uv")).unwrap();
        fs::write(home.join(".cache/uv/index"), vec![b'x'; 100]).unwrap();
        let home_str = home.to_str().unwrap();
        let empty_path_dir = scratch("empty_path_for_resolve_test");
        let uv_path = format!("{home_str}/.cache/uv");
        let wl = [uv_path.as_str()];
        let out = with_isolated_path(&empty_path_dir, || {
            resolve_candidates(home_str, &wl, Detection::MayInvoke)
        });
        assert!(
            out.iter().all(|dc| dc.candidate.path != uv_path),
            "a whitelisted resolved cache must never reach the candidate list: {:?}",
            out.iter().map(|dc| &dc.candidate.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn resolve_candidates_includes_an_existing_unwhitelisted_uv_cache_with_no_tool_on_path() {
        let home = scratch("resolve_uv_default");
        fs::create_dir_all(home.join(".cache/uv")).unwrap();
        fs::write(home.join(".cache/uv/index"), vec![b'x'; 4096]).unwrap();
        let home_str = home.to_str().unwrap();
        let empty_path_dir = scratch("empty_path_for_resolve_uv_test");
        let out = with_isolated_path(&empty_path_dir, || {
            resolve_candidates(home_str, &[], Detection::MayInvoke)
        });
        let uv_path = format!("{home_str}/.cache/uv");
        let found = out.iter().find(|dc| dc.candidate.path == uv_path);
        let found = found.expect("uv's default cache dir must be planned even with uv absent");
        assert_eq!(
            found.sweep,
            RawSweep::WhenToolAbsent,
            "uv allows a raw sweep when the tool is unavailable — and only then (dev.sh:70)"
        );
        assert!(found.delegate.is_none());
        assert!(found.candidate.size >= 4096);
    }

    // -- the property this module exists to hold: a PREVIEW does not write to the disk it previews.

    /// Every entry under `root`, as (path relative to `root`, byte length), sorted. Read off the
    /// real filesystem both times — a snapshot, never a hand-written expectation — and stricter than
    /// the `find "$HOME" | sort` the same property is checked with against the built binary, because
    /// it also catches a file that was rewritten rather than created.
    fn tree_snapshot(root: &std::path::Path) -> Vec<(String, u64)> {
        fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, u64)>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for e in entries.filter_map(|e| e.ok()) {
                let p = e.path();
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                let len = fs::symlink_metadata(&p).map(|m| m.len()).unwrap_or(0);
                out.push((rel, len));
                if p.is_dir() {
                    walk(&p, root, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// A `PATH` directory holding a fake for every tool this module probes, each of which **writes
    /// to the filesystem when merely asked a question** — the defining behaviour of the real ones
    /// (`pnpm --version` through a corepack shim unpacks a 38 MB tarball into `COREPACK_HOME`,
    /// `bun pm cache` creates the cache dir, `mise cache path` creates `~/.local/share/mise`,
    /// `go env GOCACHE` creates `~/Library/Application Support/go/telemetry`).
    ///
    /// The side-effect location is baked into each script as a literal rather than derived from
    /// `$HOME`, so nothing here depends on — or mutates — the process-wide `HOME` that the rest of
    /// the suite reads. Which is exactly why `tag` names the CALLING TEST: three tests want this
    /// directory, the literals inside differ per caller, and one shared tag meant each caller wiped
    /// and rewrote the fakes the other two were running. See [`scratch`].
    fn side_effecting_tools(tag: &str, home: &std::path::Path) -> Scratch {
        let dir = scratch(tag);
        let h = home.display();
        // (tool, the directory it fabricates and then reports) — the real per-tool locations.
        let tools = [
            ("corepack", format!("{h}/.cache/node/corepack")),
            ("uv", format!("{h}/.cache/uv")),
            ("pnpm", format!("{h}/Library/pnpm/store")),
            ("bun", format!("{h}/.bun/install/cache")),
            ("mise", format!("{h}/.local/share/mise")),
            ("go", format!("{h}/Library/Application Support/go")),
            ("conda", format!("{h}/.conda/pkgs")),
            ("pip3", format!("{h}/Library/Caches/pip")),
        ];
        for (name, side_effect) in tools {
            write_fake(
                &dir.join(name),
                &format!(
                    "mkdir -p '{side_effect}'\nprintf probe > '{side_effect}/probed'\necho '{side_effect}'"
                ),
            );
        }
        dir
    }

    #[test]
    fn a_preview_resolution_leaves_a_real_home_byte_identical() {
        let home = scratch("preview_leaves_home_untouched");
        // A real fixture with something worth planning, so this cannot pass by doing nothing: the
        // preview must still find and size uv's default cache while spawning none of the tools.
        fs::create_dir_all(home.join(".cache/uv")).unwrap();
        fs::write(home.join(".cache/uv/index"), vec![b'x'; 8192]).unwrap();
        let home_str = home.to_str().unwrap().to_string();
        let tools = side_effecting_tools("preview_leaves_home_untouched_tools", &home);

        let before = tree_snapshot(&home);
        let out = with_isolated_path(&tools, || {
            resolve_candidates(&home_str, &[], Detection::PathOnly)
        });
        let after = tree_snapshot(&home);

        assert_eq!(
            before, after,
            "`clean` without `--apply` must not create, grow or rewrite a single file under HOME"
        );
        let uv_path = format!("{home_str}/.cache/uv");
        let uv = out.iter().find(|dc| dc.candidate.path == uv_path).expect(
            "the preview must still plan uv's default cache — otherwise this proves nothing",
        );
        assert!(uv.candidate.size >= 8192);
    }

    #[test]
    fn the_same_fakes_do_write_under_may_invoke_so_the_preview_test_is_not_vacuous() {
        // The guard on the test above: if these fakes were inert, "nothing changed" would be true
        // for the wrong reason. Under `MayInvoke` — the `--apply` path, where the oracle's probes
        // are kept verbatim — the identical fakes must dirty the identical tree.
        let home = scratch("may_invoke_does_write");
        let home_str = home.to_str().unwrap().to_string();
        let tools = side_effecting_tools("may_invoke_does_write_tools", &home);

        let before = tree_snapshot(&home);
        let _ = with_isolated_path(&tools, || {
            resolve_candidates(&home_str, &[], Detection::MayInvoke)
        });
        let after = tree_snapshot(&home);

        assert_ne!(
            before, after,
            "these fakes must actually write when invoked, or the preview test proves nothing"
        );
        assert!(
            after.iter().any(|(p, _)| p.contains("probed")),
            "expected the probe marker the fakes write: {after:?}"
        );
    }

    #[test]
    fn preview_resolution_uses_the_oracles_own_probe_less_defaults_for_every_path() {
        // What the preview gives up by not asking: each path is `dev.sh`'s own `[[ -z "$x" ]]`
        // fallback literal, checked one tool at a time rather than assumed to be uniform. The fakes
        // above would report something DIFFERENT for each (`~/.local/share/mise` for mise,
        // `~/Library/Application Support/go` for go, …), so a probe leaking into this mode would
        // move the path and fail the assertion, not merely dirty the disk.
        let home = scratch("preview_defaults");
        let home_str = home.to_str().unwrap().to_string();
        let tools = side_effecting_tools("preview_defaults_tools", &home);
        let d = Detection::PathOnly;
        let (uv, pnpm, bun, mise, go, pip) = with_isolated_path(&tools, || {
            (
                uv_target(&home_str, d).unwrap().path,
                pnpm_target(&home_str, d).unwrap().path,
                bun_target(&home_str, d).unwrap().path,
                mise_target(&home_str, d).unwrap().path,
                go_targets(&home_str, &[], d)
                    .into_iter()
                    .map(|t| t.path)
                    .collect::<Vec<_>>(),
                pip_target(&home_str, d).unwrap().path,
            )
        });
        assert_eq!(uv, format!("{home_str}/.cache/uv")); // dev.sh:61
        assert_eq!(pnpm, format!("{home_str}/Library/pnpm/store")); // dev.sh:169
        assert_eq!(bun, format!("{home_str}/.bun/install/cache")); // dev.sh:186
        assert_eq!(mise, format!("{home_str}/Library/Caches/mise")); // dev.sh:327
        assert_eq!(
            go,
            vec![
                format!("{home_str}/Library/Caches/go-build"), // dev.sh:284
                format!("{home_str}/go/pkg/mod"),              // dev.sh:285
            ]
        );
        assert_eq!(pip, format!("{home_str}/Library/Caches/pip")); // dev.sh:261
    }

    #[test]
    fn mise_cache_dir_override_still_wins_in_preview_because_the_oracle_reads_it_first() {
        // `dev.sh:313-316` checks `MISE_CACHE_DIR` BEFORE it ever consults the tool, so dropping the
        // probe must not drop the override with it.
        let home = scratch("preview_mise_override");
        let override_dir = scratch("preview_mise_override_target");
        let target = with_env("MISE_CACHE_DIR", override_dir.to_str().unwrap(), || {
            mise_target(home.to_str().unwrap(), Detection::PathOnly)
        })
        .unwrap();
        assert_eq!(target.path, override_dir.to_str().unwrap());
    }

    // -----------------------------------------------------------------------------------------
    // BUR-130: under elevation, a developer tool is never taken from `PATH`
    // -----------------------------------------------------------------------------------------

    /// A fake tool that leaves a footprint when it runs, so "was it spawned" is a fact on disk
    /// rather than an inference from a return value.
    fn footprint_tool(tag: &str, name: &str) -> (Scratch, std::path::PathBuf) {
        let dir = scratch(tag);
        let footprint = dir.join("ran");
        write_fake(
            &dir.join(name),
            &format!("touch '{}'; echo /tmp/fake-cache", footprint.display()),
        );
        (dir, footprint)
    }

    /// The name is one no trusted directory ships, so the privileged half is decided by the rule
    /// and not by whether this machine happens to have the real tool in `/opt/homebrew/bin`.
    const FAKE_DEVTOOL: &str = "burrow-fake-devtool";

    // check_tests: no-golden — an elevation rule with no oracle; the anchor is `platform`'s
    // trusted-directory contract and the marker the app's helper sets.
    #[test]
    fn under_the_privileged_marker_a_tool_planted_on_path_is_neither_present_nor_spawned() {
        if crate::platform::is_root() {
            // Already privileged by uid; the unprivileged half below cannot be observed.
            return;
        }
        let (dir, footprint) = footprint_tool("privileged_marker", FAKE_DEVTOOL);
        let mut fence = env_fence(Some(&dir));

        // Unelevated: the planted tool is present, and a probe runs it — the dry-run's `PathOnly`
        // presence check and the apply's spawn both read the user's own `PATH`, as before.
        assert!(tool_on_path(FAKE_DEVTOOL), "planted on PATH, unprivileged");
        assert_eq!(
            run(FAKE_DEVTOOL, &["cache", "dir"], &[]).as_deref(),
            Some("/tmp/fake-cache")
        );
        assert!(
            footprint.exists(),
            "the probe must actually have run the fake"
        );
        fs::remove_file(&footprint).unwrap();

        // Elevated by the marker: the same `PATH`, the same file — and it is not a tool any more.
        fence.set(crate::platform::PRIVILEGED_MARKER, "1");
        assert!(
            !tool_on_path(FAKE_DEVTOOL),
            "under elevation PATH is not consulted, so the planted tool is absent"
        );
        assert_eq!(run(FAKE_DEVTOOL, &["cache", "dir"], &[]), None);
        assert!(
            !footprint.exists(),
            "a PATH-planted binary must never be spawned by a privileged engine"
        );
        // …and a delegation — the apply-time `<tool> cache prune` — is refused the same way,
        // reported as unavailable rather than run.
        let err = try_delegate(stock(FAKE_DEVTOOL)).unwrap_err();
        assert!(err.contains("unavailable"), "{err}");
        assert!(!footprint.exists());
    }

    /// The dry run keeps probing unelevated: every tool this module resolves still answers from
    /// `PATH` when no marker is set, which is what makes the preview's `PathOnly` detection work
    /// on a developer's machine at all.
    #[test]
    fn without_the_marker_every_probed_tool_still_resolves_from_path() {
        if crate::platform::is_root() {
            return;
        }
        let dir = scratch("unprivileged_path");
        for name in PROBED_TOOLS {
            write_fake(&dir.join(name), "exit 0");
        }
        let mut fence = env_fence(Some(&dir));
        fence.unset(crate::platform::PRIVILEGED_MARKER);
        for name in PROBED_TOOLS {
            assert!(
                tool_on_path(name),
                "{name} planted on PATH must resolve unelevated"
            );
        }
    }
}
