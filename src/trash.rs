//! Recoverable deletion — move a path into the real macOS Trash instead of an irreversible
//! `fs::remove_dir_all`/`fs::remove_file`. Ported from digger's `mole_delete` / `_mole_move_to_trash`
//! (`lib/core/file_ops.sh`): prefer the `trash` CLI, fall back to asking Finder to `delete` the path
//! via AppleScript.
//!
//! On current macOS the `trash` CLI is `/usr/bin/trash`, an Apple-shipped binary (`man trash`: "First
//! appeared in macOS 15.0") — not an optional Homebrew install, though it happens to be invoked
//! identically to the Homebrew formula digger originally targeted (`command -v trash`), so either one
//! satisfies the same tier. It needs no GUI/Automation permission — it's a plain move into
//! `~/.Trash`, not an Apple Event to another app. This crate's minimum supported OS is macOS 14
//! (`macos/project.yml`'s `MACOSX_DEPLOYMENT_TARGET`), which PREDATES that binary, so the AppleScript
//! fallback (digger's own fallback too) is not a rare edge case here — it is the ONLY mechanism on
//! macOS 14, and it does need Finder reachable.
//!
//! Both mechanisms hand the actual move to the OS/Finder rather than reimplementing Trash semantics
//! (per-volume `.Trashes`, `~/.Trash`, uniquifying a name that already exists, recording the "Put
//! Back" origin) with `mv` — reproducing those correctly outside the OS is genuinely hard, and any
//! gap would make a deleted file LOOK recoverable while actually being subtly broken (no Put Back,
//! wrong volume's Trash, a silently overwritten same-name item). That is worse than refusing. If
//! NEITHER mechanism succeeds — most commonly because there is no `trash` binary AND no reachable
//! Finder/GUI session for the AppleScript fallback (headless SSH, a launchd context with no window
//! server) — [`move_to_trash`] returns an error rather than silently deleting the path some other
//! way. A recoverable-delete contract that quietly becomes permanent on failure is exactly the bug
//! this module exists to close; callers (`clean::execute`, `purge`, `installer`) must treat that
//! error as "not removed", never as license to fall back to `fs::remove_*`.
//!
//! Verified for real (not just unit-tested — see this module's tests for why the OS interaction
//! itself isn't automated): both tiers were run against throwaway scratch fixtures — a plain file
//! AND a directory with nested content, since `clean`'s real targets are almost all directories —
//! and confirmed to land them in a real per-volume Trash, and both were confirmed to fail (non-zero
//! exit) on a path that doesn't exist, proving the fail-closed branch is reachable, not merely
//! written.
//!
//! **Trash is per-volume, not per-`$HOME`.** Every path this crate actually trashes (`clean`'s
//! `~/Library/Caches` etc., `purge`'s project artifacts, `installer`'s downloaded files) lives under
//! `$HOME` on the boot volume, so in practice that means `~/.Trash`, and overriding the `HOME`
//! environment variable does NOT redirect where a real trash call lands — confirmed empirically: it
//! is keyed off the target path's own volume, not any environment variable, which also means this
//! mechanism cannot be pointed at a scratch `HOME` for hermetic end-to-end testing (see the module's
//! test comments for how it's tested instead). If a target ever resolved onto a different mounted
//! volume (an external disk, a disk image), it would land in THAT volume's own hidden `.Trashes`,
//! not `~/.Trash` — correct macOS behavior, matching digger's own `mole_delete`, not something this
//! module tries to normalize away.

use std::path::Path;
use std::time::Duration;

/// Generous but bounded — matches this crate's other "OS utility that should be near-instant but
/// must never hang forever" budgets (see `status::collect`'s per-collector timeouts). A real move
/// measures in milliseconds; this only needs enough headroom that a slow-but-healthy call still
/// finishes, while a wedged `osascript` (waiting on a WindowServer connection that will never
/// arrive) is still killed and reported as a failure within the run rather than hanging the whole
/// destructive command.
const TRASH_TIMEOUT: Duration = Duration::from_secs(10);

/// Move `path` to the Trash. Tries the `trash` CLI first, then an AppleScript
/// `tell application "Finder" to delete` (see the module docs for why both tiers exist and why
/// failure must never fall back to a hard delete). `Err` — never a silent permanent delete — when
/// neither mechanism succeeds.
pub fn move_to_trash(path: &Path) -> Result<(), String> {
    // Resolved rather than spawned by name: under elevation `PATH` is not trusted, and a `trash`
    // planted on it would otherwise run as root (`crate::platform::resolve_helper`). Unprivileged
    // this is the same `PATH` lookup `Command::new("trash")` would do.
    let trash_bin = crate::platform::resolve_helper("trash", None, &[]);
    move_to_trash_with(
        path,
        trash_bin.as_deref(),
        crate::status::collect::run_command_with_timeout,
    )
}

/// The AppleScript interpreter, at its fixed system location — never resolved through `PATH`.
const OSASCRIPT: &str = "/usr/bin/osascript";

/// [`move_to_trash`] with the subprocess runner injected, so tier selection, the argv shape, and the
/// fail-safe error path are unit-tested without ever touching the real Trash or requiring a GUI
/// session — the real OS interaction is verified separately (see the module docs); mocking it away
/// entirely here would prove nothing about whether the actual mechanism works, so this split exists
/// only to make the DISPATCH logic (which tier runs, in what order, and what happens when one or
/// both fail) checkable by a fast, deterministic, CI-safe test. `run` mirrors
/// `run_command_with_timeout`'s own contract: `Some(stdout)` on a zero exit within the timeout,
/// `None` on any failure (non-zero exit, spawn failure, or timeout).
///
/// `trash_bin` is the resolved `trash` CLI, or `None` when there is none to try — the tier is
/// skipped, never spawned by bare name.
fn move_to_trash_with(
    path: &Path,
    trash_bin: Option<&Path>,
    run: impl Fn(&str, &[&str], Duration) -> Option<String>,
) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("recoverable delete (Trash) needs macOS".to_string());
    }
    let Some(p) = path.to_str() else {
        return Err(format!(
            "path is not valid UTF-8, refusing rather than guessing: {}",
            path.display()
        ));
    };

    // Tier 1: the `trash` CLI (Apple's own /usr/bin/trash on macOS 15+, or the identically-invoked
    // Homebrew formula digger preferred — either way, no AppleEvents, so no GUI/Automation
    // permission is needed).
    if let Some(bin) = trash_bin.and_then(Path::to_str) {
        if run(bin, &[p], TRASH_TIMEOUT).is_some() {
            return Ok(());
        }
    }

    // Tier 2: ask Finder directly. The path rides argv (`item 1 of argv`), never embedded in the
    // script text, matching digger's own `_mole_move_to_trash` — so quotes/backslashes/newlines in
    // a real path can't break out of a string literal or alter the script.
    let script = [
        "on run argv",
        "set p to POSIX file (item 1 of argv)",
        "tell application \"Finder\"",
        "delete p",
        "end tell",
        "end run",
    ];
    let mut args: Vec<&str> = Vec::with_capacity(script.len() * 2 + 1);
    for line in script {
        args.push("-e");
        args.push(line);
    }
    args.push(p);
    if run(OSASCRIPT, &args, TRASH_TIMEOUT).is_some() {
        return Ok(());
    }

    Err(format!(
        "couldn't move to Trash — no `trash` binary and Finder unreachable (no GUI session?): {p}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    /// The program name a runner was handed, without its directory — the tiers are identified by
    /// binary, and the `trash` tier now arrives resolved to a full path.
    fn tier(prog: &str) -> String {
        Path::new(prog)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    const TRASH_BIN: &str = "/usr/bin/trash";

    #[test]
    fn first_successful_tier_wins_and_the_second_is_never_invoked() {
        let calls: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let run = |prog: &str, _args: &[&str], _t: Duration| -> Option<String> {
            calls.borrow_mut().push(tier(prog));
            if tier(prog) == "trash" {
                Some(String::new())
            } else {
                panic!("osascript must not run once the trash CLI already succeeded")
            }
        };
        let result = move_to_trash_with(&p("/x/y"), Some(Path::new(TRASH_BIN)), run);
        if cfg!(target_os = "macos") {
            assert_eq!(result, Ok(()));
            assert_eq!(calls.into_inner(), vec!["trash".to_string()]);
        } else {
            assert!(
                result.is_err(),
                "non-macOS must refuse before spawning anything"
            );
        }
    }

    #[test]
    fn falls_back_to_osascript_when_the_trash_cli_is_unavailable() {
        let run = |prog: &str, _args: &[&str], _t: Duration| -> Option<String> {
            match tier(prog).as_str() {
                "trash" => None, // present but failing
                "osascript" => Some(String::new()),
                other => panic!("unexpected program: {other}"),
            }
        };
        let result = move_to_trash_with(&p("/x/y"), Some(Path::new(TRASH_BIN)), run);
        if cfg!(target_os = "macos") {
            assert_eq!(result, Ok(()));
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn no_trash_binary_at_all_skips_the_tier_rather_than_spawning_a_bare_name() {
        // macOS 14 (pre-/usr/bin/trash) with no Homebrew formula: nothing resolved, so the tier is
        // skipped — `trash` is never handed to a runner by name for `PATH` to interpret.
        let run = |prog: &str, _args: &[&str], _t: Duration| -> Option<String> {
            assert_eq!(tier(prog), "osascript", "only the fallback may run: {prog}");
            assert_eq!(prog, OSASCRIPT, "…and at its fixed location, not via PATH");
            Some(String::new())
        };
        let result = move_to_trash_with(&p("/x/y"), None, run);
        if cfg!(target_os = "macos") {
            assert_eq!(result, Ok(()));
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn fails_safe_when_neither_mechanism_works() {
        // The no-trash-binary AND no-GUI-session case: both tiers fail. This is the fail-CLOSED
        // guarantee itself — callers (see clean::execute's tests) must treat this Err as "not
        // removed", never as license to fall back to fs::remove_dir_all/remove_file.
        let run = |_prog: &str, _args: &[&str], _t: Duration| -> Option<String> { None };
        assert!(move_to_trash_with(&p("/x/y"), Some(Path::new(TRASH_BIN)), run).is_err());
    }

    #[test]
    fn osascript_receives_the_path_as_an_argv_element_never_embedded_in_the_script_text() {
        // Matches digger's own `_mole_move_to_trash`. Force the trash-CLI tier to fail so the
        // AppleScript fallback is what gets probed.
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let run = |prog: &str, args: &[&str], _t: Duration| -> Option<String> {
            if tier(prog) == "osascript" {
                *seen.borrow_mut() = args.iter().map(|s| s.to_string()).collect();
                Some(String::new())
            } else {
                None
            }
        };
        let tricky = p("/tmp/burrow's \"weird\" path");
        let result = move_to_trash_with(&tricky, Some(Path::new(TRASH_BIN)), run);
        if !cfg!(target_os = "macos") {
            assert!(result.is_err());
            return;
        }
        assert_eq!(result, Ok(()));
        let args = seen.into_inner();
        assert!(!args.is_empty(), "osascript must have been invoked");
        let script_lines: Vec<&str> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(flag, _)| flag.as_str() == "-e")
            .map(|(_, line)| line.as_str())
            .collect();
        assert!(
            script_lines.iter().any(|l| l.contains("item 1 of argv")),
            "the script must read the path from argv, not a literal: {script_lines:?}"
        );
        assert!(
            script_lines.iter().all(|l| !l.contains("burrow's")),
            "the path must never be embedded in the script text itself: {script_lines:?}"
        );
        // The path rides as the trailing positional argument instead.
        assert_eq!(args.last().map(String::as_str), tricky.to_str());
    }

    #[test]
    fn non_utf8_path_is_refused_cleanly_not_guessed_at() {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let bytes = [0x66, 0x6f, 0x80, 0x6f]; // "fo\x80o" - invalid UTF-8
            let bad = PathBuf::from(OsStr::from_bytes(&bytes));
            let run = |_p: &str, _a: &[&str], _t: Duration| -> Option<String> {
                panic!("must never reach a subprocess call with an unrepresentable path")
            };
            assert!(move_to_trash_with(&bad, Some(Path::new(TRASH_BIN)), run).is_err());
        }
    }
}
