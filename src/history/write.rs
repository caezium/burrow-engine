//! Cleanup-log writer — the append side of the mole history logs.
//!
//! The clean/optimize/uninstall commands record what they did to the same two logs the
//! [`super`] reader parses: `operations.log` (session markers + `[ts] [cmd] ACTION path` lines)
//! and `deletions.log` (TSV audit trail). Digger writes these; the engine must too, or the GUI
//! History view goes blank once the app runs the engine instead of digger.
//!
//! The reader DISCARDS per-operation timestamps (op lines only feed action counts), so only the
//! session start/end markers and the deletion-record timestamps are ever surfaced — this writer
//! captures one wall-clock stamp per session and reuses it. The core is pure (paths + timestamps
//! injected) so it's tested by round-tripping through the reader; [`SessionLog::start_under`] is
//! the thin convenience layer that resolves the log paths and shells `date` for the local timestamp.

use std::io::Write;

/// Append a single line (plus newline) to `path`, creating the parent dir if needed. Best-effort:
/// log-write failures never abort a cleanup (matching digger's `|| true`).
fn append_line(path: &str, line: &str) {
    // The empty path is [`SessionLog::start_under`]'s "log paths could not be resolved" state, already
    // announced on stderr there. Returning here keeps it from being handed to `create_dir_all("")`
    // and `OpenOptions::open("")`, which fail anyway but do so once per line.
    if path.is_empty() {
        return;
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Local wall-clock stamp in digger's operations-log format (`%Y-%m-%d %H:%M:%S`), via `date` so
/// the timezone matches digger exactly. Falls back to a fixed marker if `date` is unavailable.
pub fn local_timestamp() -> String {
    local_timestamp_via(&crate::platform::run_command)
}

/// Local wall-clock stamp in digger's deletions-log ISO format (`%Y-%m-%dT%H:%M:%S%z`).
pub fn local_timestamp_iso() -> String {
    local_timestamp_iso_via(&crate::platform::run_command)
}

/// [`local_timestamp`] through an injected runner.
pub fn local_timestamp_via(run: crate::platform::Runner<'_>) -> String {
    run_date(run, "+%Y-%m-%d %H:%M:%S").unwrap_or_else(|| "unknown".to_string())
}

/// [`local_timestamp_iso`] through an injected runner.
pub fn local_timestamp_iso_via(run: crate::platform::Runner<'_>) -> String {
    run_date(run, "+%Y-%m-%dT%H:%M:%S%z").unwrap_or_else(|| "unknown".to_string())
}

/// `date <fmt>` through `run`, trimmed; `None` when it fails or prints nothing.
fn run_date(run: crate::platform::Runner<'_>, fmt: &str) -> Option<String> {
    let s = run("date", &[fmt])?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// An open cleanup session that appends to the two logs. Construct with
/// [`SessionLog::start_under`] (resolves the log paths + wall-clock) or [`SessionLog::open_at`]
/// (everything injected, for tests).
pub struct SessionLog {
    command: String,
    ops_path: String,
    del_path: String,
    /// Reused for the deletion-record timestamps (all near-simultaneous within a session).
    iso_ts: String,
}

impl SessionLog {
    /// Open a session AT the given log paths, stamped with the given timestamps (pure — no env,
    /// no clock). Writes the blank-line + `session started at <op_ts>` marker to the operations
    /// log.
    pub fn open_at(
        command: &str,
        ops_path: &str,
        del_path: &str,
        op_ts: &str,
        iso_ts: &str,
    ) -> Self {
        append_line(ops_path, "");
        append_line(
            ops_path,
            &format!("# ========== {command} session started at {op_ts} =========="),
        );
        SessionLog {
            command: command.to_string(),
            ops_path: ops_path.to_string(),
            del_path: del_path.to_string(),
            iso_ts: iso_ts.to_string(),
        }
    }

    /// Open a session against the resolved log paths, stamping with the local wall clock. The home
    /// directory is supplied rather than read from the environment — see [`super::log_paths_under`]
    /// for why — so a command that enumerates under one home never records under another.
    ///
    /// Unresolvable log paths (no home directory and no complete env override — see
    /// [`super::log_paths`]) are reported on stderr and the session writes nowhere. Not a silent
    /// no-op, and not a panic either: a destructive command's outcome report matters more than its
    /// audit line. In practice this is unreachable — `clean`, `purge`, `installer` and `uninstall`
    /// all refuse before deleting anything when the home is unknown (`cli.rs`'s `home_or_refuse`) —
    /// so this arm exists to make the impossible case loud rather than to be taken; `optimize`,
    /// which needs no home, is the one caller that can reach it.
    pub fn start_under(command: &str, home: Option<&str>) -> Self {
        Self::start_under_with(command, home, &crate::platform::run_command)
    }

    /// [`SessionLog::start_under`] with the `date` runner injected, so the stamps a session opens
    /// with are pinned by a fake clock.
    pub fn start_under_with(
        command: &str,
        home: Option<&str>,
        run: crate::platform::Runner<'_>,
    ) -> Self {
        match super::log_paths_under(home) {
            Ok((ops_path, del_path)) => Self::open_at(
                command,
                &ops_path,
                &del_path,
                &local_timestamp_via(run),
                &local_timestamp_iso_via(run),
            ),
            Err(e) => {
                eprintln!(
                    "burrow-engine: {command} ran but was not recorded to the mole history log: {e}"
                );
                SessionLog {
                    command: command.to_string(),
                    ops_path: String::new(),
                    del_path: String::new(),
                    iso_ts: local_timestamp_iso_via(run),
                }
            }
        }
    }

    /// Append an operation line `[<ts>] [<command>] <ACTION> <path>[ (<detail>)]`. The `ts` is
    /// discarded by the reader, so the session's start stamp is reused.
    pub fn operation(&self, action: &str, path: &str, detail: &str) {
        let mut line = format!("[{}] [{}] {action} {path}", self.iso_ts, self.command);
        if !detail.is_empty() {
            line.push_str(&format!(" ({detail})"));
        }
        append_line(&self.ops_path, &line);
    }

    /// Append a deletion audit record `<iso_ts>\t<mode>\t<size_kb>\t<status>\t<path>`.
    pub fn deletion(&self, mode: &str, size_kb: u64, status: &str, path: &str) {
        append_line(
            &self.del_path,
            &format!("{}\t{mode}\t{size_kb}\t{status}\t{path}", self.iso_ts),
        );
    }

    /// Close the session: `session ended at <ts>, <items> items, <size_human>` where size_human
    /// is `bytes_to_human(size_kb * 1024)` (matching digger). Stamps with a fresh wall clock via
    /// the injected `end_ts`.
    pub fn end_with(&self, items: u64, size_kb: u64, end_ts: &str) {
        let size_human = crate::clean::format::bytes_to_human(size_kb.saturating_mul(1024));
        append_line(
            &self.ops_path,
            &format!(
                "# ========== {} session ended at {end_ts}, {items} items, {size_human} ==========",
                self.command
            ),
        );
    }

    /// Close the session, stamping with the local wall clock.
    pub fn end(&self, items: u64, size_kb: u64) {
        self.end_with(items, size_kb, &local_timestamp());
    }
}

/// Record a finished clean to the mole history logs (so the History view has data), matching
/// digger's format: a `REMOVED` op per item, a `FAILED` op per error, and a deletion audit record
/// per item — but ONLY for the items this run actually deleted.
///
/// The `deletions.log` record is the recoverability trail: the GUI's History view and
/// `burrow_deleted_files` read it, and a `trash` row is a promise that the bytes are sitting in a
/// Trash the user can open and Put Back from. So it is written exactly when
/// [`RemovedItem::is_auditable_deletion`] holds. Two kinds of item are deliberately excluded
/// (RULEBOOK §3m):
///
/// - **A tool cleaned its own cache.** `uv cache prune` and `go clean -cache` unlink permanently;
///   recording those as `trash … ok` tells the user bytes are recoverable that are gone forever,
///   on the DEFAULT path. The oracle records nothing at all for them — `clean_tool_cache`
///   (`dev.sh:10-42`) writes to neither log and adds to none of `bin/clean.sh`'s accounting.
/// - **A path an earlier candidate in this same run already took.** Nothing was deleted at that
///   step, so a record with a byte count would be a deletion that never happened; the oracle's
///   `safe_remove` returns early at `file_ops.sh:231-233` for a missing path, before it logs.
///
/// Both still get their `REMOVED` operations line — the action DID happen and the History view's
/// action counts should see it — with a detail that states why no size is attached instead of a
/// size that would be made up.
pub fn log_clean_session(
    log: &SessionLog,
    mode: crate::clean::execute::RemovalMode,
    outcome: &crate::clean::execute::CleanOutcome,
) {
    log_clean_items(log, mode, outcome);
    // The session's size column is every byte verified leaving its path, whichever way it went —
    // the per-item audit record's `mode` is what says whether it is recoverable.
    log.end(
        outcome.removed.len() as u64,
        outcome.accounted_bytes() / 1024,
    );
}

/// The per-item half of [`log_clean_session`], without the session end marker — so `uninstall`,
/// which runs one `execute_clean` per resolved app and interleaves the bundle's own records between
/// them, writes the same lines for the same items and closes the session once at the end.
pub fn log_clean_items(
    log: &SessionLog,
    mode: crate::clean::execute::RemovalMode,
    outcome: &crate::clean::execute::CleanOutcome,
) {
    use crate::clean::execute::Freed;
    for c in &outcome.removed {
        let detail = match c.freed {
            Freed::Bytes(n) => crate::clean::format::bytes_to_human(n),
            Freed::Delegated => "cleaned by the tool itself, bytes not measured".to_string(),
            Freed::AlreadyGone => "already removed earlier in this run".to_string(),
            Freed::Unverified => "removal reported but the path is still present".to_string(),
        };
        log.operation("REMOVED", &c.path, &detail);
        if c.is_auditable_deletion() {
            log.deletion(mode.word(), c.bytes() / 1024, "ok", &c.path);
        }
    }
    for e in &outcome.errors {
        log.operation("FAILED", &e.path, &e.error);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse_deletions, parse_operations};
    use super::*;

    fn tmp() -> (String, String, String) {
        let dir = std::env::temp_dir().join(format!(
            "burrow_histwrite_{}_{}",
            std::process::id(),
            // vary by a monotonic-ish salt so parallel tests don't collide
            std::thread::current().name().unwrap_or("t").len()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let ops = dir.join("operations.log").to_string_lossy().into_owned();
        let del = dir.join("deletions.log").to_string_lossy().into_owned();
        (dir.to_string_lossy().into_owned(), ops, del)
    }

    #[test]
    fn write_then_read_round_trips_a_session() {
        let (dir, ops, del) = tmp();
        let _ = std::fs::remove_file(&ops);
        let _ = std::fs::remove_file(&del);
        let log = SessionLog::open_at(
            "clean",
            &ops,
            &del,
            "2026-07-14 10:00:00",
            "2026-07-14T10:00:00+0000",
        );
        log.operation("REMOVED", "/a/x", "15.2MB");
        log.operation("FAILED", "/a/y", "permission denied");
        log.deletion("permanent", 512, "ok", "/a/x");
        log.end_with(1, 512, "2026-07-14 10:00:05");

        let ops_txt = std::fs::read_to_string(&ops).unwrap();
        let sessions = parse_operations(&ops_txt);
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.command, "clean");
        assert_eq!(s.started_at, "2026-07-14 10:00:00");
        assert_eq!(s.ended_at, "2026-07-14 10:00:05");
        assert_eq!(s.items, 1);
        assert_eq!(
            s.size, "524KB",
            "512 KiB -> bytes_to_human(512*1024=524288), SI/1000"
        );
        assert_eq!(s.removed, 1);
        assert_eq!(s.failed, 1);
        assert_eq!(s.operation_count, 2);

        let del_txt = std::fs::read_to_string(&del).unwrap();
        let dels = parse_deletions(&del_txt);
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0].mode, "permanent");
        assert_eq!(dels[0].size_kb, Some(512));
        assert_eq!(dels[0].path, "/a/x");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn operation_detail_is_parenthesized_and_optional() {
        let (dir, ops, del) = tmp();
        let ops = format!("{ops}.detail");
        let _ = std::fs::remove_file(&ops);
        let log = SessionLog::open_at("optimize", &ops, &del, "T", "I");
        log.operation("REBUILT", "dyld-cache", "");
        let txt = std::fs::read_to_string(&ops).unwrap();
        // No detail -> no trailing "(...)"; still parses as one REBUILT op.
        assert!(
            txt.contains("[optimize] REBUILT dyld-cache\n"),
            "got: {txt}"
        );
        assert!(
            !txt.contains("REBUILT dyld-cache ("),
            "no empty detail parens"
        );
        assert_eq!(parse_operations(&txt)[0].rebuilt, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_accumulates_across_sessions() {
        let (dir, ops, del) = tmp();
        let ops = format!("{ops}.multi");
        let _ = std::fs::remove_file(&ops);
        SessionLog::open_at("clean", &ops, &del, "A", "A").end_with(0, 0, "A2");
        SessionLog::open_at("optimize", &ops, &del, "B", "B").end_with(0, 0, "B2");
        let txt = std::fs::read_to_string(&ops).unwrap();
        let sessions = parse_operations(&txt);
        assert_eq!(
            sessions.len(),
            2,
            "second session appended, not overwritten"
        );
        assert_eq!(sessions[0].command, "clean");
        assert_eq!(sessions[1].command, "optimize");
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// The wall clock through a fake `date`: the two formats digger uses, in the argv digger
    /// uses, land on the session marker and the deletion record; a `date` that fails stamps
    /// `unknown` rather than aborting the log.
    #[test]
    fn session_stamps_come_from_the_injected_date_runner() {
        let home = std::env::temp_dir().join(format!("burrow_hist_date_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let clock = |p: &str, a: &[&str]| -> Option<String> {
            calls.borrow_mut().push(format!("{p} {}", a.join(" ")));
            match a[0] {
                "+%Y-%m-%d %H:%M:%S" => Some("2026-01-02 03:04:05\n".into()),
                "+%Y-%m-%dT%H:%M:%S%z" => Some("2026-01-02T03:04:05+0000\n".into()),
                _ => None,
            }
        };
        let log = SessionLog::start_under_with("clean", Some(home.to_str().unwrap()), &clock);
        log.deletion("trash", 4, "ok", "/x");
        assert_eq!(
            calls.borrow().as_slice(),
            ["date +%Y-%m-%d %H:%M:%S", "date +%Y-%m-%dT%H:%M:%S%z"]
        );
        let ops = std::fs::read_to_string(home.join("Library/Logs/mole/operations.log")).unwrap();
        assert!(
            ops.contains("# ========== clean session started at 2026-01-02 03:04:05 =========="),
            "{ops}"
        );
        let del = std::fs::read_to_string(home.join("Library/Logs/mole/deletions.log")).unwrap();
        assert!(
            del.starts_with("2026-01-02T03:04:05+0000\ttrash\t4\tok\t/x"),
            "{del}"
        );

        let broken = |_: &str, _: &[&str]| -> Option<String> { None };
        assert_eq!(local_timestamp_via(&broken), "unknown");
        assert_eq!(local_timestamp_iso_via(&broken), "unknown");
        let _ = std::fs::remove_dir_all(&home);
    }
}
