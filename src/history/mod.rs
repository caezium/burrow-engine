//! Cleanup-history reader — the engine port of digger's `history` command.
//!
//! Reads the two mole logs (`~/Library/Logs/mole/operations.log` + `deletions.log`), which the
//! clean/optimize/uninstall operations append to, and renders the same `history --json` contract
//! the GUI's History view consumes. Read-only: this parses logs, it never writes them (the write
//! side lives in the clean/optimize/uninstall execute path). The parser is a pure state machine
//! over the log lines, so it's fully tested against synthetic logs.
//!
//! operations.log grammar (per line):
//! - `# ========== <command> session started at <ts> ==========`
//! - `# ========== <command> session ended at <ts>[, <items> items, <size>] ==========`
//! - `[<ts>] [<command>] <ACTION> <rest…>`  (ACTION: REMOVED|TRASHED|SKIPPED|FAILED|REBUILT|other)
//!
//! deletions.log grammar: TSV `<ts>\t<mode>\t<size_kb>\t<status>\t<path>`.

pub mod write;

/// The default / max number of most-recent sessions (and deletions) emitted.
pub const DEFAULT_LIMIT: usize = 20;
pub const MAX_LIMIT: usize = 200;

/// One cleanup session aggregated from the operations log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub command: String,
    pub started_at: String,
    pub ended_at: String,
    pub items: u64,
    pub size: String,
    pub operation_count: u64,
    pub removed: u64,
    pub trashed: u64,
    pub skipped: u64,
    pub failed: u64,
    pub rebuilt: u64,
    pub other: u64,
}

/// One recorded deletion from the deletions log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deletion {
    pub timestamp: String,
    pub mode: String,
    /// `None` when the logged size wasn't a plain integer count of KiB.
    pub size_kb: Option<u64>,
    pub status: String,
    pub path: String,
}

/// Clamp a requested limit into `[1, MAX_LIMIT]`, defaulting when absent/zero.
pub fn normalize_limit(limit: Option<u64>) -> usize {
    match limit {
        None | Some(0) => DEFAULT_LIMIT,
        Some(n) if n as usize > MAX_LIMIT => MAX_LIMIT,
        Some(n) => n as usize,
    }
}

const START_PREFIX: &str = "# ========== ";
const HDR_SUFFIX: &str = " ==========";

/// Parse the operations log into sessions, in file order. Mirrors digger's state machine: an
/// operation or session-end line with no active session auto-starts one; a session-start while
/// one is active finalizes the current first; any active session is finalized at EOF.
pub fn parse_operations(log: &str) -> Vec<Session> {
    let mut sessions = Vec::new();
    let mut active: Option<Session> = None;

    let finish = |active: &mut Option<Session>, sessions: &mut Vec<Session>| {
        if let Some(s) = active.take() {
            sessions.push(s);
        }
    };

    for line in log.lines() {
        // Session start.
        if let Some((command, started_at)) = parse_session_header(line, "session started at") {
            finish(&mut active, &mut sessions);
            active = Some(Session {
                command,
                started_at,
                ..Session::default()
            });
            continue;
        }
        // Session end (may carry ", <items> items, <size>").
        if let Some((command, rest)) = parse_session_header(line, "session ended at") {
            let (ended_at, items, size) = split_session_end(&rest);
            let s = active.get_or_insert_with(|| Session {
                command,
                started_at: ended_at.clone(),
                ..Session::default()
            });
            s.ended_at = ended_at;
            if let Some(i) = items {
                s.items = i;
            }
            if let Some(sz) = size {
                s.size = sz;
            }
            finish(&mut active, &mut sessions);
            continue;
        }
        // Operation line: `[<ts>] [<command>] <ACTION> …`.
        if let Some((command, action)) = parse_operation_line(line) {
            let s = active.get_or_insert_with(|| Session {
                command,
                ..Session::default()
            });
            s.operation_count += 1;
            match action.as_str() {
                "REMOVED" => s.removed += 1,
                "TRASHED" => s.trashed += 1,
                "SKIPPED" => s.skipped += 1,
                "FAILED" => s.failed += 1,
                "REBUILT" => s.rebuilt += 1,
                _ => s.other += 1,
            }
        }
    }
    finish(&mut active, &mut sessions);
    sessions
}

/// Parse a `# ========== <command> <marker> <tail> ==========` header. Returns (command, tail).
fn parse_session_header(line: &str, marker: &str) -> Option<(String, String)> {
    let inner = line.strip_prefix(START_PREFIX)?.strip_suffix(HDR_SUFFIX)?;
    let needle = format!(" {marker} ");
    let idx = inner.find(&needle)?;
    let command = inner[..idx].to_string();
    let tail = inner[idx + needle.len()..].to_string();
    if command.is_empty() {
        return None;
    }
    Some((command, tail))
}

/// Split a session-end tail `<ended_at>[, <items> items, <size>]` into its parts.
fn split_session_end(rest: &str) -> (String, Option<u64>, Option<String>) {
    if let Some((ended_at, tail)) = rest.split_once(", ") {
        if let Some((items_str, size)) = tail.split_once(" items, ") {
            let items = items_str.trim().parse::<u64>().ok();
            return (ended_at.to_string(), items, Some(size.to_string()));
        }
        // A comma but not the "N items, size" shape: the whole rest is the timestamp.
    }
    (rest.to_string(), None, None)
}

/// Parse an operation line `[<ts>] [<command>] <ACTION> …` → (command, action). The action is the
/// first whitespace-delimited token after the command bracket.
fn parse_operation_line(line: &str) -> Option<(String, String)> {
    let after_ts = line.strip_prefix('[')?;
    let (_ts, rest) = after_ts.split_once("] ")?;
    let rest = rest.strip_prefix('[')?;
    let (command, rest) = rest.split_once("] ")?;
    let action = rest.split_whitespace().next()?;
    if command.is_empty() || action.is_empty() {
        return None;
    }
    Some((command.to_string(), action.to_string()))
}

/// Parse the deletions log (TSV) into deletions, in file order. Rows missing timestamp/mode/status
/// are skipped (matching digger).
pub fn parse_deletions(log: &str) -> Vec<Deletion> {
    let mut out = Vec::new();
    for line in log.lines() {
        if line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let (timestamp, mode, size_kb, status) = match (f.next(), f.next(), f.next(), f.next()) {
            (Some(t), Some(m), Some(sz), Some(st)) => (t, m, sz, st),
            _ => continue,
        };
        let path = f.next().unwrap_or("");
        if timestamp.is_empty() || mode.is_empty() || status.is_empty() {
            continue;
        }
        out.push(Deletion {
            timestamp: timestamp.to_string(),
            mode: mode.to_string(),
            size_kb: size_kb.parse::<u64>().ok(),
            status: status.to_string(),
            path: path.to_string(),
        });
    }
    out
}

use crate::json::escape as esc;

/// Render the `history --json` contract: `{logs:{operations,deletions},limit,sessions[…],
/// deletions[…]}`. Sessions and deletions are emitted NEWEST-FIRST, capped at `limit`.
pub fn to_json(
    operations_path: &str,
    deletions_path: &str,
    limit: usize,
    sessions: &[Session],
    deletions: &[Deletion],
) -> String {
    // Newest-first, most-recent `limit`.
    let sess = sessions
        .iter()
        .rev()
        .take(limit)
        .map(|s| {
            format!(
                "{{\"command\":{},\"started_at\":{},\"ended_at\":{},\"items\":{},\"size\":{},\"operation_count\":{},\"actions\":{{\"removed\":{},\"trashed\":{},\"skipped\":{},\"failed\":{},\"rebuilt\":{},\"other\":{}}}}}",
                esc(&s.command),
                esc(&s.started_at),
                esc(&s.ended_at),
                s.items,
                esc(&s.size),
                s.operation_count,
                s.removed,
                s.trashed,
                s.skipped,
                s.failed,
                s.rebuilt,
                s.other
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let dels = deletions
        .iter()
        .rev()
        .take(limit)
        .map(|d| {
            let size = d
                .size_kb
                .map(|n| n.to_string())
                .unwrap_or_else(|| "null".to_string());
            format!(
                "{{\"timestamp\":{},\"mode\":{},\"status\":{},\"size_kb\":{},\"path\":{}}}",
                esc(&d.timestamp),
                esc(&d.mode),
                esc(&d.status),
                size,
                esc(&d.path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"logs\":{{\"operations\":{},\"deletions\":{}}},\"limit\":{},\"sessions\":[{}],\"deletions\":[{}]}}",
        esc(operations_path),
        esc(deletions_path),
        limit,
        sess,
        dels
    )
}

/// Is this a value we are willing to turn into a directory?
///
/// [`log_paths`] feeds the writer, which calls `create_dir_all` on the parent of whatever it is
/// given (`write::append_line`). `create_dir_all` splits on `/`, so a multi-line value does not
/// fail — it silently produces a directory whose NAME contains a newline, plus a subtree for
/// everything after the next slash.
///
/// A captured failure interpolated `uninstall_list_apps` JSON into a log path and created
/// directories from it. For example, `mole\n  {"name": "Example App", "path": "` becomes a
/// directory name, with the application's path forming the subtree beneath it. The protection
/// corpora retain anonymized examples of these malformed paths.
///
/// A log path must therefore be non-empty, absolute, and free of control characters. Anything else
/// is a corrupted value, not a location.
fn is_plausible_log_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/') && !path.chars().any(|c| c.is_control())
}

/// Take the env override only if it is a usable path; otherwise say so and use the default.
///
/// Falling back rather than failing keeps a cleanup run from aborting over a bad env var, which is
/// digger's posture too — but the rejection goes to stderr instead of happening silently, because
/// a caller that set the variable and then finds its records in the default location deserves to
/// know why. stderr keeps the stdout JSON contract intact.
///
/// `default` is itself a `Result` because building it needs a home directory that may not exist (see
/// [`log_paths`]). That keeps the fallback honest in the one case where there is nothing to fall
/// back TO: a usable override still wins outright and never even looks at the default, and a
/// rejected override with no default available fails instead of quietly writing to `/Library/…`.
fn checked_log_path(
    var: &str,
    value: Option<String>,
    default: Result<String, String>,
) -> Result<String, String> {
    match value {
        Some(v) if is_plausible_log_path(&v) => Ok(v),
        Some(v) => {
            let reason = describe_rejection(&v);
            match &default {
                Ok(d) => eprintln!(
                    "burrow-engine: ignoring {var}: not a usable log path ({reason}); using {d}"
                ),
                Err(e) => eprintln!(
                    "burrow-engine: ignoring {var}: not a usable log path ({reason}); no default \
                     is available either ({e})"
                ),
            }
            default
        }
        None => default,
    }
}

/// A short reason a value was rejected, with any control characters rendered rather than echoed —
/// printing the raw value would put the newline straight back into the terminal.
fn describe_rejection(value: &str) -> String {
    if value.is_empty() {
        return "empty".to_string();
    }
    if value.chars().any(|c| c.is_control()) {
        let shown: String = value
            .chars()
            .take(60)
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect();
        return format!("contains control characters: {shown:?}");
    }
    "not an absolute path".to_string()
}

/// The mole log paths (env-overridable, matching digger's `MOLE_OPERATIONS_LOG`/`MOLE_DELETE_LOG`).
/// Values that could not be a path are rejected in favour of the default — see
/// [`is_plausible_log_path`] for the directories that taught us to check.
///
/// `Err` when a default is needed and the home directory is unknown. The condition is per-path and
/// not a blanket up-front check, because an override supplies a complete path on its own: with both
/// `MOLE_OPERATIONS_LOG` and `MOLE_DELETE_LOG` set this answers without ever consulting a home, and
/// only the paths that actually have to be BUILT from `~` can fail. Before this, an unknown home
/// silently produced `/Library/Logs/mole/operations.log` — a root-owned path nobody has — and
/// `history` reported that file as its source with zero sessions in it, which reads identically to a
/// fresh install that has simply never cleaned anything.
pub fn log_paths() -> Result<(String, String), String> {
    // The REASON travels: a root home (`platform::ROOT_HOMES`) is refused with the message that
    // names `BURROW_HOME`, not collapsed into the generic no-home one.
    let home = crate::platform::home_dir_or_error();
    log_paths_resolving(home.as_deref().map_err(String::clone))
}

/// [`log_paths`] with the home directory supplied rather than read from the environment.
///
/// `uninstall` is the caller: it already takes `home` as a parameter (its leftover enumeration is
/// relative to one), and a run that enumerates `~/Library` under one home while writing its audit
/// record under another is describing two different machines. It is also the only way a test can
/// exercise the log at all — `$HOME` is a process-global and `set_var` races every other test in the
/// binary, which is the same reason `uninstall_resolved` takes `home` in the first place.
///
/// The `MOLE_*` overrides still win, exactly as in [`log_paths`] and in bash (`file_ops.sh:782`
/// reads `MOLE_DELETE_LOG` before falling back to `$HOME/Library/Logs/mole/deletions.log`).
pub fn log_paths_under(home: Option<&str>) -> Result<(String, String), String> {
    log_paths_resolving(home.ok_or_else(|| crate::platform::NO_HOME.to_string()))
}

/// The shared body of [`log_paths`] and [`log_paths_under`]: `home` is either the directory or
/// the reason there is none, surfaced only when a default path actually has to be built from it.
fn log_paths_resolving(home: Result<&str, String>) -> Result<(String, String), String> {
    let default_for = |leaf: &str| -> Result<String, String> {
        home.as_deref()
            .map_err(String::clone)
            .and_then(|h| default_log_path(h, leaf))
    };
    let ops = checked_log_path(
        "MOLE_OPERATIONS_LOG",
        std::env::var("MOLE_OPERATIONS_LOG")
            .or_else(|_| std::env::var("OPERATIONS_LOG_FILE"))
            .ok(),
        default_for("operations.log"),
    )?;
    let del = checked_log_path(
        "MOLE_DELETE_LOG",
        std::env::var("MOLE_DELETE_LOG").ok(),
        default_for("deletions.log"),
    )?;
    Ok((ops, del))
}

fn default_log_path(home: &str, leaf: &str) -> Result<String, String> {
    // An invalid home must not become a root-level or relative audit destination. Check this
    // only for defaults so a complete, validated override can still work without a home.
    if !std::path::Path::new(home).is_absolute() || home.chars().any(char::is_control) {
        return Err(crate::platform::NO_HOME.to_string());
    }
    Ok(format!("{home}/Library/Logs/mole/{leaf}"))
}

/// Read both logs and render the history JSON for the most-recent `limit` sessions/deletions.
/// Missing log files read as empty (a fresh install with no cleanup activity yet) — but a home
/// directory that could not be resolved is an `Err`, not an empty read: the two are the same bytes
/// on the wire and completely different facts.
pub fn collect(limit: Option<u64>) -> Result<String, String> {
    let limit = normalize_limit(limit);
    let (ops_path, del_path) = log_paths()?;
    let ops = std::fs::read_to_string(&ops_path).unwrap_or_default();
    let del = std::fs::read_to_string(&del_path).unwrap_or_default();
    let sessions = parse_operations(&ops);
    let deletions = parse_deletions(&del);
    Ok(to_json(&ops_path, &del_path, limit, &sessions, &deletions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_logs_refuse_invalid_homes_before_constructing_paths() {
        for home in [
            "",
            " ",
            "relative/home",
            "/Users/example\nother",
            "/Users/example\0",
        ] {
            assert_eq!(
                default_log_path(home, "operations.log"),
                Err(crate::platform::NO_HOME.to_string()),
                "invalid home: {home:?}"
            );
        }
        let home = std::env::temp_dir().join("fixture home ");
        let home = home.to_str().unwrap();
        assert_eq!(
            default_log_path(home, "operations.log").unwrap(),
            format!("{home}/Library/Logs/mole/operations.log")
        );
    }

    #[test]
    fn normalize_limit_clamps() {
        assert_eq!(normalize_limit(None), DEFAULT_LIMIT);
        assert_eq!(normalize_limit(Some(0)), DEFAULT_LIMIT);
        assert_eq!(normalize_limit(Some(5)), 5);
        assert_eq!(normalize_limit(Some(9999)), MAX_LIMIT);
    }

    #[test]
    fn parses_a_full_session() {
        let log = "\
# ========== clean session started at 2026-07-14 10:00:00 ==========
[2026-07-14 10:00:01] [clean] REMOVED /a/x
[2026-07-14 10:00:02] [clean] TRASHED /a/y
[2026-07-14 10:00:03] [clean] SKIPPED /a/z
# ========== clean session ended at 2026-07-14 10:00:05, 3 items, 2.93GB ==========";
        let s = parse_operations(log);
        assert_eq!(s.len(), 1);
        let s = &s[0];
        assert_eq!(s.command, "clean");
        assert_eq!(s.started_at, "2026-07-14 10:00:00");
        assert_eq!(s.ended_at, "2026-07-14 10:00:05");
        assert_eq!(s.items, 3);
        assert_eq!(s.size, "2.93GB");
        assert_eq!(s.operation_count, 3);
        assert_eq!((s.removed, s.trashed, s.skipped), (1, 1, 1));
    }

    #[test]
    fn session_end_without_items_tail() {
        let log = "\
# ========== optimize session started at T1 ==========
[T1] [optimize] REBUILT dyld
# ========== optimize session ended at T2 ==========";
        let s = parse_operations(log);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ended_at, "T2");
        assert_eq!(s[0].items, 0);
        assert_eq!(s[0].size, "");
        assert_eq!(s[0].rebuilt, 1);
    }

    #[test]
    fn operation_without_start_auto_opens_a_session() {
        // A stray operation line with no preceding start still forms a session (digger behavior).
        let log = "[T] [clean] REMOVED /f";
        let s = parse_operations(log);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].command, "clean");
        assert_eq!(s[0].removed, 1);
        assert_eq!(s[0].ended_at, "", "never finished");
    }

    #[test]
    fn a_new_start_finalizes_the_previous_session() {
        let log = "\
# ========== clean session started at A ==========
[A] [clean] REMOVED /1
# ========== optimize session started at B ==========
[B] [optimize] REBUILT /2";
        let s = parse_operations(log);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].command, "clean");
        assert_eq!(s[0].removed, 1);
        assert_eq!(s[1].command, "optimize");
        assert_eq!(s[1].rebuilt, 1);
    }

    #[test]
    fn unknown_action_falls_into_other() {
        let log = "[T] [clean] FROBNICATED /f";
        let s = parse_operations(log);
        assert_eq!(s[0].other, 1);
        assert_eq!(s[0].operation_count, 1);
    }

    #[test]
    fn parses_deletions_tsv() {
        let log = "2026-07-14 10:00:01\ttrash\t512\tok\t/a/b c.txt\n\
                   2026-07-14 10:00:02\tdelete\tunknown\tfailed\t/x/y";
        let d = parse_deletions(log);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].mode, "trash");
        assert_eq!(d[0].size_kb, Some(512));
        assert_eq!(d[0].path, "/a/b c.txt", "path keeps spaces");
        assert_eq!(d[1].size_kb, None, "non-numeric size -> None");
        assert_eq!(d[1].status, "failed");
    }

    #[test]
    fn deletions_skip_malformed_rows() {
        // Fewer than 4 fields, or empty required fields, are dropped.
        let log = "only\ttwo\n\t\t\t\t/p\nT\tmode\t10\tok\t/good";
        let d = parse_deletions(log);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, "/good");
    }

    #[test]
    fn json_is_newest_first_and_limited() {
        let sessions = vec![
            Session {
                command: "clean".into(),
                started_at: "A".into(),
                ..Session::default()
            },
            Session {
                command: "optimize".into(),
                started_at: "B".into(),
                ..Session::default()
            },
            Session {
                command: "uninstall".into(),
                started_at: "C".into(),
                ..Session::default()
            },
        ];
        let json = to_json("/ops", "/del", 2, &sessions, &[]);
        // Newest first (C then B), capped at 2 (A dropped).
        let c = json.find("uninstall").unwrap();
        let b = json.find("optimize").unwrap();
        assert!(c < b, "newest (uninstall) before optimize");
        assert!(!json.contains("clean"), "limit 2 drops the oldest");
        assert!(json.contains("\"logs\":{\"operations\":\"/ops\",\"deletions\":\"/del\"}"));
        assert!(json.contains("\"limit\":2"));
    }

    #[test]
    fn json_deletion_null_size() {
        let dels = vec![Deletion {
            timestamp: "T".into(),
            mode: "trash".into(),
            size_kb: None,
            status: "ok".into(),
            path: "/p".into(),
        }];
        let json = to_json("/ops", "/del", 20, &[], &dels);
        assert!(json.contains("\"size_kb\":null"), "got: {json}");
    }

    #[test]
    fn json_matches_app_session_contract() {
        let sessions = vec![Session {
            command: "clean".into(),
            started_at: "S".into(),
            ended_at: "E".into(),
            items: 7,
            size: "1.2GB".into(),
            operation_count: 7,
            removed: 5,
            trashed: 2,
            ..Session::default()
        }];
        let json = to_json("/o", "/d", 20, &sessions, &[]);
        // Fields the GUI's MoleHistory decoder depends on.
        for needle in [
            "\"command\":\"clean\"",
            "\"started_at\":\"S\"",
            "\"ended_at\":\"E\"",
            "\"items\":7",
            "\"size\":\"1.2GB\"",
            "\"actions\":{\"removed\":5,\"trashed\":2,\"skipped\":0,\"failed\":0",
        ] {
            assert!(json.contains(needle), "missing {needle} in {json}");
        }
    }

    /// An anonymized malformed log path from the captured failure. Its newline and embedded
    /// JSON must be rejected before `create_dir_all` can split it into directories.
    const SANITIZED_CORRUPT_VALUE: &str = concat!(
        "/Users/alice/Library/Logs/mole\n",
        "  {\"name\": \"Example App\", \"bundle_id\": \"org.example.fixture.app\", \"source\": \"App\",",
        " \"uninstall_name\": \"Example App\", \"path\": \"/Applications/Example App.app\", \"size\": \"50MB\"}",
        "/operations.log"
    );

    #[test]
    fn sanitized_captured_corrupt_log_path_is_rejected() {
        assert!(
            !is_plausible_log_path(SANITIZED_CORRUPT_VALUE),
            "a multi-line value must never reach create_dir_all"
        );
        let default = "/Users/x/Library/Logs/mole/operations.log".to_string();
        assert_eq!(
            checked_log_path(
                "MOLE_OPERATIONS_LOG",
                Some(SANITIZED_CORRUPT_VALUE.to_string()),
                Ok(default.clone())
            ),
            Ok(default),
            "a rejected override falls back to the default path"
        );
        // And when there is no default to fall back to — no home directory — the rejection is
        // propagated instead of being resolved into a path built from an empty home.
        assert!(
            checked_log_path(
                "MOLE_OPERATIONS_LOG",
                Some(SANITIZED_CORRUPT_VALUE.to_string()),
                Err(crate::platform::NO_HOME.to_string())
            )
            .is_err(),
            "with no home there is nothing to fall back to, so this must fail"
        );
    }

    #[test]
    fn implausible_log_paths_are_rejected_and_ordinary_ones_are_not() {
        // Rejected: anything that cannot be a path.
        for bad in [
            "",                            // empty
            "relative/operations.log",     // not absolute
            "/tmp/a\nb/operations.log",    // newline
            "/tmp/a\tb/operations.log",    // tab
            "/tmp/a\rb/operations.log",    // carriage return
            "/tmp/a\u{0}b/operations.log", // NUL
        ] {
            assert!(
                !is_plausible_log_path(bad),
                "{bad:?} should be rejected as a log path"
            );
        }
        // Accepted: real paths, including the awkward-but-legal ones.
        for good in [
            "/Users/x/Library/Logs/mole/operations.log",
            "/tmp/burrow test/operations.log", // spaces are fine
            "/tmp/ünïcode/operations.log",     // non-ASCII is fine
            "/tmp/quote\"dir/operations.log",  // a quote is legal in a filename
        ] {
            assert!(
                is_plausible_log_path(good),
                "{good:?} is a legitimate path and must be honoured"
            );
        }
    }

    /// A good override is used as-is — the validation must not quietly disable the env var.
    #[test]
    fn a_valid_override_is_still_honoured() {
        let chosen = "/tmp/burrow-history/operations.log".to_string();
        assert_eq!(
            checked_log_path(
                "MOLE_OPERATIONS_LOG",
                Some(chosen.clone()),
                Ok("/def".into())
            ),
            Ok(chosen.clone())
        );
        assert_eq!(
            checked_log_path("MOLE_OPERATIONS_LOG", None, Ok("/def".into())),
            Ok("/def".to_string())
        );
        // A usable override answers even with no default available: `log_paths` must not demand a
        // home directory it does not need.
        assert_eq!(
            checked_log_path(
                "MOLE_OPERATIONS_LOG",
                Some(chosen.clone()),
                Err(crate::platform::NO_HOME.to_string())
            ),
            Ok(chosen)
        );
    }

    /// The rejection message must not echo the raw value: printing a newline-bearing value puts
    /// the newline straight back into the caller's terminal (and into any log that captures it).
    #[test]
    fn the_rejection_message_never_replays_the_control_characters() {
        let msg = describe_rejection(SANITIZED_CORRUPT_VALUE);
        assert!(!msg.contains('\n'), "message must be single-line: {msg}");
        assert!(msg.contains("control characters"), "{msg}");
    }
}
