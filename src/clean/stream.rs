//! NDJSON streaming serialization for `clean --stream` / `purge --stream` (and the shape
//! `optimize --stream` mirrors).
//!
//! A streamed run can't be wrapped in one buffered envelope, so it emits one JSON object per line
//! (NDJSON): a live event as each item is processed, then a terminal `done` line carrying the
//! totals. A GUI reads the pipe line-by-line to render progress. The serializers are pure so the
//! contract is unit-tested; the cli layer only adds the stdout write + per-line flush.
//!
//! The event vocabulary is ONE vocabulary, pinned by RULEBOOK §"The NDJSON streaming contract" and
//! read by the app's `BurrowStreamReport.swift`: preview → `would_remove` … `done{dry_run:true,
//! would_free_bytes,would_free_human,count}`; live → `removed`/`failed`/`protected` …
//! `done{freed_bytes,freed_human,moved_to_trash_bytes,moved_to_trash_human,removed,failed,
//! protected}`. `purge --stream` emits exactly these lines over its artifacts through the
//! `*_line` forms below, so a reader written for `clean` needs no second `case` arm.

#[cfg(test)]
use crate::clean::execute::RemovalError;
use crate::clean::execute::{CleanEvent, CleanOutcome};
use crate::clean::plan::CleanCandidate;

use crate::json::escape as esc;

/// One NDJSON line for a live clean event.
pub fn event_ndjson(event: &CleanEvent) -> String {
    match event {
        CleanEvent::Removed { path, size } => {
            format!(
                "{{\"event\":\"removed\",\"path\":{},\"bytes\":{size}}}",
                esc(path)
            )
        }
        CleanEvent::Failed { path, error } => format!(
            "{{\"event\":\"failed\",\"path\":{},\"error\":{}}}",
            esc(path),
            esc(error)
        ),
        CleanEvent::Protected { path } => {
            format!("{{\"event\":\"protected\",\"path\":{}}}", esc(path))
        }
        CleanEvent::Refused { path, reason } => format!(
            "{{\"event\":\"protected\",\"path\":{},\"reason\":{}}}",
            esc(path),
            esc(reason)
        ),
    }
}

/// One NDJSON line for a candidate in a DRY-RUN stream (nothing is removed). The GUI streams
/// previews too, so `clean --stream` without `--apply` emits these instead of live `removed` lines.
pub fn would_remove_ndjson(candidate: &CleanCandidate) -> String {
    would_remove_line(&candidate.path, candidate.size)
}

/// [`would_remove_ndjson`] over a bare path + size — the form `purge --stream` uses for an
/// artifact, so both commands' preview lines come from one serializer.
pub fn would_remove_line(path: &str, bytes: u64) -> String {
    format!(
        "{{\"event\":\"would_remove\",\"path\":{},\"bytes\":{bytes}}}",
        esc(path)
    )
}

/// [`preview_done_ndjson`] over already-totalled numbers — `purge --stream`'s dry-run terminal
/// line, whose candidates carry no identity to dedupe by (an artifact directory is one path).
pub fn preview_done_line(would_free_bytes: u64, count: usize) -> String {
    format!(
        "{{\"event\":\"done\",\"dry_run\":true,\"would_free_bytes\":{},\"would_free_human\":{},\"count\":{}}}",
        would_free_bytes,
        esc(&crate::clean::format::bytes_to_human(would_free_bytes)),
        count
    )
}

/// The terminal NDJSON line for a finished DRY-RUN stream.
///
/// Totals the candidates AFTER `dedupe_by_identity`, for the same reason
/// [`crate::clean::plan::plan_to_json`] does: `would_free_bytes` is the headline number a GUI shows,
/// and a set of bytes reachable through two targets is still freed once. Without this the streamed
/// total and the buffered `clean` total disagree on the same machine, which is worse than either
/// being wrong on its own.
///
/// THE CALLER MUST STREAM THE SAME LIST IT PASSES HERE. `count` is what a GUI reconciles its
/// `would_remove` lines against, so if the caller loops a wider list than it hands this function,
/// the two halves of one stream contradict each other — one GUI tallying lines and another reading
/// `done.count` get different answers from the same pipe. `src/cli.rs` satisfies this by deduping
/// the merged candidate list once, up front, before both the loop and this call; the dedup is not
/// repeated per consumer for exactly that reason. It stays here as well because it is idempotent
/// and because a wrong `would_free_bytes` is the more expensive of the two failures.
pub fn preview_done_ndjson(candidates: &[CleanCandidate]) -> String {
    let candidates = crate::clean::plan::dedupe_by_identity(candidates.to_vec());
    let total: u64 = candidates.iter().map(|c| c.size).sum();
    preview_done_line(total, candidates.len())
}

/// The terminal NDJSON line summarizing a finished run. `moved_to_trash_bytes`/`_human` are
/// additive beside `freed_bytes`: on the default path the latter is 0 and the verified bytes are
/// reported as moved, because a Trash move frees no space (see `CleanOutcome`).
pub fn done_ndjson(outcome: &CleanOutcome) -> String {
    format!(
        "{{\"event\":\"done\",\"freed_bytes\":{},\"freed_human\":{},\"moved_to_trash_bytes\":{},\"moved_to_trash_human\":{},\"removed\":{},\"failed\":{},\"protected\":{}}}",
        outcome.freed_bytes,
        esc(&crate::clean::format::bytes_to_human(outcome.freed_bytes)),
        outcome.moved_to_trash_bytes,
        esc(&crate::clean::format::bytes_to_human(
            outcome.moved_to_trash_bytes
        )),
        outcome.removed.len(),
        outcome.errors.len(),
        outcome.protected.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    // event_lines used to be `assert_eq!(event_ndjson(...), "<hand-typed JSON literal>")` — a
    // full-string compare that can only confirm the serializer matches the string the same
    // person who wrote the serializer also typed (check_tests.py's RULEBOOK §6 rule). This NDJSON
    // wire format has no reference capture to load — judge.py's fixtures are all request/response
    // envelopes, not a streamed line feed — the contract is instead pinned by the real Swift
    // consumer (`BurrowStreamReport.swift`, RULEBOOK §5). So instead of a blob compare, this
    // parses the output with the engine's own JSON reader and asserts individual fields —
    // round-tripping through a real parser catches a malformed-JSON regression (trailing comma,
    // bad escape) that a substring `.contains()` check would miss, without pinning key order or
    // spacing.
    #[test]
    fn event_lines() {
        let removed = event_ndjson(&CleanEvent::Removed {
            path: "/a b",
            size: 42,
        });
        let parsed = Json::parse(&removed).expect("must be valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("removed"));
        assert_eq!(parsed.get("path").and_then(Json::as_str), Some("/a b"));
        assert_eq!(parsed.get("bytes").and_then(Json::as_u64), Some(42));

        let failed = event_ndjson(&CleanEvent::Failed {
            path: "/x",
            error: "denied",
        });
        let parsed = Json::parse(&failed).expect("must be valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("failed"));
        assert_eq!(parsed.get("path").and_then(Json::as_str), Some("/x"));
        assert_eq!(parsed.get("error").and_then(Json::as_str), Some("denied"));

        let protected = event_ndjson(&CleanEvent::Protected { path: "/keep" });
        let parsed = Json::parse(&protected).expect("must be valid JSON");
        assert_eq!(
            parsed.get("event").and_then(Json::as_str),
            Some("protected")
        );
        assert_eq!(parsed.get("path").and_then(Json::as_str), Some("/keep"));

        // A plan-file refusal is the same `protected` event with one additive field.
        let refused = event_ndjson(&CleanEvent::Refused {
            path: "/elsewhere",
            reason: "not_a_clean_target",
        });
        let parsed = Json::parse(&refused).expect("must be valid JSON");
        assert_eq!(
            parsed.get("event").and_then(Json::as_str),
            Some("protected")
        );
        assert_eq!(
            parsed.get("path").and_then(Json::as_str),
            Some("/elsewhere")
        );
        assert_eq!(
            parsed.get("reason").and_then(Json::as_str),
            Some("not_a_clean_target")
        );
    }

    #[test]
    fn event_lines_escape_specials() {
        let line = event_ndjson(&CleanEvent::Removed {
            path: "/a\"b\tc",
            size: 1,
        });
        assert!(line.contains("\\\""), "{line}");
        assert!(line.contains("\\t"), "{line}");
        // Each line is a single line (no raw newline breaks the NDJSON framing).
        assert!(!line.contains('\n'));
    }

    #[test]
    fn preview_stream_lines() {
        let c = CleanCandidate {
            path: "/c".into(),
            label: "t".into(),
            size: 500,
        };
        let would_remove = would_remove_ndjson(&c);
        let parsed = Json::parse(&would_remove).expect("must be valid JSON");
        assert_eq!(
            parsed.get("event").and_then(Json::as_str),
            Some("would_remove")
        );
        assert_eq!(parsed.get("path").and_then(Json::as_str), Some("/c"));
        assert_eq!(parsed.get("bytes").and_then(Json::as_u64), Some(500));

        let d = CleanCandidate {
            path: "/d".into(),
            label: "t".into(),
            size: 500,
        };
        let done = preview_done_ndjson(&[c, d]);
        let parsed = Json::parse(&done).expect("must be valid JSON");
        assert_eq!(parsed.get("dry_run").and_then(Json::as_bool), Some(true));
        assert_eq!(
            parsed.get("would_free_bytes").and_then(Json::as_u64),
            Some(1000)
        );
        assert_eq!(parsed.get("count").and_then(Json::as_u64), Some(2));
    }

    #[test]
    fn the_preview_total_counts_one_directory_once_however_many_targets_name_it() {
        // Two textually different candidates for ONE real directory — `dir` and `dir/`, which is
        // the cheapest way to build the collision in a test, and the same collision a symlinked or
        // case-variant target produces on a real machine. `bin/clean.sh:616` keys its dedup on
        // device+inode (`mole_path_identity`), so it collapses these; a string compare would not,
        // and the streamed `would_free_bytes` would promise twice the bytes the directory holds.
        let root = std::env::temp_dir().join(format!(
            "burrow_stream_preview_identity_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("cache");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), vec![b'x'; 4096]).unwrap();
        let on_disk = std::fs::metadata(dir.join("blob")).unwrap().len();

        let spelling = |p: String| CleanCandidate {
            path: p,
            label: "User caches".into(),
            size: on_disk,
        };
        let done = preview_done_ndjson(&[
            spelling(dir.to_string_lossy().into_owned()),
            spelling(format!("{}/", dir.to_string_lossy())),
        ]);
        let parsed = Json::parse(&done).expect("must be valid JSON");
        assert_eq!(
            parsed.get("would_free_bytes").and_then(Json::as_u64),
            Some(on_disk),
            "the same inode, reached twice, is still one directory's worth of bytes: {done}"
        );
        assert_eq!(
            parsed.get("count").and_then(Json::as_u64),
            Some(1),
            "{done}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn done_line_carries_totals() {
        let item = crate::clean::execute::RemovedItem {
            path: "/r".into(),
            label: "t".into(),
            freed: crate::clean::execute::Freed::Bytes(1024),
        };
        let outcome = CleanOutcome {
            removed: vec![item.clone(), item],
            freed_bytes: 2048,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/e".into(),
                error: "boom".into(),
            }],
            protected: vec!["/p".into()],
        };
        let line = done_ndjson(&outcome);
        assert!(line.contains("\"event\":\"done\""));
        assert!(line.contains("\"freed_bytes\":2048"));
        assert!(line.contains("\"moved_to_trash_bytes\":0"), "{line}");
        assert!(line.contains("\"removed\":2"));
        assert!(line.contains("\"failed\":1"));
        assert!(line.contains("\"protected\":1"));
    }
}
