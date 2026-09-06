//! The analyze JSON contract — the shape every Burrow surface reads for a disk scan. Ported from
//! digger's `cmd/analyze/json.go`. Hand-rolled + zero-dep (the engine's rule), and it wires in the
//! already-ported `cleanable` classifier so directory entries carry the `cleanable` flag.
//!
//! Shape (compact — a consumer parses it, so indentation is irrelevant; the envelope embeds it as
//! `data` verbatim): `{path, overview, entries:[{name,path,size,is_dir,cleanable?,last_access?}],
//! large_files?:[{name,path,size}], total_size, total_files?}`. `omitempty` fields (`cleanable`,
//! `last_access`, `large_files`, `total_files`, and the not-yet-ported `insight`) are omitted when
//! empty, matching Go's `encoding/json`.

use super::cleanable::is_cleanable_dir;
use super::scanner::{DirEntry, FileEntry, ScanProgress, ScanResult};
use std::path::Path;

use crate::json::escape as esc;

/// Format a unix timestamp (seconds) as RFC 3339 UTC, e.g. `2020-09-13T12:26:40Z` — matching
/// digger's `time.UTC().Format(time.RFC3339)`. Zero-dep civil-date math (Howard Hinnant's
/// `civil_from_days`), so no chrono. Handles negative (pre-epoch) timestamps too.
pub fn rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = year + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn entry_json(e: &DirEntry) -> String {
    let mut s = format!(
        "{{\"name\":{},\"path\":{},\"size\":{},\"is_dir\":{}",
        esc(&e.name),
        esc(&e.path),
        e.size,
        e.is_dir
    );
    // `insight` is overview-only (insights module not yet ported) → always false → omitted.
    if e.is_dir && is_cleanable_dir(Path::new(&e.path)) {
        s.push_str(",\"cleanable\":true");
    }
    if let Some(atime) = e.last_access {
        s.push_str(&format!(",\"last_access\":{}", esc(&rfc3339_utc(atime))));
    }
    s.push('}');
    s
}

fn file_json(f: &FileEntry) -> String {
    format!(
        "{{\"name\":{},\"path\":{},\"size\":{}}}",
        esc(&f.name),
        esc(&f.path),
        f.size
    )
}

/// Serialize a scan into the analyze JSON contract.
pub fn to_json(path: &str, overview: bool, r: &ScanResult) -> String {
    let entries = r
        .entries
        .iter()
        .map(entry_json)
        .collect::<Vec<_>>()
        .join(",");
    let mut out = format!(
        "{{\"path\":{},\"overview\":{},\"entries\":[{}]",
        esc(path),
        overview,
        entries
    );
    // large_files is omitempty — only present when non-empty.
    if !r.large_files.is_empty() {
        let lf = r
            .large_files
            .iter()
            .map(file_json)
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(",\"large_files\":[{lf}]"));
    }
    out.push_str(&format!(",\"total_size\":{}", r.total_size));
    // total_files is omitempty — omitted when zero.
    if r.total_files != 0 {
        out.push_str(&format!(",\"total_files\":{}", r.total_files));
    }
    out.push('}');
    out
}

/// One `analyze --progress` NDJSON line: `{"type":"progress","files":N,"dirs":N,"bytes":B,"path":P}`.
/// The keys are digger's (`cmd/analyze/progress.go::progressEvent`) and are exactly what the app's
/// `AnalyzeProgressEvent.parse` reads — `type` selects the arm, the four counters default to zero
/// when absent, so none may be renamed.
pub fn progress_ndjson(p: &ScanProgress) -> String {
    format!(
        "{{\"type\":\"progress\",\"files\":{},\"dirs\":{},\"bytes\":{},\"path\":{}}}",
        p.files,
        p.dirs,
        p.bytes,
        esc(&p.path)
    )
}

/// The terminal `analyze --progress` line: `{"type":"result","data":<analyze data>}`, where `data`
/// is byte-for-byte the [`to_json`] payload the buffered command puts in its envelope (digger's
/// `resultEvent`; the app re-serializes `data` and hands it to `DiskScanner.parse`).
pub fn result_ndjson(data: &str) -> String {
    format!("{{\"type\":\"result\",\"data\":{data}}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    /// The two stream lines, parsed back through the engine's reader and checked field by field
    /// against the keys `AnalyzeProgress.swift` reads (`type`, `files`, `dirs`, `bytes`, `path`;
    /// `type`, `data`). `data` must be the buffered payload verbatim.
    #[test]
    fn progress_stream_lines_carry_the_keys_the_app_decodes() {
        let line = progress_ndjson(&ScanProgress {
            path: "/x/a b".into(),
            files: 10,
            dirs: 2,
            bytes: 4096,
        });
        let p = Json::parse(&line).expect("valid JSON");
        assert_eq!(p.get("type").and_then(Json::as_str), Some("progress"));
        assert_eq!(p.get("files").and_then(Json::as_i64), Some(10));
        assert_eq!(p.get("dirs").and_then(Json::as_i64), Some(2));
        assert_eq!(p.get("bytes").and_then(Json::as_i64), Some(4096));
        assert_eq!(p.get("path").and_then(Json::as_str), Some("/x/a b"));

        let r = ScanResult {
            entries: vec![],
            large_files: vec![],
            total_size: 123,
            total_files: 4,
        };
        let data = to_json("/x", false, &r);
        let line = result_ndjson(&data);
        let p = Json::parse(&line).expect("valid JSON");
        assert_eq!(p.get("type").and_then(Json::as_str), Some("result"));
        assert_eq!(
            p.get("data").map(Json::to_json_string),
            Some(Json::parse(&data).unwrap().to_json_string())
        );
        assert!(line.contains(&data), "data rides verbatim: {line}");
    }

    #[test]
    fn rfc3339_known_vectors() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_utc(1_600_000_000), "2020-09-13T12:26:40Z");
        // A leap day, to exercise the civil-date math.
        assert_eq!(rfc3339_utc(1_582_934_400), "2020-02-29T00:00:00Z");
    }

    fn dir(name: &str, path: &str, size: i64, is_dir: bool, la: Option<i64>) -> DirEntry {
        DirEntry {
            name: name.into(),
            path: path.into(),
            size,
            is_dir,
            last_access: la,
        }
    }

    #[test]
    fn serializes_the_contract_with_omitempty() {
        let r = ScanResult {
            entries: vec![
                dir("big", "/x/big", 8000, true, None),
                dir("f.bin", "/x/f.bin", 100, false, Some(1_600_000_000)),
            ],
            large_files: vec![FileEntry {
                name: "f.bin".into(),
                path: "/x/f.bin".into(),
                size: 100,
            }],
            total_size: 8100,
            total_files: 3,
        };
        let json = to_json("/x", false, &r);
        // Spot-check the spine + omitempty behavior.
        assert!(json.contains("\"path\":\"/x\""));
        assert!(json.contains("\"overview\":false"));
        assert!(json.contains("\"is_dir\":true"));
        assert!(json.contains("\"last_access\":\"2020-09-13T12:26:40Z\""));
        assert!(json.contains("\"large_files\":["));
        assert!(json.contains("\"total_size\":8100"));
        assert!(json.contains("\"total_files\":3"));
        // The dir entry carries no last_access (None) and the file no cleanable flag.
        assert!(
            !json.contains("\"insight\""),
            "insight is omitted (not ported)"
        );
    }

    #[test]
    fn empty_scan_omits_large_files_and_total_files() {
        let parsed = Json::parse(&to_json("/e", false, &ScanResult::default()))
            .expect("to_json must emit valid JSON");
        // omitempty (this module's header comment): large_files/total_files must be ABSENT, not
        // merely empty/zero — checked as key presence via the parser, not a whole-string literal,
        // so this can't be satisfied by coincidentally matching an unrelated hand-typed shape.
        assert_eq!(parsed.get("path").and_then(Json::as_str), Some("/e"));
        assert_eq!(parsed.get("overview").and_then(Json::as_bool), Some(false));
        assert_eq!(
            parsed
                .get("entries")
                .and_then(Json::as_array)
                .map(|a| a.len()),
            Some(0)
        );
        assert_eq!(parsed.get("total_size").and_then(Json::as_i64), Some(0));
        assert!(
            parsed.get("large_files").is_none(),
            "large_files must be OMITTED (not an empty array) when there are none"
        );
        assert!(
            parsed.get("total_files").is_none(),
            "total_files must be OMITTED (not 0) when the scan found zero files"
        );
    }

    /// The contract fixture bundled for standalone CI. `scripts/check_fixtures.py` verifies
    /// the approved public copy; `FIXTURE_PROVENANCE.md` records its captured authority.
    ///
    /// This test LOADS that file at run time and derives every `to_json` input from it — it does
    /// not transcribe values. One field is deliberately NOT round-tripped byte-for-byte:
    /// `last_access`. The golden stores it pre-formatted (`rfc3339_utc`'s RFC 3339 string output),
    /// while `DirEntry.last_access` takes raw unix seconds as INPUT, and `rfc3339_utc`'s own
    /// correctness is already covered directly by `rfc3339_known_vectors`. So this test proves the
    /// two things specific to the golden instead: every entry the golden marks as having
    /// `last_access` gets the key back out of a fresh `to_json` run (and every entry without one
    /// doesn't — RULEBOOK §3a's file-vs-directory variance), and every other field — `path`,
    /// `overview`, `total_size`, `total_files`, the `large_files` omission, and each entry's
    /// `name`/`path`/`size`/`is_dir` — matches the golden exactly.
    #[test]
    fn to_json_round_trips_the_golden_loaded_from_disk() {
        let golden_text = include_str!("analyze.golden.json");
        let golden = Json::parse(golden_text).expect("vendored golden must be valid JSON");

        let path = golden
            .get("path")
            .and_then(Json::as_str)
            .expect("golden.path");
        let overview = golden
            .get("overview")
            .and_then(Json::as_bool)
            .expect("golden.overview");
        let golden_entries = golden
            .get("entries")
            .and_then(Json::as_array)
            .expect("golden.entries must be an array");
        assert!(
            !golden_entries.is_empty(),
            "golden.entries is empty — this test can no longer prove anything"
        );

        let entries: Vec<DirEntry> = golden_entries
            .iter()
            .map(|e| {
                let has_last_access = e.get("last_access").is_some();
                dir(
                    e.get("name").and_then(Json::as_str).expect("entry.name"),
                    e.get("path").and_then(Json::as_str).expect("entry.path"),
                    e.get("size").and_then(Json::as_i64).expect("entry.size"),
                    e.get("is_dir")
                        .and_then(Json::as_bool)
                        .expect("entry.is_dir"),
                    // No raw-seconds source for last_access (the golden stores it pre-formatted)
                    // — a placeholder stands in wherever the golden has the key, purely to prove
                    // the KEY round-trips; its formatted VALUE is intentionally not compared below.
                    has_last_access.then_some(0),
                )
            })
            .collect();
        let total_size = golden
            .get("total_size")
            .and_then(Json::as_i64)
            .expect("golden.total_size");
        // omitempty: absent means zero, matching how to_json itself treats it.
        let total_files = golden
            .get("total_files")
            .and_then(Json::as_i64)
            .unwrap_or(0);

        let r = ScanResult {
            entries,
            large_files: vec![], // golden has no large_files key (nothing >= 1MiB in the fixture)
            total_size,
            total_files,
        };
        let engine =
            Json::parse(&to_json(path, overview, &r)).expect("to_json must emit valid JSON");

        assert_eq!(engine.get("path"), golden.get("path"));
        assert_eq!(engine.get("overview"), golden.get("overview"));
        assert_eq!(engine.get("total_size"), golden.get("total_size"));
        assert_eq!(engine.get("total_files"), golden.get("total_files"));
        assert_eq!(
            engine.get("large_files"),
            golden.get("large_files"),
            "golden has no large_files (nothing in the fixture is >= 1MiB) — omitempty must agree"
        );

        let engine_entries = engine
            .get("entries")
            .and_then(Json::as_array)
            .expect("engine must emit entries");
        assert_eq!(engine_entries.len(), golden_entries.len());
        for (g, eng) in golden_entries.iter().zip(engine_entries.iter()) {
            assert_eq!(eng.get("name"), g.get("name"));
            assert_eq!(eng.get("path"), g.get("path"));
            assert_eq!(eng.get("size"), g.get("size"));
            assert_eq!(eng.get("is_dir"), g.get("is_dir"));
            assert_eq!(
                eng.get("last_access").is_some(),
                g.get("last_access").is_some(),
                "last_access must be present on exactly the entries the golden has it on"
            );
        }
    }

    #[test]
    fn cleanable_flag_is_set_for_known_dep_dirs() {
        let r = ScanResult {
            entries: vec![dir("node_modules", "/proj/node_modules", 999, true, None)],
            total_size: 999,
            total_files: 0,
            large_files: vec![],
        };
        assert!(to_json("/proj", false, &r).contains("\"cleanable\":true"));
    }
}
