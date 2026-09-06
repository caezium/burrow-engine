//! Persisted previous-sample cache for the network-rate collector.
//!
//! `burrow-engine status` is a one-shot process — it has no long-lived collector struct to hold a
//! "previous sample" the way digger's `Collector` does (`cmd/status/metrics_network.go` keeps
//! `prevNet` + a timestamp on the struct, seeded once at construction and updated every call). A
//! rate needs two samples separated by a known interval, and a fresh process has no second sample
//! to compare against.
//!
//! Rather than sleep-and-resample inside one invocation (which would tax every single `status`
//! call, and `status` is on the GUI's snapshot timer), this persists the last sample's byte
//! counters + capture time to a small file and reads it back on the next run. The GUI polls
//! `status` repeatedly, so from the second invocation onward this reproduces digger's semantics
//! (real rate, real elapsed interval) at zero added latency.
//!
//! **Network only.** `disk_io` deliberately does NOT use this module — the golden's own
//! `disk_io` is `{read_rate: 0, write_rate: 0}` (the shipping conductor is exactly as one-shot as
//! this engine), and the app's `SnapshotPatcher` (`MetricsCore.swift`) fills it from a native
//! IOKit reading, but ONLY when the engine reports zeros. A fabricated non-zero rate here would
//! make the patcher stand down and ship a stale or invented number in place of the correct native
//! one. `network` has no such patcher branch (checked against `MetricsCore.swift` on
//! `origin/main` — it fills `disk_io`/`gpu`/`thermal` and nothing else), so this file is the only
//! source of a live network rate and earns the added complexity that `disk_io` doesn't.
//!
//! A missing, corrupt, unreadable, too-old, or future-dated baseline all mean the same thing here
//! — "no baseline" — and every one of them degrades to a 0.0 rate at the call site, never a
//! command failure and never an amplified/fabricated number.

use crate::json::Json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Digger's `minNetworkSampleInterval` (`metrics_network.go`) — floors `elapsed` so a fast repeat
/// call can't divide by ~0 and produce an absurd spike. Network-specific: digger's disk-IO
/// collector (`metrics_disk.go:439`) uses a DIFFERENT guard, `if elapsed <= 0 { elapsed = 1 }` (a
/// one-second floor, and only for the non-positive case, not a general minimum) — the two are not
/// the same fix, and this engine's `disk_io` doesn't compute a rate at all (see module docs), so
/// there's nothing here to reconcile with it.
pub const MIN_SAMPLE_INTERVAL_SECS: f64 = 0.1;

/// Baselines older than this are a long-run average pretending to be a live rate, not a current
/// reading. Five minutes is generous slack over any real polling cadence (the GUI's snapshot
/// timer, an MCP tool call, an interactive `status` run) while still rejecting "I haven't opened
/// the app since this morning".
pub const MAX_BASELINE_AGE_SECS: f64 = 300.0;

/// A NIC rate ceiling used to clamp an obviously-corrupt computed rate rather than ship it. FIX 6
/// (RULEBOOK): the OLD ceiling (100,000 MB/s = 100 GB/s) was above the magnitude it existed to
/// catch — a measured 1-second-old baseline with a zeroed counter produced 83,896 MB/s straight
/// through it, which `SnapshotProducer` then persisted and which pinned the network chart's y-axis
/// six orders of magnitude above a machine whose real rates are 0.02-0.13 MB/s. 10,000 MB/s
/// (10 GB/s) comfortably covers even Thunderbolt Bridge networking (realistically a few GB/s) —
/// every real consumer NIC — while sitting an order of magnitude below both the old ceiling and the
/// measured false reading. This is defense in depth, not the primary fix: the primary fix is
/// `network::build_network_status` now REJECTING a (0,0) previous sample outright (emitting 0.0)
/// rather than computing a delta against it, since a zeroed baseline is what produced the
/// astronomical reading in the first place — see that function's doc comment. Per RULEBOOK §3g,
/// emitting nothing is safe and emitting a wrong number is not; this ceiling only bounds whatever
/// gets past that rejection.
pub const MAX_PLAUSIBLE_RATE_MBS: f64 = 10_000.0;

/// One point-in-time reading of every counter this module tracks, as persisted to disk.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IoSample {
    pub at_unix_ms: u64,
    /// (interface name, cumulative bytes in, cumulative bytes out) — every interface `netstat`
    /// reported, unfiltered (the noise-prefix filter is applied when the rate is CONSUMED, not
    /// when it's cached, so a filter-list change doesn't require a fresh baseline).
    pub network: Vec<(String, u64, u64)>,
}

/// Elapsed seconds between two capture times, floored so a near-instant repeat call can't blow up
/// the rate. Pure. Callers should gate `prev` through [`is_baseline_usable`] FIRST — this function
/// alone can't distinguish "50ms real gap" from "clock went backwards", it just clamps both to the
/// same floor defensively.
pub fn elapsed_secs(prev_at_unix_ms: u64, now_unix_ms: u64) -> f64 {
    let raw = now_unix_ms.saturating_sub(prev_at_unix_ms) as f64 / 1000.0;
    raw.max(MIN_SAMPLE_INTERVAL_SECS)
}

/// Whether a persisted baseline captured at `prev_at_unix_ms` is still trustworthy at
/// `now_unix_ms`. False for a future timestamp (clock skew, a hand-edited file, or a concurrent
/// writer racing a clock adjustment — `now.saturating_sub(prev)` on a future stamp silently gives
/// 0, which `elapsed_secs` would floor to 0.1s and then divide the WHOLE accumulated delta by,
/// amplifying the error instead of containing it) and false for one older than
/// [`MAX_BASELINE_AGE_SECS`]. Pure.
pub fn is_baseline_usable(prev_at_unix_ms: u64, now_unix_ms: u64) -> bool {
    if now_unix_ms < prev_at_unix_ms {
        return false;
    }
    let age_secs = (now_unix_ms - prev_at_unix_ms) as f64 / 1000.0;
    age_secs <= MAX_BASELINE_AGE_SECS
}

/// Serialize a sample to JSON (via this crate's own zero-dep `Json` writer). Pure.
pub fn to_json(sample: &IoSample) -> String {
    let net = sample
        .network
        .iter()
        .map(|(name, bytes_in, bytes_out)| {
            let mut m = BTreeMap::new();
            m.insert("name".to_string(), Json::String(name.clone()));
            m.insert("bytes_in".to_string(), Json::Number(*bytes_in as f64));
            m.insert("bytes_out".to_string(), Json::Number(*bytes_out as f64));
            Json::Object(m)
        })
        .collect();
    let mut root = BTreeMap::new();
    root.insert(
        "at_unix_ms".to_string(),
        Json::Number(sample.at_unix_ms as f64),
    );
    root.insert("network".to_string(), Json::Array(net));
    Json::Object(root).to_json_string()
}

/// Parse a sample back. `None` on anything malformed — a corrupt state file degrades to "no
/// baseline", never a command failure. Pure.
pub fn from_json(text: &str) -> Option<IoSample> {
    let doc = Json::parse(text).ok()?;
    let at_unix_ms = doc.get("at_unix_ms")?.as_u64()?;
    let mut network = Vec::new();
    for item in doc.get("network")?.as_array()? {
        let name = item.get("name")?.as_str()?.to_string();
        let bytes_in = item.get("bytes_in")?.as_u64()?;
        let bytes_out = item.get("bytes_out")?.as_u64()?;
        network.push((name, bytes_in, bytes_out));
    }
    Some(IoSample {
        at_unix_ms,
        network,
    })
}

/// Pure resolution of the state file path from already-read environment values — injectable so
/// the HOME-unset and env-override cases are tested without mutating the real process
/// environment (`std::env::set_var` races every other test that spawns a subprocess and inherits
/// the environment; this codebase's existing convention for exactly this problem is dependency
/// injection — see `collect::resolve_proxy`, `network::collect_proxy_from_env`). `home`
/// empty/absent (HOME unset or blank) returns `None` rather than resolving a relative path: joining
/// onto an empty base would silently create `Library/Application Support/...` under the CURRENT
/// WORKING DIRECTORY, littering wherever `burrow-engine` happened to be invoked from.
///
/// Lives under Application Support, not Caches: `~/Library/Caches` is the first entry in
/// `clean::plan::UNIVERSAL_TARGETS`, and `clean::execute` removes it wholesale — the app's own
/// Clean button would delete this baseline on every run, guaranteeing a cold start (and an empty
/// baseline-dependent state) right after the exact action a user takes to tidy up their Mac. Only
/// the `CrashReporter` subpath of Application Support is a clean target, and this file lives
/// beside it, not under it.
fn resolve_state_path(env_override: Option<&str>, home: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = env_override {
        return Some(PathBuf::from(p));
    }
    let home = home.filter(|h| !h.is_empty())?;
    Some(
        Path::new(home).join(
            "Library/Application Support/dev.caezium.Burrow/burrow-engine/status-io-prev.json",
        ),
    )
}

/// Where the state file lives: `BURROW_ENGINE_STATUS_STATE` overrides it (tests inject a temp
/// path), otherwise a per-user Application Support location. `None` when HOME is unset/blank —
/// callers must treat that as "persistence disabled", not fall back to a relative path.
fn state_file_path() -> Option<PathBuf> {
    let env_override = std::env::var("BURROW_ENGINE_STATUS_STATE").ok();
    let home = crate::platform::home_dir();
    resolve_state_path(env_override.as_deref(), home.as_deref())
}

/// Load the previous sample from the real state file location, or `None` if there isn't one, HOME
/// is unset, or it can't be read or parsed.
pub fn load() -> Option<IoSample> {
    state_file_path().and_then(|p| load_from(&p))
}

/// Load a sample from an explicit path. Pure I/O, no environment involved — the primitive `load`
/// wraps and what tests call directly, so a test never needs to mutate `HOME` or the override env
/// var to exercise this.
pub fn load_from(path: &Path) -> Option<IoSample> {
    let text = std::fs::read_to_string(path).ok()?;
    from_json(&text)
}

/// Persist the current sample to the real state file location for the next invocation.
/// Best-effort: a failure to write (e.g. a read-only home directory, or HOME unset) just means
/// the NEXT call also has no baseline — not a reason to fail this one.
pub fn save(sample: &IoSample) {
    if let Some(path) = state_file_path() {
        save_to(&path, sample);
    }
}

/// Persist a sample to an explicit path, atomically: write to a per-process-unique temp file in
/// the SAME directory (so the rename below stays on one filesystem), then `rename` it over the
/// real path. Plain `fs::write` truncates-then-writes the target in place, so a concurrent reader
/// can observe a torn (partially-written) file — and this file has real concurrent writers: the
/// GUI's poll, an MCP tool call, and a terminal run can all invoke `status` around the same
/// moment. `rename` onto an existing path is atomic on APFS: any reader sees either the complete
/// old file or the complete new one, never a partial write. This does not serialize concurrent
/// writers' logical read-modify-write cycles (two processes can still race on WHICH one's sample
/// ends up as the baseline), but the clamp in the rate consumer (`MAX_PLAUSIBLE_RATE_MBS`) bounds
/// the resulting damage regardless of which one wins.
pub fn save_to(path: &Path, sample: &IoSample) {
    let Some(dir) = path.parent() else { return };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!("status-io-prev.{}.{nanos}.tmp", std::process::id()));
    if std::fs::write(&tmp, to_json(sample)).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "burrow-io-rate-test-{label}-{}-{nanos}",
                std::process::id()
            ))
            .join("status-io-prev.json")
    }

    #[test]
    fn elapsed_floors_at_min_interval() {
        assert_eq!(elapsed_secs(1000, 1050), MIN_SAMPLE_INTERVAL_SECS); // 50ms real -> floored
        assert_eq!(elapsed_secs(1000, 3000), 2.0); // 2s real, above the floor
        assert_eq!(elapsed_secs(2000, 1000), MIN_SAMPLE_INTERVAL_SECS); // defensive: shouldn't
                                                                        // reach here once callers
                                                                        // gate via is_baseline_usable
    }

    #[test]
    fn baseline_usable_within_age_cap() {
        assert!(is_baseline_usable(1000, 2000)); // 1s old
        let at_the_cap = 1000 + (MAX_BASELINE_AGE_SECS * 1000.0) as u64;
        assert!(is_baseline_usable(1000, at_the_cap));
    }

    #[test]
    fn baseline_unusable_beyond_age_cap() {
        let too_old = 1000 + (MAX_BASELINE_AGE_SECS * 1000.0) as u64 + 1;
        assert!(!is_baseline_usable(1000, too_old));
    }

    #[test]
    fn baseline_unusable_on_future_or_backwards_timestamp() {
        // prev is AFTER now — clock skew, a hand-edited file, or a race with a concurrent
        // writer. Must be rejected outright, not clamped-and-used (a naive `saturating_sub` floor
        // here would divide a real accumulated delta by the smallest legal divisor).
        assert!(!is_baseline_usable(5000, 1000));
        assert!(!is_baseline_usable(1000, 999));
    }

    #[test]
    fn round_trips_through_json() {
        let sample = IoSample {
            at_unix_ms: 1_753_000_000_123,
            network: vec![("en0".into(), 111, 222), ("en4".into(), 0, 0)],
        };
        let json = to_json(&sample);
        let back = from_json(&json).expect("round-trips");
        assert_eq!(back, sample);
    }

    #[test]
    fn corrupt_or_missing_json_degrades_to_none() {
        assert_eq!(from_json(""), None);
        assert_eq!(from_json("{not json"), None);
        assert_eq!(from_json("{}"), None); // well-formed but missing every key
        assert_eq!(
            from_json(r#"{"at_unix_ms":1,"network":[{"name":"en0"}]}"#),
            None
        ); // partial row
    }

    #[test]
    fn missing_state_file_loads_as_none_and_round_trips_once_saved() {
        let path = temp_path("missing");
        assert_eq!(load_from(&path), None);

        let sample = IoSample {
            at_unix_ms: 42,
            network: vec![("en0".into(), 1, 2)],
        };
        save_to(&path, &sample);
        assert_eq!(load_from(&path), Some(sample));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn save_to_is_atomic_and_leaves_no_temp_file_behind() {
        let path = temp_path("atomic");
        let sample = IoSample {
            at_unix_ms: 1,
            network: vec![("en0".into(), 1, 2)],
        };
        save_to(&path, &sample);
        assert_eq!(load_from(&path), Some(sample));

        let dir = path.parent().unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only the final file should remain, got {entries:?}"
        );
        assert!(!entries[0].file_name().to_string_lossy().contains(".tmp"));

        // A second save (simulating the next invocation) replaces it cleanly.
        let sample2 = IoSample {
            at_unix_ms: 2,
            network: vec![("en0".into(), 3, 4)],
        };
        save_to(&path, &sample2);
        assert_eq!(load_from(&path), Some(sample2));
        let entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "still exactly one file after a second save"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_state_path_uses_application_support_not_caches() {
        let p = resolve_state_path(None, Some("/Users/x")).unwrap();
        let s = p.to_string_lossy();
        assert!(
            s.contains("Library/Application Support/dev.caezium.Burrow"),
            "{s}"
        );
        assert!(
            !s.contains("Library/Caches"),
            "must not live under Caches — clean deletes it wholesale: {s}"
        );
    }

    #[test]
    fn resolve_state_path_home_unset_disables_persistence_instead_of_a_relative_path() {
        assert_eq!(resolve_state_path(None, None), None);
        assert_eq!(resolve_state_path(None, Some("")), None, "blank HOME too");
    }

    #[test]
    fn resolve_state_path_env_override_wins_even_without_home() {
        let p = resolve_state_path(Some("/tmp/custom.json"), None).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/custom.json"));
    }
}
