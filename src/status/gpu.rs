//! GPU identity — ported from digger's `cmd/status/metrics_gpu.go` (the macOS
//! `system_profiler -json SPDisplaysDataType` path only; this crate has no `nvidia-smi`/non-macOS
//! path to port, since every other `status` collector is macOS-only too).
//!
//! Real-time GPU utilization needs `powermetrics`, which needs root — digger accepts that
//! limitation and reports `-1` ("unavailable") whenever it can't sample it. RULEBOOK §3g / "do not
//! write an SMC or IOKit reader" applies the same way here: `MetricsCore.SnapshotPatcher` on the
//! app side fills `gpu[0].usage` from a native (unprivileged, in-process) reading whenever the
//! engine reports `<= 0`, so this collector's job is only to emit the honest static identity with
//! `usage: -1` and let the app fill the rest — never to invoke `powermetrics` itself.

use crate::json::Json;

/// One GPU's static identity + (always -1 here) utilization.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GpuInfo {
    pub name: String,
    pub usage: f64,
    pub memory_used: u64,
    pub memory_total: u64,
    pub core_count: i64,
    pub note: String,
}

/// Parse `system_profiler -json SPDisplaysDataType` into one `GpuInfo` per display adapter that
/// has a name. `note` joins whichever of `spdisplays_vram` / `spdisplays_metal` / `spdisplays_vendor`
/// the adapter's JSON carries with " · ", in that order — ported field-for-field from digger's
/// `readMacGPUInfo`, including the exact key names. Deliberately NOT widened with the newer key
/// current macOS actually uses for the Metal family (`spdisplays_mtlgpufamilysupport`): verified
/// live, this adapter's real JSON has that key but not `spdisplays_metal`, and the golden's own
/// `note` is `"sppci_vendor_Apple"` alone (vendor only fired) — so the oracle itself is reading the
/// same now-absent key digger asks for. Matching the golden means porting the miss, not fixing it.
/// `usage` is always -1 (see module docs); `memory_used`/`memory_total` are always 0 — digger's
/// static-info parser never sets them either, on any code path. Empty when the JSON doesn't parse
/// or carries no display with a name.
pub fn parse_sp_displays_json(raw: &str) -> Vec<GpuInfo> {
    let Ok(doc) = Json::parse(raw) else {
        return Vec::new();
    };
    let Some(displays) = doc.get("SPDisplaysDataType").and_then(Json::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in displays {
        let name = d.get("_name").and_then(Json::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let mut note_parts: Vec<String> = Vec::new();
        if let Some(vram) = d.get("spdisplays_vram").and_then(Json::as_str) {
            if !vram.is_empty() {
                note_parts.push(format!("VRAM {vram}"));
            }
        }
        if let Some(metal) = d.get("spdisplays_metal").and_then(Json::as_str) {
            if !metal.is_empty() {
                note_parts.push(metal.to_string());
            }
        }
        if let Some(vendor) = d.get("spdisplays_vendor").and_then(Json::as_str) {
            if !vendor.is_empty() {
                note_parts.push(vendor.to_string());
            }
        }
        let core_count = d
            .get("sppci_cores")
            .and_then(Json::as_str)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        out.push(GpuInfo {
            name: name.to_string(),
            usage: -1.0,
            memory_used: 0,
            memory_total: 0,
            core_count,
            note: note_parts.join(" · "),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized system_profiler capture; the field layout, vendor token and core
    // count match the public golden. The device model is fictional.
    const APPLE_SILICON_SAMPLE: &str = r#"{
  "SPDisplaysDataType" : [
    {
      "_name" : "Fixture GPU 1",
      "spdisplays_mtlgpufamilysupport" : "spdisplays_metal4",
      "spdisplays_vendor" : "sppci_vendor_Apple",
      "sppci_bus" : "spdisplays_builtin",
      "sppci_cores" : "20",
      "sppci_device_type" : "spdisplays_gpu",
      "sppci_model" : "Fixture GPU 1"
    }
  ]
}"#;

    #[test]
    fn apple_silicon_note_is_vendor_only_matching_the_golden_shape() {
        // APPLE_SILICON_SAMPLE preserves captured system_profiler structure; the EXPECTED
        // values come from the vendored golden, loaded here rather than retyped, per RULEBOOK
        // §3e — the same live JSON has no `spdisplays_vram`/`spdisplays_metal` keys (only the
        // newer `spdisplays_mtlgpufamilysupport`, which digger's field list doesn't read), so
        // only vendor fires and the golden's own note is the single-part "sppci_vendor_Apple".
        let golden_json: &str = include_str!("status.golden.json");
        let golden = Json::parse(golden_json).expect("vendored golden must parse");
        let g_gpu0 = golden
            .get("gpu")
            .and_then(Json::as_array)
            .and_then(|a| a.first())
            .expect("golden.gpu[0] must exist");

        let gpus = parse_sp_displays_json(APPLE_SILICON_SAMPLE);
        assert_eq!(gpus.len(), 1);
        assert_eq!(
            Some(gpus[0].name.as_str()),
            g_gpu0.get("name").and_then(Json::as_str)
        );
        assert_eq!(gpus[0].usage, -1.0); // never in the golden's own shape — see module docs
        assert_eq!(gpus[0].memory_used, 0);
        assert_eq!(gpus[0].memory_total, 0);
        assert_eq!(
            Some(gpus[0].core_count),
            g_gpu0.get("core_count").and_then(Json::as_i64)
        );
        assert_eq!(
            Some(gpus[0].note.as_str()),
            g_gpu0.get("note").and_then(Json::as_str)
        );
    }

    #[test]
    // check_tests: no-golden — synthetic input exercising the VRAM+Metal note-joining branch,
    // which no real capture available while writing this exercises (the captured JSON has
    // neither key — see the test above). Feeds a hand-built raw system_profiler string to the
    // pure PARSER `parse_sp_displays_json`, not a serializer; that function's name happens to
    // contain "_json(" (as in, ends with it), which is what trips check_tests.py's SERIALIZES
    // heuristic (meant for `to_json`-style calls) — not an actual golden-shaped assertion.
    fn vram_and_metal_join_with_vendor_when_present() {
        let raw = r#"{"SPDisplaysDataType":[{"_name":"Some GPU","spdisplays_vram":"8 GB","spdisplays_metal":"Metal 3","spdisplays_vendor":"Vendor X","sppci_cores":"32"}]}"#;
        let gpus = parse_sp_displays_json(raw);
        assert_eq!(gpus[0].note, "VRAM 8 GB · Metal 3 · Vendor X");
        assert_eq!(gpus[0].core_count, 32);
    }

    #[test]
    // check_tests: no-golden — synthetic edge case (an unnamed display); see the waiver above for
    // why this trips check_tests.py's SERIALIZES heuristic despite calling a parser.
    fn unnamed_displays_are_dropped() {
        let raw = r#"{"SPDisplaysDataType":[{"_name":"","spdisplays_vendor":"X"}]}"#;
        assert!(parse_sp_displays_json(raw).is_empty());
    }

    #[test]
    // check_tests: no-golden — malformed/garbage input has no oracle capture by definition; see
    // the waiver two tests up for why this trips check_tests.py's SERIALIZES heuristic anyway.
    fn malformed_or_missing_root_yields_empty_not_a_panic() {
        assert!(parse_sp_displays_json("not json").is_empty());
        assert!(parse_sp_displays_json(r#"{"SomethingElse":[]}"#).is_empty());
    }
}
