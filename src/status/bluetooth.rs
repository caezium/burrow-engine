//! Bluetooth device inventory — genuinely NET-NEW: nothing else in the engine touches
//! `SPBluetoothDataType` (unlike `batteries`/`thermal`/`gpu`/`top_processes`, which are mostly
//! wiring over data the engine already collects elsewhere).
//!
//! Parses `system_profiler -json SPBluetoothDataType` via the crate's zero-dep JSON reader
//! (`crate::json`) rather than porting digger's TEXT parser (`parseSPBluetooth`,
//! metrics_bluetooth.go), which walks raw indentation depth to find section/device boundaries.
//! The JSON shape is a clean, stable array of single-key `{"Device Name": {..fields..}}` objects
//! under `device_connected`/`device_not_connected` — verified live against a real machine — so
//! there's no reason to depend on leading-whitespace counting to do the same job JSON already
//! structures for us.

use crate::json::Json;

/// One paired/discovered Bluetooth device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BluetoothDevice {
    pub name: String,
    pub connected: bool,
    /// Raw battery reading (e.g. `"82%"`), or `""` when the device doesn't report one. Kept as the
    /// raw string (with its `%`) rather than parsed to an int — matches `BluetoothDevice.battery:
    /// String` in `MoleStatus.swift`, which does its own digit-extraction client-side.
    pub battery: String,
}

/// The plausible battery-level keys Apple's `system_profiler -json SPBluetoothDataType` uses,
/// checked in this order (single-battery devices first, then AirPods-style Left/Right/Case).
/// UNVERIFIED against a real battery-reporting accessory — none was available while writing this
/// (every paired device here reports no battery, matching the golden's own all-`""` battery
/// column) — so this list is not a port of digger's TEXT-mode `"Battery Level:"` scan (which is
/// itself narrower than this: it only matches simple single-battery lines, not the
/// "Left Battery Level:"/"Right Battery Level:" lines AirPods-style devices print, a real quirk in
/// the original, not a spec worth reproducing). Sourced instead from exelban/stats
/// (`Modules/Bluetooth/readers.swift`), a real, independently-shipping macOS app parsing this
/// exact JSON for this exact purpose.
const BATTERY_KEYS: &[&str] = &[
    "device_batteryLevelMain",
    "device_batteryLevelCase",
    "device_batteryLevelLeft",
    "device_batteryLevelRight",
    "Left Battery Level",
    "Right Battery Level",
];

fn device_battery(fields: &Json) -> String {
    for key in BATTERY_KEYS {
        if let Some(v) = fields.get(key).and_then(Json::as_str) {
            return v.to_string();
        }
    }
    String::new()
}

/// Append every device in a `device_connected`/`device_not_connected` array — each element is a
/// single-key object `{"Device Name": {..fields..}}` — to `out` with the given `connected` value.
fn devices_from_section(section: Option<&Json>, connected: bool, out: &mut Vec<BluetoothDevice>) {
    let Some(items) = section.and_then(Json::as_array) else {
        return;
    };
    for item in items {
        let Json::Object(map) = item else { continue };
        for (name, fields) in map {
            out.push(BluetoothDevice {
                name: name.clone(),
                connected,
                battery: device_battery(fields),
            });
        }
    }
}

/// Parse `system_profiler -json SPBluetoothDataType` into a flat device list: every connected
/// device first (in report order), then every not-connected device (in report order) — matching
/// digger's `parseSPBluetooth`, which walks the TEXT output top-to-bottom and always meets the
/// "Connected:" section before "Not Connected:" (system_profiler's own fixed section order).
/// Empty — not a sentinel — when the JSON doesn't parse or carries no devices at all; the
/// collector (`collect::collect_bluetooth`) is what applies digger's "never an empty array on
/// macOS" sentinel-row fallback, matching where digger itself does it (the collector, not the
/// parser).
pub fn parse_sp_bluetooth_json(raw: &str) -> Vec<BluetoothDevice> {
    let Ok(doc) = Json::parse(raw) else {
        return Vec::new();
    };
    let Some(entry) = doc
        .get("SPBluetoothDataType")
        .and_then(Json::as_array)
        .and_then(|a| a.first())
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    devices_from_section(entry.get("device_connected"), true, &mut out);
    devices_from_section(entry.get("device_not_connected"), false, &mut out);
    out
}

/// FIX 5 (RULEBOOK, ADJUDICATED — port the miss, not the fix). Forces every device's `connected`
/// to `false`, reproducing digger's OWN (broken) output rather than this parser's more-correct one.
///
/// `system_profiler`'s TEXT output nests `Connected:` only as a SECTION HEADER (grouping
/// `device_connected` vs `device_not_connected`), never as a per-device field. digger's
/// `parseSPBluetooth` (`metrics_bluetooth.go`) detects device names by indentation depth
/// (8-space-indented lines ending in `:`) — and on modern macOS, `Connected:` itself is indented at
/// exactly that depth, so digger's parser reads it AS a device name, not a section marker, and then
/// never encounters a real per-device `Connected: Yes/No` line to set the flag from. Every device
/// comes out `false`, structurally, on every run — not a timing artifact: a reviewer confirmed a
/// live oracle run reports `false` for the SAME keyboard, at the SAME instant, that this engine's
/// JSON-based parser (above) correctly reads as connected.
///
/// This engine is left CORRECT internally (`parse_sp_bluetooth_json` stays honest and is tested on
/// its own merits) and this override is applied only at the collection boundary
/// (`collect::collect_bluetooth`), as a single, visible, easily-reversible line — because flipping
/// `connected` on for real activates `bluetoothWithBattery` (`StatusView.swift:458`), a filter that
/// can never have been true under digger, so up to nine new `RingGauge` rows would render for the
/// first time ever, mid-migration, with no way to tell a migration regression from a UI regression.
/// The correct behavior belongs in its own later change with its own testing.
pub fn match_digger_connected_state(devices: Vec<BluetoothDevice>) -> Vec<BluetoothDevice> {
    devices
        .into_iter()
        .map(|d| BluetoothDevice {
            connected: false,
            ..d
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sanitized system_profiler capture, with the same seven-device structure as the
    // public golden (one connected, six not connected). Device names and addresses are
    // fictional; the captured field layout and battery absence are preserved.
    const SANITIZED_SAMPLE: &str = r#"{
  "SPBluetoothDataType" : [
    {
      "controller_properties" : { "controller_address" : "02:00:00:00:00:03" },
      "device_connected" : [
        { "Fixture Bluetooth Device 1" : { "device_address" : "02:00:00:00:00:06", "device_minorType" : "Keyboard" } }
      ],
      "device_not_connected" : [
        { "Fixture Bluetooth Device 2" : { "device_address" : "02:00:00:00:00:05" } },
        { "Fixture Bluetooth Device 3" : { "device_address" : "02:00:00:00:00:07", "device_rssi" : "-78" } },
        { "Fixture Bluetooth Device 4" : { "device_address" : "02:00:00:00:00:01" } },
        { "Fixture Bluetooth Device 5" : { "device_address" : "02:00:00:00:00:09", "device_rssi" : "-32" } },
        { "Fixture Bluetooth Device 6" : { "device_address" : "02:00:00:00:00:08", "device_minorType" : "Keyboard" } },
        { "Fixture Bluetooth Device 7" : { "device_address" : "02:00:00:00:00:02", "device_minorType" : "Headset" } }
      ]
    }
  ]
}"#;

    #[test]
    fn connected_section_comes_first_then_not_connected_in_report_order() {
        // SANITIZED_SAMPLE preserves captured system_profiler structure; the EXPECTED
        // names/battery come from the vendored golden's own `bluetooth[]`, loaded here rather
        // than retyped, per RULEBOOK §3e. `connected` is deliberately NOT compared against the
        // golden's per-device values here — this test checks `parse_sp_bluetooth_json` itself,
        // which is honestly structural (module doc comment), while the golden's own `connected`
        // is ALWAYS `false` for every device. An earlier version of this comment claimed that was
        // "genuinely live state" that happened to differ at capture time — a reviewer FALSIFIED
        // that: a live oracle run reports `false` for this exact keyboard at the SAME INSTANT this
        // parser correctly reads `true` from the JSON. The real cause is structural, not timing:
        // digger's TEXT parser can never populate `connected` on modern macOS at all — see
        // `match_digger_connected_state`'s doc comment, which is where this engine reproduces that
        // (broken, but shipped) behavior, with its own dedicated test. What IS a stable structural
        // claim — and what this test checks instead — is the SECTION ORDER: `parse_sp_bluetooth_json`
        // always emits every `device_connected` entry before every `device_not_connected` entry,
        // matching digger's own TEXT parser (system_profiler's section order is fixed).
        let golden_json: &str = include_str!("status.golden.json");
        let golden = Json::parse(golden_json).expect("vendored golden must parse");
        let g_bt = golden
            .get("bluetooth")
            .and_then(Json::as_array)
            .expect("golden.bluetooth must be an array");
        assert!(
            !g_bt.is_empty(),
            "golden must carry real rows to anchor against"
        );

        let devices = parse_sp_bluetooth_json(SANITIZED_SAMPLE);
        assert_eq!(devices.len(), g_bt.len());
        for (d, g) in devices.iter().zip(g_bt.iter()) {
            assert_eq!(Some(d.name.as_str()), g.get("name").and_then(Json::as_str));
            assert_eq!(
                Some(d.battery.as_str()),
                g.get("battery").and_then(Json::as_str)
            );
        }
        // Structural claim, checked against THIS sample's own connected state (not the golden's
        // — see above): the connected section is emitted first, before any not-connected entry.
        assert!(devices[0].connected);
        assert!(devices[1..].iter().all(|d| !d.connected));
    }

    #[test]
    // check_tests: no-golden — every device in the golden's own bluetooth[] reports
    // battery:"" (no battery-reporting accessory was available while writing this — see the
    // module doc comment), so there's no oracle value for a battery-present row to anchor to.
    // Feeds a synthetic AirPods-shaped snippet to the pure PARSER `parse_sp_bluetooth_json`, not
    // a serializer; see the waiver on `malformed_or_missing_root_yields_empty_not_a_panic` below
    // for why the name still trips check_tests.py's SERIALIZES heuristic.
    fn battery_key_is_read_when_present() {
        let raw = r#"{"SPBluetoothDataType":[{"device_not_connected":[
            {"AirPods Pro":{"device_address":"AA:BB","device_batteryLevelMain":"82%"}}
        ]}]}"#;
        let devices = parse_sp_bluetooth_json(raw);
        assert_eq!(devices[0].battery, "82%");
    }

    #[test]
    // check_tests: no-golden — malformed/garbage input has no oracle capture by definition.
    // Trips check_tests.py's SERIALIZES heuristic only because `parse_sp_bluetooth_json`'s name
    // happens to contain "_json(" — that regex is aimed at `to_json`-style calls, and this is a
    // parser, not a serializer.
    fn malformed_or_missing_root_yields_empty_not_a_panic() {
        assert!(parse_sp_bluetooth_json("not json").is_empty());
        assert!(parse_sp_bluetooth_json(r#"{"SomethingElse":[]}"#).is_empty());
        assert!(parse_sp_bluetooth_json(r#"{"SPBluetoothDataType":[]}"#).is_empty());
    }

    #[test]
    fn match_digger_connected_state_forces_every_device_false() {
        // FIX 5 (RULEBOOK): the parser itself is structurally correct — SANITIZED_SAMPLE's keyboard is
        // genuinely connected and `parse_sp_bluetooth_json` says so. digger's own shipped output
        // can never say so on modern macOS (see this function's doc comment), so the override
        // reproduces that deliberately, at the collection boundary, leaving the parser honest.
        let devices = parse_sp_bluetooth_json(SANITIZED_SAMPLE);
        assert!(
            devices[0].connected,
            "the parser itself must stay honest and correct"
        );
        let matched = match_digger_connected_state(devices);
        assert!(
            matched.iter().all(|d| !d.connected),
            "every device must read false, matching digger's structural miss"
        );
        // Names/battery must pass through unchanged — only `connected` is touched.
        assert_eq!(matched[0].name, "Fixture Bluetooth Device 1");
    }
}
