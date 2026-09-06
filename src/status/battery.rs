//! Battery health arithmetic + ioreg number parsing — ported from digger's
//! `cmd/status/metrics_battery.go`. These are the pure kernels the native battery collector (which
//! shells out to `system_profiler` / `ioreg`) feeds. The JSON-parsing half (`parse_system_power_json`,
//! `parse_pmset_batt`) now has a home too: `crate::json` is the zero-dep JSON reader this crate
//! settled on, so the "waits on the zero-dep-vs-libc call" this doc comment used to mention is
//! resolved — JSON won.

use crate::json::Json;

/// Battery max-capacity as a percentage of design capacity, rounded (half away from zero, matching
/// Go's `math.Round`) and clamped to [0,100]. Prefers the nominal charge, falling back to the raw
/// max; 0 when design or capacity is unknown.
pub fn battery_health_percent(design: i64, nominal: i64, raw_max: i64) -> i32 {
    if design <= 0 {
        return 0;
    }
    let capacity = if nominal == 0 { raw_max } else { nominal };
    if capacity <= 0 {
        return 0;
    }
    let pct = (capacity as f64 * 100.0 / design as f64).round();
    pct.clamp(0.0, 100.0) as i32
}

/// Parse an integer percentage like `" 82% "` → 82, tolerating surrounding whitespace and a
/// trailing `%`. 0 on anything unparseable.
pub fn parse_percent_int(raw: &str) -> i32 {
    raw.trim()
        .trim_end_matches('%')
        .trim()
        .parse::<i32>()
        .unwrap_or(0)
}

/// Parse an ioreg-printed integer. ioreg sometimes prints a negative `int64` as its unsigned two's
/// complement, so a value above `i64::MAX` is reinterpreted as the corresponding negative number.
/// `None` on non-numeric input (or a magnitude that can't fit `i64`).
pub fn parse_ioreg_signed_integer(raw: &str) -> Option<i64> {
    if let Ok(v) = raw.parse::<i64>() {
        return Some(v);
    }
    let val = raw.parse::<u64>().ok()?;
    if val <= i64::MAX as u64 {
        return Some(val as i64);
    }
    // Two's-complement reinterpretation: magnitude = ~val + 1.
    let neg_mag = (!val).wrapping_add(1);
    if neg_mag > i64::MAX as u64 {
        return None;
    }
    Some(-(neg_mag as i64))
}

/// Battery health read from `system_profiler SPPowerDataType` TEXT output: cycle count, condition,
/// and maximum capacity. Scans line-by-line for the labelled fields (case-insensitive), taking the
/// value after the first colon. `parse_percent_int` tolerates the non-breaking space Apple prints
/// before `%`. (The equivalent JSON output needs a JSON reader and waits on the zero-dep call.)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemPowerInfo {
    pub health: String,
    pub cycles: i32,
    pub capacity: i32,
}

pub fn parse_system_power_text(out: &str) -> SystemPowerInfo {
    let mut info = SystemPowerInfo::default();
    for line in out.lines() {
        let lower = line.to_lowercase();
        let after_colon = || line.split_once(':').map(|(_, a)| a.trim());
        if lower.contains("cycle count") {
            if let Some(a) = after_colon() {
                info.cycles = a.parse().unwrap_or(0);
            }
        }
        if lower.contains("condition") {
            if let Some(a) = after_colon() {
                info.health = a.to_string();
            }
        }
        if lower.contains("maximum capacity") {
            if let Some(a) = after_colon() {
                info.capacity = parse_percent_int(a);
            }
        }
    }
    info
}

/// Battery health read from `system_profiler SPPowerDataType -json` output — the JSON path digger
/// PREFERS over the TEXT one above (`getCachedSystemPowerData` tries JSON first, falls back to
/// TEXT only when JSON is empty/unparseable). This is not just a faster-but-equivalent parse of
/// the same field: verified live, on current macOS the JSON `sppower_battery_health` value
/// ("Good") and the TEXT rendering's `Condition:` line ("Normal") are DIFFERENT strings for the
/// SAME battery at the SAME instant. The golden's `batteries[0].health` is `"Good"`, which only
/// the JSON path produces — so this isn't an alternate implementation of
/// `parse_system_power_text`, it is the one the contract actually needs. Reads the first
/// `SPPowerDataType[]` entry with a `sppower_battery_health_info` object (there are several
/// sibling entries — AC settings, scheduled-wake events — that don't carry one) and accepts it
/// when health/cycles/capacity isn't all-empty, matching digger's `parseSystemPowerJSON`. `None`
/// when the JSON doesn't parse or no entry has a plausible reading.
pub fn parse_system_power_json(raw: &str) -> Option<SystemPowerInfo> {
    let doc = Json::parse(raw).ok()?;
    let entries = doc.get("SPPowerDataType")?.as_array()?;
    for entry in entries {
        let Some(info) = entry.get("sppower_battery_health_info") else {
            continue;
        };
        let health = info
            .get("sppower_battery_health")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        let cycles = info
            .get("sppower_battery_cycle_count")
            .and_then(Json::as_i64)
            .unwrap_or(0) as i32;
        let capacity = info
            .get("sppower_battery_health_maximum_capacity")
            .and_then(Json::as_str)
            .map(parse_percent_int)
            .unwrap_or(0);
        if !health.is_empty() || cycles > 0 || capacity > 0 {
            return Some(SystemPowerInfo {
                health,
                cycles,
                capacity,
            });
        }
    }
    None
}

/// Fan speed (RPM) from `system_profiler SPPowerDataType` TEXT output: the number on the first
/// line containing both "fan" and "speed" (case-insensitive), read as the token right after the
/// colon (stopping at the next space). Ported from digger's `collectThermal` (metrics_battery.go)
/// — its own fan LOOP, not a separate function there, pulled out here so it's independently
/// testable. 0 when no such line is present, which is true of every Apple Silicon Mac available
/// while writing this (the golden's own `fan_speed` is 0). digger never computes `fan_count` at
/// all — it stays its Go zero value unconditionally — so there is no equivalent parser for it;
/// the collector hardcodes 0 for the same reason digger does: nothing produces another number.
pub fn parse_fan_speed(out: &str) -> i32 {
    for line in out.lines() {
        let lower = line.to_lowercase();
        if lower.contains("fan") && lower.contains("speed") {
            if let Some((_, after)) = line.split_once(':') {
                let num_str = after.trim().split(' ').next().unwrap_or("");
                if let Ok(v) = num_str.parse::<i32>() {
                    return v;
                }
            }
        }
    }
    0
}

/// One `pmset -g batt` battery line: the live percent/status/remaining-time, before the separate
/// cycle-count/capacity/health context (a different command's output — see `collect::
/// collect_batteries`) is merged in. Ported from digger's `parsePMSet` (metrics_battery.go) minus
/// its health/cycles/capacity parameters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PmsetReading {
    pub percent: f64,
    pub status: String,
    pub time_left: String,
}

/// Parse `pmset -g batt` output into one reading per battery line (lines containing a `%`).
/// `time_left` is scraped once from whichever line contains the word "remaining" (the token right
/// before it) and applied to every reading, matching digger exactly — on a machine with more than
/// one battery line the single parsed remaining-time would be shared across all of them the same
/// way. A line with no parseable `N%` token is skipped entirely (not pushed with a zero percent).
pub fn parse_pmset_batt(raw: &str) -> Vec<PmsetReading> {
    let mut out = Vec::new();
    let mut time_left = String::new();

    for line in raw.lines() {
        if line.contains("remaining") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            for (i, p) in parts.iter().enumerate() {
                if *p == "remaining" && i > 0 {
                    time_left = parts[i - 1].to_string();
                }
            }
        }

        if !line.contains('%') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let mut percent = 0.0f64;
        let mut found = false;
        let mut status = "Unknown".to_string();
        for (i, f) in fields.iter().enumerate() {
            if f.contains('%') {
                let value = f.trim_end_matches(';').trim_end_matches('%');
                if let Ok(p) = value.parse::<f64>() {
                    percent = p;
                    found = true;
                    if i + 1 < fields.len() {
                        status = fields[i + 1].trim_end_matches(';').to_string();
                    }
                }
                break;
            }
        }
        if !found {
            continue;
        }
        out.push(PmsetReading {
            percent,
            status,
            time_left: time_left.clone(),
        });
    }
    out
}

/// The value assigned to `"key"` on an `ioreg` line: `"key" = <value>`, stopping at the first
/// delimiter (`, } )` or whitespace) and stripping surrounding quotes. `None` when the key isn't on
/// the line, isn't followed by `=`, or has an empty value.
fn ioreg_value_for_key(line: &str, key: &str) -> Option<String> {
    let marker = format!("\"{key}\"");
    let rest = line.split_once(&marker)?.1.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=')?.trim_start_matches([' ', '\t']);
    if rest.is_empty() || rest.starts_with(',') {
        return None;
    }
    let end = rest
        .find([',', '}', ')', ' ', '\t', '\n', '\r'])
        .unwrap_or(rest.len());
    let value = rest[..end].trim_matches('"');
    (!value.is_empty()).then(|| value.to_string())
}

/// Battery health from `ioreg -rn AppleSmartBattery` output: cycle count and a health percentage
/// derived from DesignCapacity vs the NominalChargeCapacity (preferred) or AppleRawMaxCapacity.
/// Returns (cycles, health_percent). First plausible value for each key wins.
pub fn parse_apple_smart_battery_health(out: &str) -> (i32, i32) {
    let (mut cycles, mut design, mut nominal, mut raw_max) = (0i64, 0i64, 0i64, 0i64);
    let read =
        |line: &str, key: &str| ioreg_value_for_key(line, key).and_then(|r| r.parse::<i64>().ok());
    for line in out.lines() {
        let line = line.trim();
        if cycles == 0 {
            if let Some(v) = read(line, "CycleCount") {
                if v > 0 && v < 100_000 {
                    cycles = v;
                }
            }
        }
        if design == 0 {
            if let Some(v) = read(line, "DesignCapacity") {
                if v > 0 {
                    design = v;
                }
            }
        }
        if nominal == 0 {
            if let Some(v) = read(line, "NominalChargeCapacity") {
                if v > 0 {
                    nominal = v;
                }
            }
        }
        if raw_max == 0 {
            if let Some(v) = read(line, "AppleRawMaxCapacity") {
                if v > 0 {
                    raw_max = v;
                }
            }
        }
    }
    (
        cycles as i32,
        battery_health_percent(design, nominal, raw_max),
    )
}

/// Parse a float-valued ioreg field (`"key" = 3.5`).
fn parse_ioreg_float_value(line: &str, key: &str) -> Option<f64> {
    ioreg_value_for_key(line, key)?.parse::<f64>().ok()
}

/// Parse a signed-integer ioreg field as f64, handling the unsigned two's-complement quirk.
fn parse_ioreg_signed_number(line: &str, key: &str) -> Option<f64> {
    parse_ioreg_signed_integer(&ioreg_value_for_key(line, key)?).map(|v| v as f64)
}

/// Battery thermal + power readings from `ioreg -rn AppleSmartBattery`. All in real-world units:
/// °C and Watts. Distinct from the health score's CPU thermal — battery temperature never leaks
/// into CPU temp.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BatteryThermal {
    pub battery_temp: f64,  // °C
    pub adapter_power: f64, // W
    pub system_power: f64,  // W (mW/1000)
    pub battery_power: f64, // W, positive = discharging
}

/// Parse AppleSmartBattery thermal/power. Temperature is centi-°C (÷100 above 1000, else already
/// °C); adapter Watts come only from the normalized `AdapterDetails` (never `AppleRaw*`); system
/// and battery power are mW→W with sanity ranges; and when BatteryPower is absent it's derived from
/// Voltage × Amperage (signed mA — negative = discharging, so power stays positive on discharge).
pub fn parse_apple_smart_battery_thermal(out: &str) -> BatteryThermal {
    let mut t = BatteryThermal::default();
    let (mut voltage_mv, mut amperage_ma) = (0.0f64, 0.0f64);

    for line in out.lines() {
        let line = line.trim();

        if let Some(temp) = parse_ioreg_float_value(line, "Temperature") {
            if temp > 0.0 {
                t.battery_temp = if temp < 1000.0 { temp } else { temp / 100.0 };
            }
        }
        // Adapter watts: only the normalized AdapterDetails, and only the first one.
        if line.contains("\"AdapterDetails\"")
            && !line.contains("AppleRaw")
            && t.adapter_power == 0.0
        {
            if let Some(w) = parse_ioreg_float_value(line, "Watts") {
                if w > 0.0 {
                    t.adapter_power = w;
                }
            }
        }
        if let Some(mw) = parse_ioreg_float_value(line, "SystemPowerIn") {
            set_system_power_mw(&mut t, mw);
        }
        if t.system_power == 0.0 {
            if let Some(mw) = parse_ioreg_float_value(line, "SystemPower") {
                set_system_power_mw(&mut t, mw);
            }
        }
        if let Some(mw) = parse_ioreg_signed_number(line, "BatteryPower") {
            set_battery_power_mw(&mut t, mw);
        }
        if let Some(v) = parse_ioreg_float_value(line, "Voltage") {
            if v > 0.0 {
                voltage_mv = v;
            }
        }
        if let Some(v) = parse_ioreg_float_value(line, "AppleRawBatteryVoltage") {
            if v > 0.0 {
                voltage_mv = v;
            }
        }
        if let Some(a) = parse_ioreg_signed_number(line, "InstantAmperage") {
            if a != 0.0 {
                amperage_ma = a;
            }
        }
        if let Some(a) = parse_ioreg_signed_number(line, "Amperage") {
            if a != 0.0 && amperage_ma == 0.0 {
                amperage_ma = a;
            }
        }
    }

    // Fall back to V×I when BatteryPower wasn't reported directly.
    if t.battery_power == 0.0 && voltage_mv > 0.0 && amperage_ma != 0.0 {
        let watts = -(voltage_mv * amperage_ma) / 1_000_000.0;
        if watts > -200.0 && watts < 200.0 {
            t.battery_power = watts;
        }
    }
    t
}

fn set_system_power_mw(t: &mut BatteryThermal, power_mw: f64) {
    if (0.0..1_000_000.0).contains(&power_mw) {
        t.system_power = power_mw / 1000.0;
    }
}

fn set_battery_power_mw(t: &mut BatteryThermal, power_mw: f64) {
    if power_mw > -200_000.0 && power_mw < 200_000.0 {
        t.battery_power = power_mw / 1000.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_percent_rounds_and_clamps() {
        assert_eq!(battery_health_percent(10000, 8249, 0), 82); // 82.49 → 82
        assert_eq!(battery_health_percent(10000, 8250, 0), 83); // 82.5 → 83 (half away from zero)
        assert_eq!(battery_health_percent(10000, 12000, 0), 100); // clamp
        assert_eq!(battery_health_percent(0, 8000, 0), 0); // unknown design
        assert_eq!(battery_health_percent(10000, 0, 0), 0); // no capacity
        assert_eq!(battery_health_percent(10000, 0, 9000), 90); // falls back to raw_max
    }

    #[test]
    fn percent_int_tolerates_whitespace_and_suffix() {
        assert_eq!(parse_percent_int(" 82% "), 82);
        assert_eq!(parse_percent_int("100"), 100);
        assert_eq!(parse_percent_int("n/a"), 0);
        assert_eq!(parse_percent_int(""), 0);
    }

    #[test]
    fn ioreg_signed_integer_handles_twos_complement() {
        assert_eq!(parse_ioreg_signed_integer("42"), Some(42));
        assert_eq!(parse_ioreg_signed_integer("-7"), Some(-7));
        // u64 that fits i64.
        assert_eq!(
            parse_ioreg_signed_integer("9223372036854775807"),
            Some(i64::MAX)
        );
        // 0xFFFF...FFFF = -1 printed as unsigned two's complement.
        assert_eq!(parse_ioreg_signed_integer("18446744073709551615"), Some(-1));
        // 0xFFFF...FFF9 = -7.
        assert_eq!(parse_ioreg_signed_integer("18446744073709551609"), Some(-7));
        assert_eq!(parse_ioreg_signed_integer("not-a-number"), None);
    }

    #[test]
    fn system_power_text_reads_labelled_fields() {
        // Apple prints a non-breaking space before % — parse_percent_int must still yield 97.
        let raw = "    Battery Information:\n\n      Health Information:\n          Cycle Count: 12\n          Condition: Normal\n          Maximum Capacity: 97\u{00a0}%\n";
        assert_eq!(
            parse_system_power_text(raw),
            SystemPowerInfo {
                health: "Normal".into(),
                cycles: 12,
                capacity: 97
            }
        );
    }

    #[test]
    fn system_power_text_absent_fields_default_to_empty() {
        assert_eq!(
            parse_system_power_text("nothing here"),
            SystemPowerInfo::default()
        );
    }

    #[test]
    fn ioreg_value_for_key_extracts_and_stops_at_delimiter() {
        assert_eq!(
            ioreg_value_for_key("  \"CycleCount\" = 250", "CycleCount"),
            Some("250".into())
        );
        assert_eq!(
            ioreg_value_for_key("\"Serial\" = \"ABC123\",", "Serial"),
            Some("ABC123".into())
        );
        assert_eq!(ioreg_value_for_key("\"X\" = 5", "Y"), None); // key absent
        assert_eq!(ioreg_value_for_key("\"X\" 5", "X"), None); // no '='
    }

    #[test]
    fn apple_smart_battery_prefers_nominal_charge() {
        let out = "\n  | |   \"DesignCapacity\" = 10000\n  | |   \"AppleRawMaxCapacity\" = 7800\n  | |   \"NominalChargeCapacity\" = 8300\n  | |   \"CycleCount\" = 250\n";
        assert_eq!(parse_apple_smart_battery_health(out), (250, 83));
    }

    #[test]
    fn apple_smart_battery_falls_back_to_raw_max() {
        let out = "\n  | |   \"DesignCapacity\" = 10000\n  | |   \"AppleRawMaxCapacity\" = 7800\n  | |   \"CycleCount\" = 12\n";
        assert_eq!(parse_apple_smart_battery_health(out), (12, 78));
    }

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.001
    }

    #[test]
    fn thermal_reads_temp_power_and_adapter() {
        let out = "\n  | |   \"Temperature\" = 3055\n  | |   \"SystemPowerIn\" = 19967\n  | |   \"BatteryPower\" = 13654\n  | |   \"AdapterDetails\" = {\"Watts\" = 96}\n";
        let t = parse_apple_smart_battery_thermal(out);
        assert!(approx(t.battery_temp, 30.55), "{}", t.battery_temp); // centi-°C ÷100
        assert!(approx(t.system_power, 19.967), "{}", t.system_power); // mW → W
        assert_eq!(t.adapter_power, 96.0);
        assert!(approx(t.battery_power, 13.654), "{}", t.battery_power);
    }

    #[test]
    fn thermal_two_complement_battery_power() {
        let t =
            parse_apple_smart_battery_thermal("\n  | |   \"BatteryPower\"=18446744073709539271\n");
        assert!(approx(t.battery_power, -12.345), "{}", t.battery_power);
    }

    #[test]
    fn thermal_derives_watts_from_voltage_and_amperage() {
        // 12000 mV × -1500 mA → -(V·I)/1e6 = 18 W (discharge stays positive).
        let t = parse_apple_smart_battery_thermal(
            "\n  | |   \"Voltage\" = 12000\n  | |   \"InstantAmperage\" = -1500\n",
        );
        assert!(approx(t.battery_power, 18.0), "{}", t.battery_power);
    }

    #[test]
    fn thermal_ignores_raw_adapter_watts() {
        let out = "\n  | |   \"AppleRawAdapterDetails\" = {\"Watts\" = 140}\n  | |   \"AdapterDetails\" = {\"Watts\" = 96}\n";
        assert_eq!(parse_apple_smart_battery_thermal(out).adapter_power, 96.0);
    }
}
