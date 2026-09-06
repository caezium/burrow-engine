//! System health score — ported verbatim from digger's `cmd/status/metrics_health.go`.
//!
//! A pure function of already-collected metrics: start at 100, subtract weighted penalties for CPU,
//! memory (+ pressure), disk, thermal, disk-IO, battery wear, and long uptime, clamp to [0,100],
//! and build a banded message ("Excellent"/"Good"/"Fair"/"Needs Attention") with the specific
//! issues appended. The `colorizeTemp`/view helpers in the Go file are TUI-only and not ported.

use std::fmt::Write as _;

// Weights.
const CPU_WEIGHT: f64 = 30.0;
const MEM_WEIGHT: f64 = 25.0;
const DISK_WEIGHT: f64 = 20.0;
const THERMAL_WEIGHT: f64 = 15.0;
const IO_WEIGHT: f64 = 10.0;

// CPU (%).
const CPU_NORMAL: f64 = 50.0;
const CPU_HIGH: f64 = 85.0;

// Memory (%).
const MEM_NORMAL: f64 = 70.0;
const MEM_HIGH: f64 = 88.0;
const MEM_PRESSURE_WARN_PENALTY: f64 = 5.0;
const MEM_PRESSURE_CRIT_PENALTY: f64 = 15.0;

// Disk (%).
const DISK_WARN: f64 = 80.0;
const DISK_CRIT: f64 = 93.0;

// Thermal (°C).
const THERMAL_NORMAL: f64 = 65.0;
const THERMAL_HIGH: f64 = 85.0;

// Disk IO (MB/s).
const IO_NORMAL: f64 = 50.0;
const IO_HIGH: f64 = 150.0;

// Battery.
const BATTERY_CYCLE_WARN: i64 = 800;
const BATTERY_CYCLE_DANGER: i64 = 900;
const BATTERY_CAP_WARN: i64 = 80;
const BATTERY_CAP_DANGER: i64 = 60;

// Uptime (seconds).
const UPTIME_WARN_SECS: u64 = 7 * 86_400;
const UPTIME_DANGER_SECS: u64 = 14 * 86_400;

// Score display bands.
const SCORE_EXCELLENT: i32 = 85;
const SCORE_GOOD: i32 = 65;
const SCORE_FAIR: i32 = 45;

/// The metric fields the health score reads. Subsets of digger's full status structs — the rest of
/// each is filled in as the native collectors are ported. `Default` gives the "healthy" baseline.
#[derive(Debug, Clone, Default)]
pub struct CpuStatus {
    pub usage: f64,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryStatus {
    pub used_percent: f64,
    /// "normal" | "warn" | "critical" (empty treated as normal).
    pub pressure: String,
}

#[derive(Debug, Clone, Default)]
pub struct DiskStatus {
    pub used_percent: f64,
}

#[derive(Debug, Clone, Default)]
pub struct DiskIoStatus {
    pub read_rate: f64,
    pub write_rate: f64,
}

#[derive(Debug, Clone, Default)]
pub struct ThermalStatus {
    pub cpu_temp: f64,
}

#[derive(Debug, Clone, Default)]
pub struct BatteryStatus {
    pub cycle_count: i64,
    pub capacity: i64,
}

/// Compute the 0-100 health score and its banded message. Pure.
pub fn calculate_health_score(
    cpu: &CpuStatus,
    mem: &MemoryStatus,
    disks: &[DiskStatus],
    disk_io: &DiskIoStatus,
    thermal: &ThermalStatus,
    batteries: &[BatteryStatus],
    uptime_secs: u64,
) -> (i32, String) {
    let mut score = 100.0f64;
    let mut issues: Vec<&str> = Vec::new();

    // CPU penalty.
    if cpu.usage > CPU_NORMAL {
        score -= if cpu.usage > CPU_HIGH {
            CPU_WEIGHT * (cpu.usage - CPU_NORMAL) / CPU_HIGH
        } else {
            (CPU_WEIGHT / 2.0) * (cpu.usage - CPU_NORMAL) / (CPU_HIGH - CPU_NORMAL)
        };
    }
    if cpu.usage > CPU_HIGH {
        issues.push("High CPU");
    }

    // Memory penalty.
    if mem.used_percent > MEM_NORMAL {
        score -= if mem.used_percent > MEM_HIGH {
            MEM_WEIGHT * (mem.used_percent - MEM_NORMAL) / MEM_NORMAL
        } else {
            (MEM_WEIGHT / 2.0) * (mem.used_percent - MEM_NORMAL) / (MEM_HIGH - MEM_NORMAL)
        };
    }
    if mem.used_percent > MEM_HIGH {
        issues.push("High Memory");
    }

    // Memory pressure penalty.
    match mem.pressure.as_str() {
        "warn" => {
            score -= MEM_PRESSURE_WARN_PENALTY;
            issues.push("Memory Pressure");
        }
        "critical" => {
            score -= MEM_PRESSURE_CRIT_PENALTY;
            issues.push("Critical Memory");
        }
        _ => {}
    }

    // Disk penalty (primary disk only).
    if let Some(disk) = disks.first() {
        let usage = disk.used_percent;
        if usage > DISK_WARN {
            score -= if usage > DISK_CRIT {
                DISK_WEIGHT * (usage - DISK_WARN) / (100.0 - DISK_WARN)
            } else {
                (DISK_WEIGHT / 2.0) * (usage - DISK_WARN) / (DISK_CRIT - DISK_WARN)
            };
        }
        if usage > DISK_CRIT {
            issues.push("Disk Almost Full");
        }
    }

    // Thermal penalty. (digger guards `CPUTemp > 0` for "has a reading" first, but the normal
    // threshold of 65 already implies it, so the penalty condition is just `> THERMAL_NORMAL`.)
    if thermal.cpu_temp > THERMAL_NORMAL {
        if thermal.cpu_temp > THERMAL_HIGH {
            score -= THERMAL_WEIGHT;
            issues.push("Overheating");
        } else {
            score -= THERMAL_WEIGHT * (thermal.cpu_temp - THERMAL_NORMAL)
                / (THERMAL_HIGH - THERMAL_NORMAL);
        }
    }

    // Disk IO penalty.
    let total_io = disk_io.read_rate + disk_io.write_rate;
    if total_io > IO_NORMAL {
        if total_io > IO_HIGH {
            score -= IO_WEIGHT;
            issues.push("Heavy Disk IO");
        } else {
            score -= IO_WEIGHT * (total_io - IO_NORMAL) / (IO_HIGH - IO_NORMAL);
        }
    }

    // Battery wear penalty (primary battery only).
    if let Some(b) = batteries.first() {
        match battery_health_label(b.cycle_count, b.capacity).1 {
            "danger" => {
                score -= 5.0;
                issues.push("Battery Service Soon");
            }
            "warn" => score -= 2.0,
            _ => {}
        }
    }

    // Uptime penalty (long uptime without restart).
    if uptime_secs > UPTIME_DANGER_SECS {
        score -= 3.0;
        issues.push("Restart Recommended");
    } else if uptime_secs > UPTIME_WARN_SECS {
        score -= 1.0;
    }

    let score = score.clamp(0.0, 100.0) as i32; // truncates toward zero, like Go's int(...)

    let mut msg = match score {
        s if s >= SCORE_EXCELLENT => "Excellent",
        s if s >= SCORE_GOOD => "Good",
        s if s >= SCORE_FAIR => "Fair",
        _ => "Needs Attention",
    }
    .to_string();
    if !issues.is_empty() {
        let _ = write!(msg, ": {}", issues.join(", "));
    }
    (score, msg)
}

/// Human-readable battery label + severity ("ok" | "warn" | "danger") from cycle count and
/// maximum-capacity percentage (capacity 0 means unknown → ignored).
pub fn battery_health_label(cycles: i64, capacity: i64) -> (&'static str, &'static str) {
    if cycles > BATTERY_CYCLE_DANGER || (capacity > 0 && capacity < BATTERY_CAP_DANGER) {
        return ("Service Soon", "danger");
    }
    if cycles > BATTERY_CYCLE_WARN || (capacity > 0 && capacity < BATTERY_CAP_WARN) {
        return ("Fair", "warn");
    }
    ("Healthy", "ok")
}

/// Uptime severity: "danger" past 14 days, "warn" past 7, else "ok".
pub fn uptime_severity(secs: u64) -> &'static str {
    if secs > UPTIME_DANGER_SECS {
        "danger"
    } else if secs > UPTIME_WARN_SECS {
        "warn"
    } else {
        "ok"
    }
}

/// Compact uptime: `2d 3h` past a day, `1h 2m` past an hour, else `5m`.
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m")
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::type_complexity)] // compact table-driven test helpers
mod tests {
    use super::*;

    fn score(
        cpu: f64,
        mem: f64,
        pressure: &str,
        disks: &[f64],
        io: (f64, f64),
        temp: f64,
        batts: &[(i64, i64)],
        uptime: u64,
    ) -> (i32, String) {
        let disks: Vec<DiskStatus> = disks
            .iter()
            .map(|&d| DiskStatus { used_percent: d })
            .collect();
        let batts: Vec<BatteryStatus> = batts
            .iter()
            .map(|&(c, cap)| BatteryStatus {
                cycle_count: c,
                capacity: cap,
            })
            .collect();
        calculate_health_score(
            &CpuStatus { usage: cpu },
            &MemoryStatus {
                used_percent: mem,
                pressure: pressure.into(),
            },
            &disks,
            &DiskIoStatus {
                read_rate: io.0,
                write_rate: io.1,
            },
            &ThermalStatus { cpu_temp: temp },
            &batts,
            uptime,
        )
    }

    #[test]
    fn perfect_is_100_excellent() {
        let (s, m) = score(10.0, 20.0, "normal", &[30.0], (5.0, 5.0), 40.0, &[], 0);
        assert_eq!(s, 100);
        assert_eq!(m, "Excellent");
    }

    #[test]
    fn detects_issues_under_load() {
        let (s, m) = score(95.0, 95.0, "critical", &[98.0], (120.0, 80.0), 90.0, &[], 0);
        assert!(s < 60, "heavy load should drop the score, got {s}");
        assert_ne!(m, "Excellent");
        assert!(m.contains("High CPU"), "{m}");
        assert!(m.contains("Disk Almost Full"), "{m}");
    }

    #[test]
    fn edge_case_ranges_match_digger() {
        // (cpu, mem, pressure, disks, io, temp, min, max)
        let cases: &[(f64, f64, &str, &[f64], (f64, f64), f64, i32, i32)] = &[
            (50.0, 70.0, "", &[80.0], (25.0, 25.0), 65.0, 95, 100),
            (10.0, 40.0, "warn", &[40.0], (5.0, 5.0), 40.0, 90, 100),
            (10.0, 30.0, "", &[], (5.0, 5.0), 40.0, 95, 100), // empty disks
            (10.0, 30.0, "", &[40.0], (5.0, 5.0), 0.0, 95, 100), // zero thermal
        ];
        for &(cpu, mem, p, d, io, t, lo, hi) in cases {
            let (s, _) = score(cpu, mem, p, d, io, t, &[], 0);
            assert!(
                (lo..=hi).contains(&s),
                "score {s} out of [{lo},{hi}] for cpu={cpu}"
            );
        }
    }

    #[test]
    fn battery_and_uptime_penalize() {
        let perfect = score(10.0, 20.0, "", &[30.0], (5.0, 5.0), 40.0, &[], 0).0;
        let old_batt = score(10.0, 20.0, "", &[30.0], (5.0, 5.0), 40.0, &[(950, 75)], 0).0;
        let long_up = score(10.0, 20.0, "", &[30.0], (5.0, 5.0), 40.0, &[], 15 * 86_400).0;
        assert!(old_batt < perfect, "old battery reduces score");
        assert!(long_up < perfect, "long uptime reduces score");
    }

    #[test]
    fn battery_health_label_matches_digger() {
        assert_eq!(battery_health_label(100, 98), ("Healthy", "ok"));
        assert_eq!(battery_health_label(600, 92), ("Healthy", "ok"));
        assert_eq!(battery_health_label(950, 85), ("Service Soon", "danger"));
        assert_eq!(battery_health_label(200, 55), ("Service Soon", "danger"));
        assert_eq!(battery_health_label(200, 75), ("Fair", "warn"));
        assert_eq!(battery_health_label(0, 0), ("Healthy", "ok"));
    }

    #[test]
    fn uptime_severity_matches_digger() {
        assert_eq!(uptime_severity(3600), "ok");
        assert_eq!(uptime_severity(6 * 86_400), "ok");
        assert_eq!(uptime_severity(8 * 86_400), "warn");
        assert_eq!(uptime_severity(15 * 86_400), "danger");
    }

    #[test]
    fn format_uptime_matches_digger() {
        let cases: &[(u64, &str)] = &[
            (0, "0m"),
            (59, "0m"),
            (60, "1m"),
            (65, "1m"),
            (3599, "59m"),
            (3600, "1h 0m"),
            (3720, "1h 2m"),
            (86_400, "1d 0h"),
            (90_000, "1d 1h"),
            (172_800, "2d 0h"),
            (86_400 * 2 + 3600 * 3 + 60 * 5, "2d 3h"),
            (31_536_000, "365d 0h"),
        ];
        for &(secs, want) in cases {
            assert_eq!(format_uptime(secs), want, "format_uptime({secs})");
        }
    }
}
