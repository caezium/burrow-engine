//! Metric collectors — the IO half of `status`, run the system command and feed a ported parser.
//!
//! This is the engine's answer to gopsutil while honoring the crate's zero-dependency rule: rather
//! than an FFI/`libc` dep, each collector shells out to the same tool digger used (scutil, ioreg,
//! system_profiler, ps, diskutil, df, …) and parses the output with the pure functions already in
//! this module. The command-running is a thin, side-effecting shell; the DECISION logic is factored
//! out as pure, injectable functions so it stays unit-tested without spawning anything.

use super::battery::{
    parse_apple_smart_battery_health, parse_apple_smart_battery_thermal, parse_fan_speed,
    parse_pmset_batt, parse_system_power_json, parse_system_power_text, BatteryThermal,
    SystemPowerInfo,
};
use super::bluetooth::{match_digger_connected_state, parse_sp_bluetooth_json, BluetoothDevice};
use super::disk::{apply_fstypes, parse_df_k, parse_mount_fstypes, DiskUsage};
use super::gpu::{parse_sp_displays_json, GpuInfo};
use super::network::{
    collect_proxy_from_env, collect_proxy_from_scutil_output, collect_proxy_from_tun_interfaces,
    parse_netstat_ib, NetInterface, ProxyStatus,
};
use super::process::{parse_process_output, parse_ps_aux_output, ProcessInfo};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// The shell-out primitives — `run_command`, `run_command_with_timeout`, `run_command_checked`
// and `CommandFailure` — live in `crate::platform` (BUR-126: they are process plumbing, not a
// status metric) and are re-exported here for the collectors and the callers that grew up
// naming them through this module.
pub use crate::platform::{
    run_command, run_command_checked, run_command_with_timeout, CommandFailure,
};

/// Resolve the active proxy from already-collected inputs, in digger's exact precedence order
/// (`metrics_network.go::collectProxy`): environment variables FIRST, then the system config
/// (`scutil --proxy`), then an active `utun`/`tun` interface as a last resort. Pure + injectable
/// (env, scutil output, and the interface list are all passed in) so it's testable without running
/// scutil, netstat, or touching the real environment.
///
/// FIX 3 (RULEBOOK): this used to check scutil FIRST, which is backwards — a `HTTPS_PROXY` env var
/// a user actually set can be shadowed by an unrelated system config entry that merely happens to
/// be enabled. Measured live: `HTTPS_PROXY` set in the environment AND scutil reporting
/// `HTTPSEnable:1` at the same instant produced oracle `type:"HTTP"` (env) vs this engine's
/// pre-fix `type:"HTTPS"` (scutil) — a real, reproducible divergence, not a hypothetical one.
pub fn resolve_proxy(
    scutil_output: Option<&str>,
    getenv: impl Fn(&str) -> String,
    tun_interfaces: &[NetInterface],
) -> ProxyStatus {
    let from_env = collect_proxy_from_env(getenv);
    if from_env.enabled {
        return from_env;
    }
    if let Some(out) = scutil_output {
        let sys = collect_proxy_from_scutil_output(out);
        if sys.enabled {
            return sys;
        }
    }
    collect_proxy_from_tun_interfaces(tun_interfaces)
}

/// Collect the active proxy on this machine: environment, then `scutil --proxy` (macOS), then
/// active `utun`/`tun` interfaces. `net_interfaces` is the ALREADY-COLLECTED, unfiltered netstat
/// read (`collect_net_interfaces`'s result) — passed in rather than re-shelling-out, since the TUN
/// fallback needs exactly the same data `network[]` collection already fetched (see
/// `network::collect_proxy_from_tun_interfaces`'s doc comment for why it must be the unfiltered
/// list, not the noise-filtered `network[]` display array).
pub fn collect_proxy(net_interfaces: &[NetInterface]) -> ProxyStatus {
    let scutil = if cfg!(target_os = "macos") {
        // 500ms, matching digger's own `collectProxy` (`metrics_network.go:170`).
        run_command_with_timeout("scutil", &["--proxy"], Duration::from_millis(500))
    } else {
        None
    };
    resolve_proxy(
        scutil.as_deref(),
        |k| std::env::var(k).unwrap_or_default(),
        net_interfaces,
    )
}

/// Boot time (unix seconds) from `sysctl -n kern.boottime` output: `{ sec = 1699999999, usec = … }`.
/// Pure. The first `sec =` is the boot second (it precedes `usec =`), so the substring match is safe.
pub fn parse_boottime_secs(sysctl_output: &str) -> Option<u64> {
    let after = sysctl_output.split("sec =").nth(1)?;
    let digits: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Uptime, from an injected boot time and current unix time — pure so it's testable. Clamps to 0 if
/// the clock is behind boot (shouldn't happen).
pub fn uptime_secs_from(now_unix: u64, boottime: Option<u64>) -> u64 {
    now_unix.saturating_sub(boottime.unwrap_or(now_unix))
}

/// Collect system uptime in seconds: `sysctl -n kern.boottime` vs the wall clock.
///
/// digger reads boot time via gopsutil's `host.Info()` syscall, so there's no `context.WithTimeout`
/// to port for this specific shell-out; 500ms matches the one sysctl-family call the original DOES
/// bound this way (`getCoreTopology`, `metrics_cpu.go:130`) — the same "fast local kernel read"
/// class of command.
pub fn collect_uptime_secs() -> u64 {
    collect_uptime_secs_checked().unwrap_or(0)
}

/// [`collect_uptime_secs`], keeping the reason it failed — one of the four inputs the health score
/// is computed from, so `status` has to be able to say "not measured" instead of `0`.
///
/// `Exited(None)` stands in for "`sysctl` ran and its output was not a boot time we could parse":
/// there is no exit code involved, but the program plainly did run, so reporting it as unspawnable
/// would be a worse lie than reporting it as a run that did not answer.
pub fn collect_uptime_secs_checked() -> Result<u64, CommandFailure> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out = run_command_checked(
        "sysctl",
        &["-n", "kern.boottime"],
        Duration::from_millis(500),
    )?;
    let boot = parse_boottime_secs(&out).ok_or(CommandFailure::Exited(None))?;
    Ok(uptime_secs_from(now, Some(boot)))
}

/// Memory pressure level from `memory_pressure` output: "critical" | "warn" | "normal", or "" when
/// none is present. Order matters (critical before warn before normal). Pure.
pub fn parse_memory_pressure(output: &str) -> String {
    let lower = output.to_lowercase();
    for level in ["critical", "warn", "normal"] {
        if lower.contains(level) {
            return level.to_string();
        }
    }
    String::new()
}

/// File-backed (cached) memory in bytes from `vm_stat` output: page size comes from the first line
/// (`page size of N bytes`, default 4096), then `File-backed pages: N.` × page size. macOS reports 0
/// for gopsutil's Cached, so this fills it in. Pure. 0 when the field is absent.
pub fn parse_file_backed_bytes(vm_stat: &str) -> u64 {
    let mut page_size = 4096u64;
    for (i, line) in vm_stat.lines().enumerate() {
        if i == 0 {
            if let Some((_, after)) = line.split_once("page size of ") {
                if let Some((before, _)) = after.split_once(" bytes") {
                    if let Ok(sz) = before.trim().parse::<u64>() {
                        page_size = sz;
                    }
                }
            }
        }
        if line.contains("File-backed pages:") {
            if let Some((_, after)) = line.split_once(':') {
                if let Ok(pages) = after.trim().trim_end_matches('.').parse::<u64>() {
                    return pages * page_size;
                }
            }
        }
    }
    0
}

/// Battery readings derived from one `ioreg -rn AppleSmartBattery` dump — cycle count, health
/// percentage, and thermal/power — by feeding the already-ported parsers. Pure.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BatteryReadings {
    pub cycles: i32,
    pub capacity: i32,
    pub thermal: BatteryThermal,
}

pub fn battery_from_ioreg(ioreg: &str) -> BatteryReadings {
    let (cycles, capacity) = parse_apple_smart_battery_health(ioreg);
    BatteryReadings {
        cycles,
        capacity,
        thermal: parse_apple_smart_battery_thermal(ioreg),
    }
}

/// Collect battery health + thermal from a single `ioreg -rn AppleSmartBattery` call (macOS only;
/// `None` off macOS, when there's no battery, ioreg fails, or it doesn't finish within 500ms —
/// matching digger's own `getAppleSmartBatteryHealthData` / `collectThermal`, both of which bound
/// the identical `ioreg -rn AppleSmartBattery` call at 500ms, `metrics_battery.go:222` and `:364`).
pub fn collect_battery() -> Option<BatteryReadings> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    run_command_with_timeout(
        "ioreg",
        &["-rn", "AppleSmartBattery"],
        Duration::from_millis(500),
    )
    .map(|o| battery_from_ioreg(&o))
}

/// Battery health text/cycles/capacity from `system_profiler SPPowerDataType`: JSON preferred,
/// falling back to TEXT only when JSON fails to parse or produces no plausible reading. Ported from
/// digger's `getCachedSystemPowerData` (minus its 30s cache — this engine is one-shot, so there's
/// nothing to cache across). See `parse_system_power_json`'s doc comment for why JSON isn't simply
/// interchangeable with the TEXT parse below it — on current macOS they can disagree.
pub fn collect_battery_health() -> SystemPowerInfo {
    // 3s for both calls, matching digger's `getSystemPowerJSONOutput` / `getSystemPowerOutput`
    // (`metrics_battery.go:306` and `:330`) — the same `system_profiler SPPowerDataType` command,
    // JSON then text, at the same budget.
    if let Some(json) = run_command_with_timeout(
        "system_profiler",
        &["SPPowerDataType", "-json"],
        Duration::from_secs(3),
    ) {
        if let Some(info) = parse_system_power_json(&json) {
            return info;
        }
    }
    run_command_with_timeout(
        "system_profiler",
        &["SPPowerDataType"],
        Duration::from_secs(3),
    )
    .as_deref()
    .map(parse_system_power_text)
    .unwrap_or_default()
}

/// Merge `system_profiler`-sourced cycles/capacity with `ioreg`-sourced ones: ioreg wins whenever
/// it has a positive reading, `system_profiler`'s is the fallback. Health stays `system_profiler`'s
/// always — `ioreg -rn AppleSmartBattery` doesn't carry a health-condition label at all. Ported
/// from digger's `mergeBatteryHealthData`. Pure.
fn merge_battery_counts(
    sp_cycles: i32,
    sp_capacity: i32,
    ioreg_cycles: i32,
    ioreg_capacity: i32,
) -> (i32, i32) {
    let cycles = if ioreg_cycles > 0 {
        ioreg_cycles
    } else {
        sp_cycles
    };
    let capacity = if ioreg_capacity > 0 {
        ioreg_capacity
    } else {
        sp_capacity
    };
    (cycles, capacity)
}

/// One `batteries[]` row: `pmset`'s live percent/status/time_left plus the merged health context.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BatteryEntry {
    pub percent: f64,
    pub status: String,
    pub time_left: String,
    pub health: String,
    pub cycle_count: i32,
    pub capacity: i32,
}

/// Collect the `batteries[]` array: `pmset -g batt` for the live reading(s), `ioreg`'s
/// cycle/capacity (from `ioreg_reading`, the SAME `BatteryReadings` already spent on `thermal`'s
/// battery_temp/power — no second `ioreg -rn AppleSmartBattery` spawn) preferred over
/// `system_profiler`'s, and the health label always from `system_profiler`. Empty — not a sentinel
/// row — when `pmset` reports nothing: digger's own `collectBatteries` returns `nil` cleanly on a
/// battery-less Mac, no fake entry invented to fill the pane.
pub fn collect_batteries(ioreg_reading: Option<&BatteryReadings>) -> Vec<BatteryEntry> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    // digger's own `collectBatteries` (`metrics_battery.go:38`) calls this SAME `pmset -g batt`
    // with `context.Background()` — i.e. no timeout at all, not even an unported one. That's not a
    // budget to match; treat it like the other no-Go-equivalent calls below and pick a bound of our
    // own. `pmset` is a simple IOKit power-state query with no network/disk I/O, so 2s is generous
    // headroom over its normal near-instant cost while still closing off the "hangs forever"
    // failure mode the original leaves open.
    let Some(pmset_out) =
        run_command_with_timeout("pmset", &["-g", "batt"], Duration::from_secs(2))
    else {
        return Vec::new();
    };
    let readings = parse_pmset_batt(&pmset_out);
    if readings.is_empty() {
        return Vec::new();
    }
    let sp = collect_battery_health();
    let (ioreg_cycles, ioreg_capacity) = ioreg_reading
        .map(|r| (r.cycles, r.capacity))
        .unwrap_or((0, 0));
    let (cycles, capacity) =
        merge_battery_counts(sp.cycles, sp.capacity, ioreg_cycles, ioreg_capacity);
    readings
        .into_iter()
        .map(|r| BatteryEntry {
            percent: r.percent,
            status: r.status,
            time_left: r.time_left,
            health: sp.health.clone(),
            cycle_count: cycles,
            capacity,
        })
        .collect()
}

/// Fan speed (RPM) via a dedicated `system_profiler SPPowerDataType` TEXT call — the JSON variant
/// `collect_battery_health` prefers doesn't carry fan data at all. Independent of the
/// battery-health call: a Mac with no battery still has fans. 0 off macOS or on failure (also the
/// honest, and currently the ONLY observed, value on Apple Silicon — see `parse_fan_speed`'s docs).
pub fn collect_fan_speed() -> i32 {
    if !cfg!(target_os = "macos") {
        return 0;
    }
    // 3s, same command + budget as `collect_battery_health`'s text call (`metrics_battery.go:330`).
    run_command_with_timeout(
        "system_profiler",
        &["SPPowerDataType"],
        Duration::from_secs(3),
    )
    .as_deref()
    .map(parse_fan_speed)
    .unwrap_or(0)
}

/// Collect the `gpu[]` array: `system_profiler -json SPDisplaysDataType`, parsed for static
/// identity (`usage` always -1 — see the `gpu` module docs for why this collector never invokes
/// `powermetrics` itself). Empty off macOS. digger's own GPU field is never an empty array on
/// macOS, so this collector isn't either — but it has TWO distinct sentinels for two distinct
/// failures, matching digger exactly (previously this collapsed both into one):
///  - The command itself fails to run at all: digger's `readMacGPUInfo` returns an error, its
///    caller's `cachedGPU` stays empty, and `collectGPU` falls through PAST the darwin-only static-
///    info block to the generic (non-macOS) path — which finds no `nvidia-smi` on a Mac and returns
///    THIS text, with `Usage` at Go's zero-value (`0`), not `-1`.
///  - The command succeeds but nothing parses (no displays / unexpected JSON): THIS is
///    `readMacGPUInfo`'s own internal sentinel, `usage: -1` ("will be updated with real-time data",
///    a promise this engine deliberately doesn't keep — see the module docs above).
pub fn collect_gpu() -> Vec<GpuInfo> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    // 4s, matching digger's `systemProfilerTimeout` (`metrics_gpu.go:15`, used by `readMacGPUInfo`
    // for this exact command at `metrics_gpu.go:95`).
    let Some(out) = run_command_with_timeout(
        "system_profiler",
        &["-json", "SPDisplaysDataType"],
        Duration::from_secs(4),
    ) else {
        return vec![GpuInfo {
            name: "No GPU metrics available".to_string(),
            usage: 0.0,
            note: "Install nvidia-smi or use platform-specific metrics".to_string(),
            ..Default::default()
        }];
    };
    let gpus = parse_sp_displays_json(&out);
    if gpus.is_empty() {
        return vec![GpuInfo {
            name: "GPU info unavailable".to_string(),
            usage: -1.0,
            note: "Unable to parse system_profiler output".to_string(),
            ..Default::default()
        }];
    }
    gpus
}

/// Collect the `bluetooth[]` array: `system_profiler -json SPBluetoothDataType`. Empty off macOS;
/// a single "No Bluetooth info" sentinel row (ported verbatim from digger's own `collectBluetooth`
/// fallback text) when the command fails or the machine has no Bluetooth controller at all —
/// digger's own Bluetooth field is never an empty array, so this collector isn't either.
pub fn collect_bluetooth() -> Vec<BluetoothDevice> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let sentinel = || {
        vec![BluetoothDevice {
            name: "No Bluetooth info".to_string(),
            connected: false,
            battery: String::new(),
        }]
    };
    // 4s, matching digger's `systemProfilerTimeout` (`metrics_gpu.go:15`, shared package-wide and
    // used for this exact command at `metrics_bluetooth.go:45`).
    let Some(out) = run_command_with_timeout(
        "system_profiler",
        &["-json", "SPBluetoothDataType"],
        Duration::from_secs(4),
    ) else {
        return sentinel();
    };
    let devices = parse_sp_bluetooth_json(&out);
    if devices.is_empty() {
        return sentinel();
    }
    // FIX 5 (RULEBOOK, adjudicated — port the miss): match digger's own always-`false` `connected`
    // state rather than this engine's more-correct JSON-derived one — see
    // `bluetooth::match_digger_connected_state`'s doc comment for why.
    match_digger_connected_state(devices)
}

/// Collect real local disk usage: `df -kl` for sizes, `mount` for filesystem types, then drop the
/// pseudo/network/FUSE volumes. Empty when `df` can't run.
///
/// The `-l` (lowercase L, "local only") flag is load-bearing, not cosmetic: digger only ever calls
/// `disk.Usage()` — the stat that can hang on a slow/unresponsive mount — for partitions that
/// ALREADY survived `shouldSkipDiskPartition`'s network/FUSE filters. This engine's `df -k` used to
/// stat EVERY mount, filtering only afterward, so a hung network share would hang `df` itself
/// before the filter ever got a chance to drop it — the same class of bug RULEBOOK §3d documents
/// for unflagged `netstat`. `-l` restricts `df` to local filesystems at the command level, closing
/// this without changing which LOCAL disks are ever reported (the fstype/mountpoint filters still
/// run afterward, unchanged).
pub fn collect_disks() -> Vec<DiskUsage> {
    collect_disks_checked().unwrap_or_default()
}

/// [`collect_disks`], keeping the reason `df` failed — one of the four health-score inputs.
///
/// Only `df` is checked. `mount` supplies fstype LABELS for disks `df` already found, so losing it
/// costs an annotation rather than the reading itself, and treating that as "disks were not
/// measured" would report a failure where there is real data.
pub fn collect_disks_checked() -> Result<Vec<DiskUsage>, CommandFailure> {
    // digger reads this via gopsutil's `disk.Partitions()`/`disk.Usage()` syscalls, so there's no
    // `context.WithTimeout` to port for either `df` or `mount`. Both are local-filesystem-only
    // reads (the `-l` above already restricts `df` to what survived the network/FUSE filter, per
    // this function's own doc comment) and normally complete in well under 100ms; 3s is a generous
    // bound in the same tier as this file's other "moderate local command" budgets.
    let df = run_command_checked("df", &["-kl"], Duration::from_secs(3))?;
    let fstypes = run_command_with_timeout("mount", &[], Duration::from_secs(3))
        .map(|m| parse_mount_fstypes(&m))
        .unwrap_or_default();
    Ok(apply_fstypes(parse_df_k(&df), &fstypes))
}

/// The `vm_stat` page size (bytes) from its first line (`page size of N bytes`), default 4096.
fn vm_stat_page_size(vm_stat: &str) -> u64 {
    vm_stat
        .lines()
        .next()
        .and_then(|l| l.split_once("page size of "))
        .and_then(|(_, a)| a.split_once(" bytes"))
        .and_then(|(n, _)| n.trim().parse().ok())
        .unwrap_or(4096)
}

/// Whether `vm_stat` is a real reading rather than empty/garbage — i.e. it has at least one of the
/// two page-count lines [`compute_memory`] derives `available` from. Guards against a subprocess
/// failure (not found, non-zero exit, or — since a previous slice added `run_command`'s timeout —
/// a hang) reaching `compute_memory` as `""` and being silently computed through as "0 free/inactive
/// pages", which see that function's own doc comment for why it is not a safe default.
fn vm_stat_has_reading(vm_stat: &str) -> bool {
    vm_stat.contains("Pages free:") || vm_stat.contains("Pages inactive:")
}

/// The page count for a `vm_stat` line whose (trimmed) label is exactly `label` (e.g. `Pages
/// active:`) — a full-prefix match, since "Pages inactive:" contains "active" and there are two
/// "compressor" lines. 0 when absent.
fn vm_stat_pages(vm_stat: &str, label: &str) -> u64 {
    for line in vm_stat.lines() {
        let line = line.trim_start();
        if line.starts_with(label) {
            if let Some((_, after)) = line.split_once(':') {
                if let Ok(p) = after.trim().trim_end_matches('.').parse::<u64>() {
                    return p;
                }
            }
        }
    }
    0
}

/// Physical memory usage. Distinct from the health score's minimal MemoryStatus.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryUsage {
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub used_percent: f64,
    pub swap_used: u64,
    pub swap_total: u64,
    /// File-backed (reclaimable) memory — `parse_file_backed_bytes` on the SAME `vm_stat` sample
    /// `used`/`available` are computed from. gopsutil (and this engine's own `used`/`available`
    /// math) has no equivalent field, which is why digger fills it from `vm_stat` directly rather
    /// than from its normal memory-stats source.
    pub cached: u64,
}

/// Compute memory usage from `vm_stat` page counts and a total (from `hw.memsize`). Matches
/// gopsutil's Darwin `mem.VirtualMemory()` — the ORACLE's real source (digger's `collectMemory`
/// calls it directly) — by inverting the derivation: `available` is computed FIRST, as
/// `(inactive + free) * page_size`, and `used` is whatever's left of `total`.
///
/// This function previously summed active+wired+compressor into `used` directly (Activity
/// Monitor's own "Memory Used" convention) and derived `available` as the remainder — NOT the same
/// computation as gopsutil's, because `hw.memsize` (`total` here) is larger than the sum of every
/// bucket `vm_stat` enumerates. The unaccounted memory landed in `used` under the old formula and
/// lands in `used` under this one too, but only because it's on the side NOT explicitly summed —
/// the two formulas disagree by exactly that unaccounted amount. Measured live, same machine, same
/// `vm_stat` sample: the old active+wired+compressor formula gave 65.9% used; this (gopsutil's)
/// formula gives 68.7%; the real oracle reads 68.59% — settling which one is the contract. Do not
/// try to close a future gap by adding more buckets to a sum (a real reviewer already ruled out
/// `speculative` this way, at only 10MB) — gopsutil doesn't enumerate the unaccounted memory
/// anywhere, so only the inverted form matches it.
///
/// "cached" is `parse_file_backed_bytes` on the same sample, unaffected by this — digger fills
/// `Cached` from `vm_stat` directly too (gopsutil's own `Cached` is always 0 on Darwin).
///
/// Pure — the total is injected so it's testable. Swap is filled in by the caller
/// (`collect_memory`) since it comes from a separate command (`sysctl vm.swapusage`).
///
/// A `vm_stat` that failed to run — not found, exited non-zero, or (since a previous slice added
/// `run_command`'s timeout) hung and was killed — reaches this function as `""`
/// (`collect_memory`'s `.unwrap_or_default()`). Computed through the formula below unguarded, zero
/// free+inactive pages would report `used_percent: 100.0`: a FALSE "completely out of memory"
/// reading, not an absence of one, because the derivation computes `available` FIRST and treats
/// every unaccounted page as `used` (see the doc comment above). That is worse than reporting
/// nothing — RULEBOOK §3g/§3h's point that a missing reading must degrade to an honest, neutral
/// value, never a fabricated (here, alarming) one, applies just as much to a false 100% as to a
/// false 0%. So a `vm_stat` with neither recognized marker line is treated as "no reading" and
/// reported all-zero except `total` (which comes from a separate, independently-collected sysctl
/// call and is preserved) — exactly like this function's `total == 0` branch below already does
/// when THAT collector fails instead.
pub fn compute_memory(vm_stat: &str, total: u64) -> MemoryUsage {
    if !vm_stat_has_reading(vm_stat) {
        return MemoryUsage {
            total,
            ..Default::default()
        };
    }
    let ps = vm_stat_page_size(vm_stat);
    let available_pages =
        vm_stat_pages(vm_stat, "Pages inactive:") + vm_stat_pages(vm_stat, "Pages free:");
    let available = (available_pages * ps).min(total);
    let used = total.saturating_sub(available);
    let used_percent = if total > 0 {
        used as f64 * 100.0 / total as f64
    } else {
        0.0
    };
    MemoryUsage {
        total,
        used,
        available,
        used_percent,
        swap_used: 0,
        swap_total: 0,
        cached: parse_file_backed_bytes(vm_stat),
    }
}

/// Collect physical memory usage: `sysctl -n hw.memsize` (total) + `vm_stat` (breakdown + cached) +
/// `sysctl vm.swapusage` (swap).
pub fn collect_memory() -> MemoryUsage {
    collect_memory_checked().unwrap_or_else(|(_, mem)| mem)
}

/// [`collect_memory`], keeping the reason either physical-memory probe failed — one of the four
/// health-score inputs. The `Err` arm still carries the partially-built [`MemoryUsage`] so a caller
/// that wants to report both "here is what I could read" and "this was not measured" can.
///
/// Both `hw.memsize` and `vm_stat` must answer before `used_percent` is a reading. The partial
/// all-zero breakdown on failure is still useful to render, but cannot establish idle memory.
#[allow(clippy::result_large_err)]
pub fn collect_memory_checked() -> Result<MemoryUsage, (CommandFailure, MemoryUsage)> {
    // hw.memsize: no Go shell-out (gopsutil's `mem.VirtualMemory()` syscall reads it directly) —
    // 500ms matches this file's other sysctl-family budgets, all ported from the one sysctl call
    // digger DOES bound this way (`getCoreTopology`, `metrics_cpu.go:130`, 500ms).
    let total = run_command_checked("sysctl", &["-n", "hw.memsize"], Duration::from_millis(500))
        .and_then(|s| {
            s.trim()
                .parse::<u64>()
                .map_err(|_| CommandFailure::Exited(None))
        });
    // 500ms, matching digger's `getFileBackedMemory` (`metrics_memory.go:55`) — the same `vm_stat`
    // call, there used only for `Cached` (gopsutil supplies used/available/total independently in
    // the original); this engine reuses the one spawn for both, see `MemoryUsage::cached`'s doc
    // comment and `compute_memory`'s guard against a failed/timed-out read below.
    let vm = run_command_checked("vm_stat", &[], Duration::from_millis(500));
    memory_from_probes(total, vm, collect_swap())
}

fn memory_from_probes(
    total: Result<u64, CommandFailure>,
    vm: Result<String, CommandFailure>,
    swap: (u64, u64),
) -> Result<MemoryUsage, (CommandFailure, MemoryUsage)> {
    let mut mem = compute_memory(
        vm.as_deref().unwrap_or_default(),
        *total.as_ref().unwrap_or(&0),
    );
    mem.swap_used = swap.0;
    mem.swap_total = swap.1;
    match (total, vm) {
        (Err(e), _) | (_, Err(e)) => Err((e, mem)),
        (Ok(n), Ok(vm)) if n > 0 && vm_stat_has_reading(&vm) => Ok(mem),
        _ => Err((CommandFailure::NoOutput, mem)),
    }
}

/// Swap used/total in BYTES, parsed from `sysctl vm.swapusage` text (e.g. `"vm.swapusage: total =
/// 5120.00M  used = 4597.62M  free = 522.38M  (encrypted)"`). `M` here is MiB (1024*1024); gopsutil
/// reads the raw `xsw_usage` struct (already byte-exact) rather than this rounded-to-2-decimals
/// text, so this is accurate to roughly 10KB, not bit-exact. That's acceptable: swap usage is
/// live and changes constantly, so byte-exact parity with a frozen golden capture isn't reachable
/// OR meaningful — only the unit (bytes, matching the golden's magnitude) and correct field
/// matter. Pure.
pub fn parse_swapusage_bytes(output: &str) -> Option<(u64, u64)> {
    let total_mb = swapusage_field(output, "total")?;
    let used_mb = swapusage_field(output, "used")?;
    let to_bytes = |mb: f64| (mb * 1024.0 * 1024.0).round() as u64;
    Some((to_bytes(used_mb), to_bytes(total_mb)))
}

fn swapusage_field(output: &str, key: &str) -> Option<f64> {
    let marker = format!("{key} = ");
    let (_, rest) = output.split_once(marker.as_str())?;
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits.parse().ok()
}

/// Collect swap used/total in bytes: `sysctl vm.swapusage`. `(0, 0)` off macOS / on failure — a
/// machine that genuinely has swap disabled also reads `(0, 0)`, which is indistinguishable and
/// correct either way.
pub fn collect_swap() -> (u64, u64) {
    if !cfg!(target_os = "macos") {
        return (0, 0);
    }
    // No Go shell-out (gopsutil's `mem.SwapMemory()` syscall) — 500ms matches this file's other
    // sysctl-family budgets (see `collect_memory`'s `hw.memsize` comment for the precedent).
    run_command_with_timeout("sysctl", &["vm.swapusage"], Duration::from_millis(500))
        .as_deref()
        .and_then(parse_swapusage_bytes)
        .unwrap_or((0, 0))
}

/// Overall CPU usage percent from `top -l 2` output, as `100 − idle` of the LAST "CPU usage:" line
/// (the second, instantaneous sample; the first is since-boot and misleading). Pure. `None` when no
/// such line is present. Clamped to [0,100].
pub fn parse_top_cpu_usage(top_output: &str) -> Option<f64> {
    let line = top_output.lines().rfind(|l| l.contains("CPU usage:"))?;
    let idle_part = line.split(',').find(|p| p.contains("idle"))?;
    let num: String = idle_part
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let idle: f64 = num.parse().ok()?;
    Some((100.0 - idle).clamp(0.0, 100.0))
}

/// Collect overall CPU usage: two `top` samples (the second is the real one), or 0 off macOS /
/// on failure.
pub fn collect_cpu_usage() -> f64 {
    if !cfg!(target_os = "macos") {
        return 0.0;
    }
    // No Go equivalent: digger's own CPU fallback shells to `ps -Aceo pcpu` (500ms,
    // `metrics_cpu.go:233`), not `top`. This engine uses `top -l 2 -n 0` instead specifically
    // because it also doubles as the `procs` source (see `collect_cpu_usage_and_procs`); its two
    // samples measure ~1.8s on this machine (see `snapshot.rs`'s FIX 8 comment), so 5s is a
    // comfortable margin above the real cost, not an arbitrary guess.
    run_command_with_timeout("top", &["-l", "2", "-n", "0"], Duration::from_secs(5))
        .as_deref()
        .and_then(parse_top_cpu_usage)
        .unwrap_or(0.0)
}

/// Live process count from `top`'s summary line (`"Processes: 717 total, 2 running, ..."`) — the
/// LAST such line when `-l 2` prints two samples, matching `parse_top_cpu_usage`'s "use the last
/// (instantaneous) sample" rule. Pure. `None` when no such line is present.
pub fn parse_top_procs(top_output: &str) -> Option<u64> {
    let line = top_output.lines().rfind(|l| l.contains("Processes:"))?;
    let after = line.split_once("Processes:")?.1;
    let digits: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// CPU usage percent + live process count from ONE `top -l 2 -n 0` sample, sharing the spawn: the
/// two-sample `top` call already costs the bulk of `status`'s latency, so a second spawn just to
/// also read `Processes:` would double that for nothing. Falls back to `(0.0, 0)` off macOS / on
/// failure, same as `collect_cpu_usage` alone.
pub fn collect_cpu_usage_and_procs() -> (f64, u64) {
    if !cfg!(target_os = "macos") {
        return (0.0, 0);
    }
    // 5s — see `collect_cpu_usage`'s doc comment for why this bound (no Go equivalent for `top`;
    // measured ~1.8s real cost for the two-sample invocation).
    let out = run_command_with_timeout("top", &["-l", "2", "-n", "0"], Duration::from_secs(5));
    let usage = out.as_deref().and_then(parse_top_cpu_usage).unwrap_or(0.0);
    let procs = out.as_deref().and_then(parse_top_procs).unwrap_or(0);
    (usage, procs)
}

/// Load averages (1/5/15 min) from `sysctl -n vm.loadavg` output: `"{ 5.55 5.54 5.37 }"`. Pure.
pub fn parse_loadavg(output: &str) -> Option<(f64, f64, f64)> {
    let inner = output.trim().trim_start_matches('{').trim_end_matches('}');
    let mut nums = inner
        .split_whitespace()
        .filter_map(|s| s.parse::<f64>().ok());
    Some((nums.next()?, nums.next()?, nums.next()?))
}

/// Collect load averages: `sysctl -n vm.loadavg`. `(0.0, 0.0, 0.0)` off macOS / on failure.
pub fn collect_loadavg() -> (f64, f64, f64) {
    if !cfg!(target_os = "macos") {
        return (0.0, 0.0, 0.0);
    }
    // No Go shell-out (gopsutil's `load.Avg()` syscall; digger's OWN fallback for this shells to
    // `uptime` at 500ms, `fallbackLoadAvgFromUptime`, `metrics_cpu.go:177` — a different command,
    // same "fast local query" tier) — 500ms, matching this file's sysctl-family budgets.
    run_command_with_timeout("sysctl", &["-n", "vm.loadavg"], Duration::from_millis(500))
        .as_deref()
        .and_then(parse_loadavg)
        .unwrap_or((0.0, 0.0, 0.0))
}

/// Physical/logical CPU core counts from `sysctl -n hw.physicalcpu hw.logicalcpu` (one value per
/// line, in that order — a single call for both keys). Pure.
pub fn parse_cpu_counts(output: &str) -> Option<(i64, i64)> {
    let mut lines = output.lines().filter_map(|l| l.trim().parse::<i64>().ok());
    Some((lines.next()?, lines.next()?))
}

/// Collect physical/logical CPU core counts. `(0, 0)` when the probe genuinely fails — that is
/// the honest answer, not a value shaped to satisfy a gate. A fabricated `(1, 1)` fallback would
/// make a failed probe indistinguishable from a real single-core machine, hiding the failure
/// instead of surfacing it; `core_count: 0` decodes fine and is the correct signal that something
/// is wrong upstream (no sysctl, a stripped environment, an unexpected output format).
pub fn collect_cpu_counts() -> (i64, i64) {
    // No Go shell-out (gopsutil's `cpu.Counts()` syscall) — 500ms, matching this file's other
    // sysctl-family budgets.
    run_command_with_timeout(
        "sysctl",
        &["-n", "hw.physicalcpu", "hw.logicalcpu"],
        Duration::from_millis(500),
    )
    .as_deref()
    .and_then(parse_cpu_counts)
    .unwrap_or((0, 0))
}

/// P/E core counts from `sysctl -n hw.perflevel0.logicalcpu hw.perflevel0.name
/// hw.perflevel1.logicalcpu hw.perflevel1.name` (one value per line, in that order): whichever
/// level's name contains "performance" contributes `p_cores`, "efficiency" contributes `e_cores`.
/// `(0, 0)` on fewer than 4 lines — a real answer, not a probe failure, on any CPU with no
/// heterogeneous core levels (every Intel Mac). Pure. Ported from digger's `getCoreTopology`.
pub fn parse_core_topology(output: &str) -> (i64, i64) {
    let lines: Vec<&str> = output.lines().collect();
    if lines.len() < 4 {
        return (0, 0);
    }
    let count0 = lines[0].trim().parse::<i64>().unwrap_or(0);
    let name0 = lines[1].trim().to_lowercase();
    let count1 = lines[2].trim().parse::<i64>().unwrap_or(0);
    let name1 = lines[3].trim().to_lowercase();

    let mut p_cores = 0i64;
    let mut e_cores = 0i64;
    if name0.contains("performance") {
        p_cores = count0;
    } else if name0.contains("efficiency") {
        e_cores = count0;
    }
    if name1.contains("performance") {
        p_cores = count1;
    } else if name1.contains("efficiency") {
        e_cores = count1;
    }
    (p_cores, e_cores)
}

/// Collect P/E core counts (macOS only). `(0, 0)` off macOS or on any Intel Mac: a CPU with no
/// heterogeneous cores has no `hw.perflevel1` key at all, so `sysctl` exits non-zero, `run_command`
/// returns `None`, and this degrades to `(0, 0)` the same honest way `collect_cpu_counts` does —
/// never a fabricated positive pair (RULEBOOK §3h).
pub fn collect_core_topology() -> (i64, i64) {
    if !cfg!(target_os = "macos") {
        return (0, 0);
    }
    // 500ms, DIRECT match to digger's `getCoreTopology` (`metrics_cpu.go:130`) — the exact same
    // sysctl invocation at the exact same budget.
    run_command_with_timeout(
        "sysctl",
        &[
            "-n",
            "hw.perflevel0.logicalcpu",
            "hw.perflevel0.name",
            "hw.perflevel1.logicalcpu",
            "hw.perflevel1.name",
        ],
        Duration::from_millis(500),
    )
    .as_deref()
    .map(parse_core_topology)
    .unwrap_or((0, 0))
}

/// Collect the full process list (`ps -Aceo pid=,ppid=,pcpu=,pmem=,rss=,comm=, -r`, sorted by %CPU
/// descending) — the same invocation digger's `collectProcesses` uses. Feeds both `top_processes`
/// (via `process::top_processes`) and the per-core CPU estimate (`process::estimate_per_core`)
/// from ONE spawn, matching this file's existing "share a spawn across derived values" convention
/// (`collect_cpu_usage_and_procs`). Empty off macOS or on failure — digger's own `collectProcesses`
/// returns `nil, nil` off-darwin too.
/// Lower-priority RULEBOOK fix: falls back to `ps aux` when the primary invocation fails, matching
/// digger's `collectProcesses` (`metrics_process.go`) exactly. Without this, a primary-form failure
/// (a stripped `ps`, an unexpected sandbox restriction) used to silently empty BOTH `top_processes`
/// AND `cpu.per_core` (the per-core estimate is derived from this same process list) — the fallback
/// gives both a second chance at a real reading instead of going straight to empty/zeroed output.
pub fn collect_processes() -> Vec<ProcessInfo> {
    collect_processes_checked().unwrap_or_default()
}

/// [`collect_processes`], keeping the reason both `ps` forms failed.
///
/// This is the fourth health-score input, and the least obviously so: `cpu.usage` is the mean of
/// `cpu.per_core`, which this engine derives from THIS process list (see `snapshot::collect`'s FIX
/// 2 comment). So an unreadable `ps` produces `cpu.usage: 0.0`, which sails past
/// `cpu.usage > CPU_NORMAL` and contributes no penalty — the same silent-zero shape as the other
/// three.
///
/// The reported failure is the FALLBACK's, since that is the last thing tried; the primary form's
/// failure is not surfaced, because digger's own contract is "either invocation answering is a
/// success" and reporting the first one's error alongside a working second one would be noise.
pub fn collect_processes_checked() -> Result<Vec<ProcessInfo>, CommandFailure> {
    if !cfg!(target_os = "macos") {
        // Not `NotSpawnable`: `ps` exists on Linux and on Windows via Git-Bash-style toolchains, so
        // claiming it could not be started would be a guess. The engine simply does not have a
        // process reading for this platform, and that is a different, permanent fact.
        return Err(CommandFailure::NotSpawnable(
            "no process collector on this platform".to_string(),
        ));
    }
    // 3s, matching digger's `collectProcesses` (`metrics_process.go:20`) for the primary
    // invocation. digger reuses ONE 3s `ctx` across BOTH the primary attempt and the `ps aux`
    // fallback (so their combined worst case is 3s, not 6s); giving the fallback its own
    // independent 3s budget here is a deliberate, minor simplification rather than tracking
    // "remaining time" across two calls — it only matters in the compound, already-rare case where
    // BOTH the primary form fails/hangs AND the fallback also hangs, and even then the result is
    // still bounded (6s, not forever), just not byte-for-byte identical to the original's ceiling.
    if let Some(out) = run_command_with_timeout(
        "ps",
        &["-Aceo", "pid=,ppid=,pcpu=,pmem=,rss=,comm=", "-r"],
        Duration::from_secs(3),
    ) {
        return Ok(parse_process_output(&out));
    }
    run_command_checked("ps", &["aux"], Duration::from_secs(3)).map(|o| parse_ps_aux_output(&o))
}

/// Collect per-interface cumulative network byte counters (`netstat -ibn`). `None` — not
/// `Some(vec![])` — when `netstat` can't be run at all: the two are different facts. A caller
/// that collapses "couldn't read" into "read zero interfaces" and persists that as a rate
/// baseline corrupts the NEXT successful read's delta (this is exactly the bug the disk-IO
/// collector had before it was deleted — see `io_rate`'s module docs). `Some(vec![])` (netstat
/// ran, genuinely found nothing) is a real, if unlikely, possible outcome and is preserved as-is.
///
/// The `-n` is load-bearing, not cosmetic: measured on this machine, plain `netstat -ib` attempts
/// reverse-DNS on every address it prints and took 90+ seconds when the resolver was slow (2.4s
/// when it wasn't — same binary, same machine, different moment). `status` has nothing to do with
/// names here at all, only cumulative BYTE COUNTERS, so the lookup is pure unbounded cost for zero
/// benefit. `-n` forces numeric addresses and returns instantly. This is `run_command`'s only
/// caller with that failure mode in `src/status/` — audited every other collector in this file
/// (`system_profiler`, `ioreg`, `diskutil`, `ifconfig`, `ps`, `sysctl`, `pmset`, …) for an
/// equivalent name-resolution/network/interactive-prompt flag and found none; see RULEBOOK §3d.
/// `parse_netstat_ib` needs no change for it — verified against a live `-n` capture: `-n` only
/// changes how the Network/Address columns render (numeric vs resolved), and this parser (a) skips
/// every row that isn't the `<Link#N>` row via the `fields[2].contains("Link")` guard, so it never
/// even reads the address column, and (b) reads the byte counters from the end of the row, which
/// are never dashed/resolved on any row shape. See `netstat_ibn_does_not_double_count_multi_family_interfaces`.
pub fn collect_net_interfaces() -> Option<Vec<NetInterface>> {
    // No Go shell-out (gopsutil's `net.IOCounters()` syscall reads this directly) — but this IS
    // the exact command RULEBOOK §3d's own history is about: 2.4s one hour, 90+s the next, before
    // `-n` closed the reverse-DNS hang. Post-`-n` this should be near-instant, but "measure the
    // worst case, not the convenient one" is the whole lesson of that section, so 5s (comfortably
    // above the 2.4s normal case, the same tier as this file's other "expensive" system_profiler
    // budgets) rather than something tight enough to risk false timeouts on a slower machine.
    run_command_with_timeout("netstat", &["-ibn"], Duration::from_secs(5))
        .map(|o| parse_netstat_ib(&o))
}

/// Collect interface name -> IPv4 address (`ifconfig -a`). Empty map on failure.
pub fn collect_interface_ips() -> std::collections::HashMap<String, String> {
    // No Go shell-out (gopsutil's `net.Interfaces()` syscall) — 3s: local interface enumeration,
    // no DNS/network I/O, same "moderate local command" tier as `collect_disks`'s `df`/`mount`.
    run_command_with_timeout("ifconfig", &["-a"], Duration::from_secs(3))
        .map(|o| super::network::parse_ifconfig_ips(&o))
        .unwrap_or_default()
}

/// The machine's hostname (`hostname`), e.g. `"fixture-mac"`. Empty string on failure.
pub fn collect_hostname() -> String {
    // No Go shell-out (gopsutil's `host.Info().Hostname` syscall) — 1s, matching the "trivial local
    // binary" tier this file's one direct `sw_vers` precedent uses (`collect_platform`, below).
    run_command_with_timeout("hostname", &[], Duration::from_secs(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `"darwin 26.5.2"` — gopsutil's darwin `host.Info()` reports `Platform` as the literal string
/// `"darwin"` (distinct from Rust's own `std::env::consts::OS`, which is `"macos"`) plus the OS
/// product version. Ported field-for-field from digger's
/// `fmt.Sprintf("%s %s", hostInfo.Platform, hostInfo.PlatformVersion)`.
pub fn collect_platform() -> String {
    if !cfg!(target_os = "macos") {
        return std::env::consts::OS.to_string();
    }
    // 1s, matching digger's OWN use of this exact command (`sw_vers -productVersion`,
    // `metrics_hardware.go:57`) — a different call site (there it feeds `hardware.os_version`,
    // here `platform`) but the same command at the same budget.
    let version = run_command_with_timeout("sw_vers", &["-productVersion"], Duration::from_secs(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if version.is_empty() {
        "darwin".to_string()
    } else {
        format!("darwin {version}")
    }
}

/// `"+0700"` / `"-0700"` (from `date +%z`) -> signed offset in seconds. Pure.
pub fn parse_utc_offset(s: &str) -> Option<i32> {
    let s = s.trim();
    if s.len() != 5 {
        return None;
    }
    let sign = match s.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let hh: i32 = s.get(1..3)?.parse().ok()?;
    let mm: i32 = s.get(3..5)?.parse().ok()?;
    Some(sign * (hh * 3600 + mm * 60))
}

/// Combine `date -r <epoch> "+%Y-%m-%dT%H:%M:%S %z"` output (e.g. `"2026-07-16T10:48:50 -0700"`)
/// with a microsecond count into the fractional-seconds ISO8601 string `MoleStatus` requires:
/// `"2026-07-16T10:48:50.611799-07:00"`. `None` if the input isn't in the expected two-part shape.
/// Pure.
pub fn format_collected_at(date_and_offset: &str, micros: u32) -> Option<String> {
    let (dt, off) = date_and_offset.trim().rsplit_once(' ')?;
    let off = parse_utc_offset(off)?;
    let (sign, abs) = if off < 0 { ('-', -off) } else { ('+', off) };
    Some(format!(
        "{dt}.{micros:06}{sign}{:02}:{:02}",
        abs / 3600,
        (abs % 3600) / 60
    ))
}

/// Collect `collected_at`: local wall-clock time as ISO8601 with microsecond fractional seconds
/// and a numeric (never `Z`, even at UTC+0 — `MoleStatus` is fine with `Z` too, but the golden's
/// own captures always use a numeric offset, so this matches that exactly) UTC offset. The
/// calendar breakdown and offset come from the OS's own `date -r <epoch>` (no hand-rolled calendar
/// math, matching this crate's shell-out-and-parse style everywhere else); the epoch seconds AND
/// the microsecond fraction both come from ONE read of Rust's own clock, so there's no skew
/// between "the instant" and "its sub-second part" (a separate `date` call for fractional seconds
/// isn't possible anyway — BSD `date` has no `%N`).
pub fn collect_collected_at() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let micros = dur.subsec_micros();
    // No Go equivalent (digger uses `time.Now()` natively, no subprocess at all — this call only
    // exists because this crate avoids hand-rolled calendar math, per this function's own doc
    // comment above) — 1s, a trivial local computation with no I/O.
    let stamp = run_command_with_timeout(
        "date",
        &["-r", &dur.as_secs().to_string(), "+%Y-%m-%dT%H:%M:%S %z"],
        Duration::from_secs(1),
    );
    stamp
        .as_deref()
        .and_then(|s| format_collected_at(s, micros))
        .unwrap_or_else(|| format!("1970-01-01T00:00:00.{micros:06}+00:00"))
}

/// Collect the macOS memory pressure level (`memory_pressure`), or "" off macOS / on failure.
pub fn collect_memory_pressure() -> String {
    if !cfg!(target_os = "macos") {
        return String::new();
    }
    // 500ms, matching digger's `getMemoryPressure` (`metrics_memory.go:97`) for this exact command.
    run_command_with_timeout("memory_pressure", &[], Duration::from_millis(500))
        .map(|o| parse_memory_pressure(&o))
        .unwrap_or_default()
}

/// How long `collect_trash_size` will walk `~/.Trash` before giving up and reporting a partial
/// total. Ported from digger's `scanTrashSize` (`metrics_disk.go`), which wraps the identical walk
/// in `context.WithTimeout(context.Background(), 2*time.Second)`. Load-bearing, not decorative:
/// Trash can hold an arbitrarily large/deep tree, and an unbounded walk here is exactly the hang
/// class that cost this migration a 90-second `netstat` (RULEBOOK §3d) — this collector bounds
/// itself the same way regardless of whether `run_command`'s missing subprocess timeout is ever
/// fixed (a separate, not-this-slice problem noted in the same section).
const TRASH_SCAN_TIMEOUT: Duration = Duration::from_secs(2);

/// Resolve `~/.Trash` from an already-read HOME value — injectable so the "HOME unset" case is
/// tested without mutating the real process environment. Mirrors this crate's established pattern
/// for exactly this problem (`io_rate::resolve_state_path`). `None` when HOME is unset/blank.
fn resolve_trash_path(home: Option<&str>) -> Option<PathBuf> {
    let home = home.filter(|h| !h.is_empty())?;
    Some(Path::new(home).join(".Trash"))
}

/// Total size in bytes of every regular file under `root`, and whether `budget` was exceeded
/// before the walk finished (`true` = the total is a partial lower bound, not the real size).
/// Root/budget are both parameters — not the real `~/.Trash` and a hardcoded 2s — so tests can
/// exercise both the normal and timed-out paths against a small hermetic temp directory without
/// ever actually sleeping (a `budget` of `Duration::ZERO` forces the timeout branch on the very
/// first entry, deterministically).
///
/// Ported from digger's `scanTrashSize`: sums the file's APPARENT length (`Metadata::len()`, i.e.
/// Go's `info.Size()`) — deliberately NOT `analyze::scanner::actual_size`'s block-allocated,
/// sparse/clone-aware sizing, which digger's trash walker never applies; reusing that helper here
/// would silently diverge from the original it's supposed to match. Symlinks are skipped entirely —
/// counted neither for their own size nor followed — matching `d.Type()&fs.ModeSymlink != 0` in the
/// Go source (and differing from `scanner.rs`, which DOES count a symlink's own size: two different
/// original behaviors, ported faithfully as two different Rust behaviors). A directory that doesn't
/// exist or can't be read — including `root` itself — contributes 0 and is not an error, matching
/// the Go callback's `if err != nil { return nil }` (which never even inspects `d` in that branch).
pub fn scan_trash_dir(root: &Path, budget: Duration) -> (u64, bool) {
    let start = Instant::now();
    let mut total = 0u64;
    let mut timed_out = false;
    walk_trash(root, &start, budget, &mut total, &mut timed_out);
    (total, timed_out)
}

fn walk_trash(
    dir: &Path,
    start: &Instant,
    budget: Duration,
    total: &mut u64,
    timed_out: &mut bool,
) {
    if *timed_out {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // missing / unreadable directory — contributes nothing, not an error
    };
    for entry in entries.flatten() {
        if start.elapsed() >= budget {
            *timed_out = true;
            return;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            continue; // neither sized nor followed — matches digger exactly
        }
        if ft.is_dir() {
            walk_trash(&path, start, budget, total, timed_out);
            if *timed_out {
                return;
            }
        } else {
            *total += meta.len();
        }
    }
}

/// Collect `trash_size`/`trash_approx`: total bytes under `~/.Trash`, bounded to
/// [`TRASH_SCAN_TIMEOUT`]. `(0, false)` off macOS, when `HOME` is unset/blank, or when `~/.Trash`
/// doesn't exist — all the same "nothing to report, no error" case digger degrades to as well.
pub fn collect_trash_size() -> (u64, bool) {
    if !cfg!(target_os = "macos") {
        return (0, false);
    }
    let home = crate::platform::home_dir();
    let Some(trash) = resolve_trash_path(home.as_deref()) else {
        return (0, false);
    };
    scan_trash_dir(&trash, TRASH_SCAN_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_vm_stat_preserves_total_but_marks_memory_unavailable() {
        let (error, partial) = memory_from_probes(
            Ok(8192),
            Err(CommandFailure::TimedOut(Duration::from_millis(500))),
            (7, 9),
        )
        .unwrap_err();
        assert!(matches!(error, CommandFailure::TimedOut(_)));
        assert_eq!(partial.total, 8192);
        assert_eq!((partial.swap_used, partial.swap_total), (7, 9));
        assert!(memory_from_probes(Ok(8192), Ok("unrecognized data".into()), (0, 0)).is_err());
        assert!(memory_from_probes(
            Ok(8192),
            Ok("Pages free: 1.\nPages inactive: 0.\nPages active: 1.\n".into()),
            (0, 0)
        )
        .is_ok());
    }
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| m.get(k).cloned().unwrap_or_default()
    }

    #[test]
    fn env_wins_over_an_enabled_system_proxy() {
        // FIX 3 (RULEBOOK): digger checks env FIRST — an enabled scutil entry must NOT shadow a
        // proxy the user actually set via environment variable. This inverts what this test used
        // to assert (system proxy winning), which was the bug: live divergence measured with
        // HTTPS_PROXY set AND scutil's HTTPSEnable:1 both true at once (oracle "HTTP", engine
        // pre-fix "HTTPS", same instant).
        let scutil =
            "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.0.0.1\n  HTTPPort : 3128\n}";
        let p = resolve_proxy(
            Some(scutil),
            env(&[("ALL_PROXY", "socks5://127.0.0.1:1")]),
            &[],
        );
        assert_eq!(p.kind, "SOCKS");
        assert_eq!(p.host, "127.0.0.1:1");
    }

    #[test]
    fn falls_back_to_system_proxy_when_env_reports_none() {
        // No env proxy set → the enabled system config is used.
        let scutil =
            "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 10.0.0.1\n  HTTPPort : 3128\n}";
        let p = resolve_proxy(Some(scutil), env(&[]), &[]);
        assert_eq!(p.kind, "HTTP");
        assert_eq!(p.host, "10.0.0.1:3128");
    }

    #[test]
    fn falls_back_to_tun_when_env_and_system_report_none() {
        // Neither env nor scutil have anything enabled → an active utun interface is the last
        // resort (FIX 3: this fallback didn't exist at all before).
        let ifaces = [NetInterface {
            name: "utun4".to_string(),
            bytes_in: 100,
            bytes_out: 50,
        }];
        let p = resolve_proxy(Some("<dictionary> {}"), env(&[]), &ifaces);
        assert_eq!(p.kind, "TUN");
        assert_eq!(p.host, "utun4");
    }

    #[test]
    fn disabled_everywhere_is_disabled() {
        let p = resolve_proxy(None, env(&[]), &[]);
        assert!(!p.enabled);
    }

    #[test]
    fn boottime_parses_and_uptime_computes() {
        let sysctl = "{ sec = 1699999999, usec = 123456 } Wed Nov 15 00:00:00 2023";
        assert_eq!(parse_boottime_secs(sysctl), Some(1699999999));
        assert_eq!(parse_boottime_secs("garbage"), None);
        // 3600s after boot → 1h uptime; a missing/behind boot time clamps to 0.
        assert_eq!(uptime_secs_from(1700003599, Some(1699999999)), 3600);
        assert_eq!(uptime_secs_from(1000, None), 0);
        assert_eq!(uptime_secs_from(500, Some(1000)), 0); // clock behind boot
    }

    #[test]
    fn battery_from_one_ioreg_dump() {
        // One dump feeds both the health parser (cycles/capacity) and the thermal parser.
        let ioreg = "  | |   \"DesignCapacity\" = 10000\n  | |   \"NominalChargeCapacity\" = 8300\n  | |   \"CycleCount\" = 250\n  | |   \"Temperature\" = 3055\n  | |   \"BatteryPower\" = 13654\n";
        let b = battery_from_ioreg(ioreg);
        assert_eq!(b.cycles, 250);
        assert_eq!(b.capacity, 83);
        assert!((b.thermal.battery_temp - 30.55).abs() < 0.001);
        assert!((b.thermal.battery_power - 13.654).abs() < 0.001);
    }

    #[test]
    fn memory_available_is_inactive_plus_free_matching_gopsutil() {
        // Matches gopsutil's Darwin `mem.VirtualMemory()`, the oracle's real source: `available` is
        // computed from inactive+free pages FIRST, and `used` is whatever's left of `total` — NOT
        // a sum of active/wired/compressor pages (that was the pre-fix formula, and it disagreed
        // with the oracle by the memory `vm_stat` doesn't enumerate at all — see the doc comment).
        let vm = "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n\
Pages free:                      500.\n\
Pages active:                    100.\n\
Pages inactive:                  999.\n\
Pages wired down:                 50.\n\
Pages stored in compressor:     8000.\n\
Pages occupied by compressor:     25.\n";
        // available = (999 inactive + 500 free) pages × 4096 = 1499 × 4096 = 6,139,904.
        // used = total - available. active/wired/compressor are NOT summed into anything here.
        let total = 20_000_000u64;
        let m = compute_memory(vm, total);
        let expected_available = 1499 * 4096;
        assert_eq!(m.available, expected_available);
        assert_eq!(m.total, total);
        assert_eq!(m.used, total - expected_available);
        assert!(
            (m.used_percent - ((total - expected_available) as f64 * 100.0 / total as f64)).abs()
                < 1e-9
        );
    }

    #[test]
    fn memory_reproduces_the_live_oracle_measurement() {
        // FIX (RULEBOOK / commander live diagnosis): reproduces the exact live comparison that
        // caught this — same machine, a real `vm_stat` sample, `total` from `sysctl hw.memsize`.
        // The old active+wired+compressor formula read 65.9% used on this sample; the real oracle
        // read 68.59%; this (gopsutil's own) formula must land in that neighborhood, not the old
        // one's.
        let vm = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
Pages free:                                    17490.\n\
Pages active:                                 468148.\n\
Pages inactive:                               468488.\n\
Pages speculative:                              4916.\n\
Pages wired down:                             251554.\n\
Pages purgeable:                                6528.\n\
Pages occupied by compressor:                 320058.\n";
        let total = 25_769_803_776u64; // this machine's real hw.memsize (24 GiB)
        let m = compute_memory(vm, total);
        // available = (468488 + 17490) * 16384 = 7,962,263,552 -> used = 17,807,540,224 (69.10%).
        assert_eq!(m.available, 7_962_263_552);
        assert_eq!(m.used, 17_807_540_224);
        assert!(
            (m.used_percent - 69.10235087076823).abs() < 1e-9,
            "got {}, want ~69.10 — close to the oracle's own 68.59-68.93% band across sampled runs, \
             not the old formula's ~65.9-66.6%",
            m.used_percent
        );
    }

    #[test]
    fn memory_is_all_zero_not_100_percent_used_when_vm_stat_has_no_reading() {
        // A `vm_stat` that failed to run (not found, non-zero exit, or — since `run_command` grew a
        // timeout — a kill on deadline) reaches `compute_memory` as `""`. Before this fix, an empty
        // string parsed as "0 free pages, 0 inactive pages", so `available` came out 0 and `used`
        // came out equal to `total` — a false 100%-memory-used reading, worse than reporting
        // nothing at all. The fix must report all-zero (except the independently-collected `total`)
        // instead, matching this same function's existing `total == 0` branch.
        let m = compute_memory("", 25_769_803_776);
        assert_eq!(
            m.total, 25_769_803_776,
            "total is from a separate sysctl call, kept as-is"
        );
        assert_eq!(
            m.used, 0,
            "must not report 100% used from an absent reading"
        );
        assert_eq!(m.available, 0);
        assert_eq!(m.used_percent, 0.0);
        assert_eq!(m.cached, 0);

        // Garbage/unrelated text (e.g. a truncated or corrupted read) must degrade the same way,
        // not just a literal empty string.
        let garbage = compute_memory("not vm_stat output at all\nsome other noise\n", 1_000_000);
        assert_eq!(garbage.used, 0);
        assert_eq!(garbage.used_percent, 0.0);

        // Sanity check the guard doesn't fire on real output: a genuine all-pages-used machine
        // (vanishingly rare, but a real 0-free/0-inactive `vm_stat` reading, not an absent one)
        // still computes through the normal formula rather than being caught by this guard.
        let real_but_full = "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n\
Pages free:                      0.\n\
Pages inactive:                  0.\n";
        let full = compute_memory(real_but_full, 1_000_000);
        assert_eq!(full.used_percent, 100.0);
    }

    #[test]
    fn top_cpu_uses_last_sample_100_minus_idle() {
        // Two samples — the second (instantaneous) one wins.
        let top = "Processes: 500 total\nCPU usage: 2.00% user, 1.00% sys, 97.00% idle\nload...\n\
CPU usage: 19.32% user, 13.00% sys, 67.66% idle\n";
        assert!((parse_top_cpu_usage(top).unwrap() - 32.34).abs() < 0.001);
        assert_eq!(parse_top_cpu_usage("no cpu line here"), None);
    }

    #[test]
    fn memory_pressure_levels() {
        assert_eq!(
            parse_memory_pressure("The system has critical memory pressure"),
            "critical"
        );
        assert_eq!(
            parse_memory_pressure("System memory pressure: warn"),
            "warn"
        );
        assert_eq!(parse_memory_pressure("normal"), "normal");
        assert_eq!(parse_memory_pressure("nothing relevant"), "");
        // critical wins if multiple are present.
        assert_eq!(
            parse_memory_pressure("was normal, now critical"),
            "critical"
        );
    }

    #[test]
    fn file_backed_uses_reported_page_size() {
        let vm = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100.\nFile-backed pages: 388975.\n";
        assert_eq!(parse_file_backed_bytes(vm), 388975 * 16384);
        // Default 4096 when the page-size line is absent.
        let vm4k = "Statistics:\nFile-backed pages: 10.\n";
        assert_eq!(parse_file_backed_bytes(vm4k), 10 * 4096);
        assert_eq!(parse_file_backed_bytes("no such field"), 0);
    }

    #[test]
    fn run_command_captures_stdout() {
        // `true`/`echo` are on every unix; on Windows this collector path isn't exercised.
        #[cfg(unix)]
        {
            let out = run_command("echo", &["hello"]).unwrap();
            assert_eq!(out.trim(), "hello");
            assert!(run_command("this-command-does-not-exist-xyz", &[]).is_none());
        }
    }

    #[test]
    fn run_command_with_timeout_kills_a_hanging_child_instead_of_blocking_forever() {
        // The whole point of this function: a child that never exits must not hang the caller.
        // `sleep 30` with a 200ms budget proves the kill-on-deadline path actually fires, not just
        // that the happy path works — the disk.rs integration tests never exercise a genuine hang.
        #[cfg(unix)]
        {
            let start = Instant::now();
            let out = run_command_with_timeout("sleep", &["30"], Duration::from_millis(200));
            assert!(
                out.is_none(),
                "a killed child must report no output, not partial output"
            );
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "must return promptly on the timeout, not wait anywhere near the full 30s sleep"
            );
        }
    }

    #[test]
    fn run_command_with_timeout_drains_output_larger_than_a_pipe_buffer() {
        // A child that writes MORE than one pipe buffer's worth of output before exiting must not
        // deadlock. Measured live on this machine: `ps aux` (the `collect_processes` fallback)
        // alone emits ~248KB and the primary `ps -Aceo …` form ~36KB, both far past macOS's default
        // per-pipe capacity — if stdout were only read AFTER `try_wait` reports the child has
        // exited (this function's OLD implementation, correct only for the few-KB `diskutil`/
        // `osascript` outputs it was originally written for), the child would block forever
        // writing into a full pipe nobody is draining, and only the timeout below — not a clean
        // read — would ever return, turning every `status` run on a busy machine into a silent,
        // permanent `top_processes`/`cpu.per_core` failure. 200KB (via `yes`/`head`, no reliance on
        // any real system command's current output size) reproduces that scale directly.
        #[cfg(unix)]
        {
            let out = run_command_with_timeout(
                "sh",
                &["-c", "yes x | head -c 200000"],
                Duration::from_secs(10),
            )
            .expect("must drain 200KB of stdout without deadlocking against a full pipe");
            assert_eq!(out.len(), 200_000);
        }
    }

    /// The distinction the whole `status` honesty fix rests on: a program that does not exist, a
    /// program that ran and disagreed, and a program that would not finish are three different
    /// facts. `run_command_with_timeout` collapses all three into `None`, and every caller then
    /// `unwrap_or_default()`s that into a zero — which is how `status` came to report
    /// `health_score: 100, "Excellent"` from a snapshot in which nothing had been collected.
    ///
    /// Driven against real programs on the real machine rather than a stubbed spawner, because the
    /// thing under test IS the spawn: which `io::Error` a missing binary produces, and whether a
    /// non-zero exit reaches this function as an exit status rather than as a spawn failure, are
    /// facts about the OS.
    #[cfg(unix)]
    #[test]
    fn a_missing_binary_a_failing_one_and_a_hanging_one_are_three_distinguishable_facts() {
        let missing = run_command_checked(
            "burrow_engine_definitely_not_a_real_program",
            &[],
            Duration::from_secs(5),
        );
        assert!(
            matches!(missing, Err(CommandFailure::NotSpawnable(_))),
            "a program that is not there must report that it could not be started: {missing:?}"
        );

        let failed = run_command_checked("sh", &["-c", "exit 3"], Duration::from_secs(5));
        assert_eq!(
            failed,
            Err(CommandFailure::Exited(Some(3))),
            "a program that RAN and exited 3 must carry its exit code, not read as missing"
        );

        let timeout = Duration::from_millis(200);
        let hung = run_command_checked("sleep", &["30"], timeout);
        assert_eq!(
            hung,
            Err(CommandFailure::TimedOut(timeout)),
            "a program that would not finish must be distinguishable from one that failed fast"
        );

        let ok = run_command_checked("sh", &["-c", "printf hello"], Duration::from_secs(5));
        assert_eq!(ok, Ok("hello".to_string()), "and success still works");

        // The three failures must not describe themselves identically either — the reason text is
        // what reaches the user through `metrics_unavailable`.
        let described: Vec<String> = [missing, failed, hung]
            .iter()
            .map(|r| r.as_ref().unwrap_err().to_string())
            .collect();
        assert_eq!(
            described
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3,
            "each failure must describe itself distinctly: {described:?}"
        );
    }

    /// The `Option`-returning wrapper must stay a pure `.ok()` over the checked form, or the two
    /// drift and ~40 call sites start disagreeing with the four that care about the reason.
    #[cfg(unix)]
    #[test]
    fn the_option_form_agrees_with_the_checked_form_on_every_outcome() {
        for (program, args) in [
            ("sh", &["-c", "printf hi"][..]),
            ("sh", &["-c", "exit 1"][..]),
            ("burrow_engine_definitely_not_a_real_program", &[][..]),
        ] {
            let checked = run_command_checked(program, args, Duration::from_secs(5));
            let optional = run_command_with_timeout(program, args, Duration::from_secs(5));
            assert_eq!(checked.ok(), optional, "{program} {args:?}");
        }
    }

    // Captured from `sysctl vm.swapusage` on this machine.
    #[test]
    fn swapusage_parses_megabytes_to_bytes() {
        let out = "vm.swapusage: total = 5120.00M  used = 4597.62M  free = 522.38M  (encrypted)\n";
        let (used, total) = parse_swapusage_bytes(out).unwrap();
        assert_eq!(total, (5120.00_f64 * 1024.0 * 1024.0).round() as u64);
        assert_eq!(used, (4597.62_f64 * 1024.0 * 1024.0).round() as u64);
        // Bytes, not the raw "5120.00" — matching the golden's magnitude (~13 billion, not ~13
        // thousand) is the whole point of this field.
        assert!(total > 1_000_000_000, "must be bytes, got {total}");
    }

    #[test]
    fn swapusage_missing_or_garbage_is_none() {
        assert_eq!(parse_swapusage_bytes(""), None);
        assert_eq!(parse_swapusage_bytes("garbage output"), None);
    }

    // Captured from `top -l 2 -n 0` on this machine (two summary blocks; only the trailing
    // fields of each are shown here since the parsers only read "Processes:"/"CPU usage:").
    const TOP_SAMPLE: &str = "\
Processes: 676 total, 4 running, 1 stuck, 671 sleeping, 6261 threads \n\
Load Avg: 5.55, 5.54, 5.37 \n\
CPU usage: 2.00% user, 1.00% sys, 97.00% idle \n\
\n\
Processes: 679 total, 2 running, 677 sleeping, 6250 threads \n\
Load Avg: 5.60, 5.55, 5.38 \n\
CPU usage: 19.32% user, 13.00% sys, 67.66% idle \n";

    #[test]
    fn top_procs_uses_last_sample() {
        // The LAST "Processes:" line wins, same rule as `parse_top_cpu_usage` — matches the
        // instantaneous second `-l 2` sample, not the since-boot first one.
        assert_eq!(parse_top_procs(TOP_SAMPLE), Some(679));
        assert_eq!(parse_top_procs("no processes line here"), None);
    }

    #[test]
    fn cpu_usage_and_procs_share_one_top_output() {
        // Not spawning `top` here (that's `collect_cpu_usage_and_procs`'s job) — just confirming
        // both pure parsers agree on the SAME captured sample, which is what makes sharing one
        // spawn correct.
        assert!((parse_top_cpu_usage(TOP_SAMPLE).unwrap() - 32.34).abs() < 0.001);
        assert_eq!(parse_top_procs(TOP_SAMPLE), Some(679));
    }

    // Captured from `sysctl -n vm.loadavg` on this machine.
    #[test]
    fn loadavg_parses_braced_triplet() {
        assert_eq!(
            parse_loadavg("{ 5.55 5.54 5.37 }\n"),
            Some((5.55, 5.54, 5.37))
        );
        assert_eq!(parse_loadavg(""), None);
        assert_eq!(parse_loadavg("{ 1.0 2.0 }"), None); // only two values
    }

    // Captured from `sysctl -n hw.physicalcpu hw.logicalcpu` on this machine (M4 Pro: no SMT, so
    // physical == logical).
    #[test]
    fn cpu_counts_parses_two_line_output() {
        assert_eq!(parse_cpu_counts("14\n14\n"), Some((14, 14)));
        assert_eq!(parse_cpu_counts("10\n14\n"), Some((10, 14)));
        assert_eq!(parse_cpu_counts("14\n"), None); // only one line
        assert_eq!(parse_cpu_counts(""), None);
    }

    // Captured from `sysctl -n hw.perflevel0.logicalcpu hw.perflevel0.name
    // hw.perflevel1.logicalcpu hw.perflevel1.name` on this machine (M4 Pro: 10 performance + 4
    // efficiency cores).
    #[test]
    fn core_topology_parses_performance_and_efficiency_levels() {
        assert_eq!(
            parse_core_topology("10\nPerformance\n4\nEfficiency\n"),
            (10, 4)
        );
        // Order isn't assumed — whichever level says "efficiency" wins e_cores regardless of index.
        assert_eq!(
            parse_core_topology("4\nEfficiency\n10\nPerformance\n"),
            (10, 4)
        );
    }

    #[test]
    fn core_topology_is_zero_zero_on_homogeneous_cpus() {
        // Intel Macs (and `sysctl`'s own error text on any failure) never produce 4 clean lines.
        assert_eq!(parse_core_topology(""), (0, 0));
        assert_eq!(parse_core_topology("14\nSomething\n"), (0, 0));
    }

    #[test]
    fn merge_battery_counts_prefers_ioreg_when_positive() {
        // signature: (sp_cycles, sp_capacity, ioreg_cycles, ioreg_capacity) -> (cycles, capacity)
        assert_eq!(merge_battery_counts(80, 78, 595, 91), (595, 91));
        // ioreg absent/zero on both → system_profiler's own reading is the fallback.
        assert_eq!(merge_battery_counts(80, 78, 0, 0), (80, 78));
        // ioreg has cycles but not capacity → mixed: ioreg's cycles, system_profiler's capacity.
        assert_eq!(merge_battery_counts(80, 78, 595, 0), (595, 78));
    }

    #[test]
    fn utc_offset_parses_sign_and_colon_free_form() {
        assert_eq!(parse_utc_offset("-0700"), Some(-7 * 3600));
        assert_eq!(parse_utc_offset("+0530"), Some(5 * 3600 + 30 * 60));
        assert_eq!(parse_utc_offset("+0000"), Some(0));
        assert_eq!(parse_utc_offset("garbage"), None);
        assert_eq!(parse_utc_offset(""), None);
    }

    #[test]
    fn collected_at_matches_the_golden_style_exactly() {
        // Real `date -r <epoch> "+%Y-%m-%dT%H:%M:%S %z"` output on this machine, combined with a
        // microsecond count, must reproduce the exact shape of the golden's own
        // "2026-07-16T10:48:50.611799-07:00" — fractional seconds + a COLON-separated numeric
        // offset, never bare seconds and never `Z`.
        let got = format_collected_at("2026-07-16T10:48:50 -0700", 611_799).unwrap();
        assert_eq!(got, "2026-07-16T10:48:50.611799-07:00");
    }

    #[test]
    fn collected_at_handles_positive_offset_and_pads_micros() {
        let got = format_collected_at("2026-01-05T03:04:05 +0530", 7).unwrap();
        assert_eq!(got, "2026-01-05T03:04:05.000007+05:30");
    }

    #[test]
    fn collected_at_rejects_malformed_input() {
        assert_eq!(format_collected_at("not a valid stamp", 0), None);
        assert_eq!(format_collected_at("2026-01-05T03:04:05", 0), None); // no offset half
    }

    #[test]
    fn collected_at_live_value_round_trips_through_the_iso8601_regex_shape() {
        // This DOES spawn `date` (it's the live `collect_collected_at`, not the pure formatter) —
        // just checking the end-to-end shape against the real system clock matches the golden's
        // style: "YYYY-MM-DDTHH:MM:SS.NNNNNN(+|-)HH:MM", 32 chars, numeric offset (never `Z`).
        let got = collect_collected_at();
        assert_eq!(got.len(), 32, "got {got:?}");
        assert_eq!(&got[4..5], "-");
        assert_eq!(&got[10..11], "T");
        assert_eq!(&got[19..20], ".");
        assert_eq!(&got[29..30], ":");
        assert!(
            got.as_bytes()[26] == b'+' || got.as_bytes()[26] == b'-',
            "got {got:?}"
        );
    }

    #[test]
    fn hostname_and_platform_are_nonempty_on_this_machine() {
        // Live collectors — this crate's tests already run real subprocesses elsewhere
        // (`run_command_captures_stdout` above); macOS always has `hostname` and `sw_vers`.
        #[cfg(target_os = "macos")]
        {
            assert!(!collect_hostname().is_empty());
            let platform = collect_platform();
            assert!(platform.starts_with("darwin "), "got {platform:?}");
        }
    }

    #[test]
    fn trash_path_resolves_under_home_and_disables_when_unset() {
        assert_eq!(
            resolve_trash_path(Some("/Users/x")),
            Some(PathBuf::from("/Users/x/.Trash"))
        );
        assert_eq!(resolve_trash_path(None), None, "HOME unset");
        assert_eq!(resolve_trash_path(Some("")), None, "blank HOME too");
    }

    /// A fresh, unique-per-call scratch directory under the OS temp dir — mirrors
    /// `io_rate`'s test helper of the same shape, for the same reason: parallel `cargo test`
    /// threads must never collide on the same path.
    fn trash_test_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "burrow-trash-test-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn scan_trash_dir_sums_files_recursively_and_skips_symlinks() {
        let dir = trash_test_dir("sums");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap(); // 5 bytes
        std::fs::write(dir.join("sub").join("b.txt"), b"world!").unwrap(); // 6 bytes
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("a.txt"), dir.join("link")).unwrap();
        }

        let (total, approx) = scan_trash_dir(&dir, Duration::from_secs(2));

        #[cfg(unix)]
        assert_eq!(total, 11, "the symlink must not be counted");
        #[cfg(not(unix))]
        assert_eq!(total, 11);
        assert!(!approx, "well within budget");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_trash_dir_reports_approx_when_budget_is_exceeded() {
        let dir = trash_test_dir("timeout");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();

        // A zero budget is already exceeded before the first entry is even read — deterministic,
        // no real sleeping required to exercise the timeout branch.
        let (_total, approx) = scan_trash_dir(&dir, Duration::ZERO);
        assert!(approx, "a zero budget must report approx=true");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_trash_dir_missing_root_is_zero_not_an_error() {
        let dir = trash_test_dir("missing").join("does-not-exist");
        assert_eq!(scan_trash_dir(&dir, Duration::from_secs(2)), (0, false));
    }

    #[test]
    fn collect_trash_size_is_off_by_construction_outside_macos() {
        // `(0, false)` off macOS regardless of environment — same pattern as every other
        // macOS-only collector in this file (`collect_swap`, `collect_cpu_usage`, ...).
        #[cfg(not(target_os = "macos"))]
        assert_eq!(collect_trash_size(), (0, false));
        // On macOS this just needs to not panic against whatever the real ~/.Trash holds; its
        // magnitude/approx-ness is machine-state, not something a unit test can pin.
        #[cfg(target_os = "macos")]
        {
            let (_total, _approx) = collect_trash_size();
        }
    }
}
