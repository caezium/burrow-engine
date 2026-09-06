//! System snapshot — runs every collector, computes the health score, and serializes the whole
//! thing to JSON. This is the aggregation `burrow-engine status` emits (the engine's equivalent of
//! digger's Metrics), assembled from the ported parsers + collectors.
//!
//! `collect` is IO (spawns the collector commands); `to_json` is pure over a `Snapshot`, so the
//! serialization + health wiring are unit-tested against a hand-built snapshot without spawning.

use super::bluetooth::BluetoothDevice;
use super::collect::{self, BatteryEntry, BatteryReadings, MemoryUsage};
use super::cpu;
use super::disk::DiskUsage;
use super::gpu::GpuInfo;
use super::hardware::{collect_hardware, HardwareInfo};
use super::health::{
    calculate_health_score, BatteryStatus, CpuStatus, DiskIoStatus, DiskStatus, MemoryStatus,
    ThermalStatus,
};
use super::io_rate::{self, IoSample};
use super::network::{self, NetworkStatus, ProxyStatus};
use super::process::{self, ProcessInfo};
use super::process_watch::{
    format_go_duration_secs, ProcessAlert, ProcessWatchOptions, ProcessWatcher,
};
use std::collections::HashMap;

/// The `thermal` object — cpu/gpu temp always 0 (digger never synthesizes them from battery
/// sensors — see `parse_fan_speed`'s sibling comment in `collect_thermal`'s port), fan_count
/// always 0 (digger never sets it either), battery_temp/system_power/adapter_power/battery_power
/// re-shaped from the SAME `ioreg -rn AppleSmartBattery` dump `collect_battery` already parses for
/// `BatteryReadings.thermal`. RULEBOOK §3g: this container must ALWAYS be emitted (never behind an
/// `Option` that omits the key) because `MetricsCore.SnapshotPatcher` on the app side only fills
/// the zero holes INTO an object that already exists — an absent `thermal` key means the native
/// fan/cpu-temp/gpu-temp fill can never happen at all, permanently, not just on this one sample.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ThermalInfo {
    pub cpu_temp: f64,
    pub gpu_temp: f64,
    pub battery_temp: f64,
    pub fan_speed: i32,
    pub fan_count: i32,
    pub system_power: f64,
    pub adapter_power: f64,
    pub battery_power: f64,
}

/// A full status reading.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub collected_at: String,
    pub host: String,
    pub platform: String,
    pub procs: u64,
    pub uptime_secs: u64,
    pub cpu_usage: f64,
    pub cpu_load1: f64,
    pub cpu_load5: f64,
    pub cpu_load15: f64,
    pub cpu_core_count: i64,
    pub cpu_logical_cpu: i64,
    /// Per-core CPU usage over a real window — `host_processor_info` tick deltas, see
    /// [`super::cpu`]. When that reading is unavailable (off macOS, or a window that accrued no
    /// ticks) it is `process::estimate_per_core`'s evenly-spread estimate instead, flagged by
    /// `cpu_per_core_estimated` — the honest answer rather than an empty array (RULEBOOK §6) or
    /// a fabricated realistic-looking one (§3h).
    pub cpu_per_core: Vec<f64>,
    /// `false` when `cpu_per_core` is the genuine per-core reading, `true` when it is the
    /// uniform-spread fallback — digger's own `PerCoreEstimated` (`cmd/status/metrics_cpu.go`),
    /// which starts `false` and flips `true` only when its real syscall reading fails. This engine
    /// used to have the fallback as its ONLY path (no in-process Mach call), so this was always
    /// `true` and `cpu.usage` was the estimate's mean; BUR-140 ported the real sampler.
    pub cpu_per_core_estimated: bool,
    pub cpu_p_core_count: i64,
    pub cpu_e_core_count: i64,
    pub memory: MemoryUsage,
    pub memory_pressure: String,
    pub disks: Vec<DiskUsage>,
    /// Total bytes under `~/.Trash`, and whether the 2-second scan budget was hit before the whole
    /// tree was visited (`collect::collect_trash_size`, ported from digger's `collectTrashSize` /
    /// `scanTrashSize` in `metrics_disk.go`). Zero consumers in `MoleStatus.swift` today — this
    /// exists for judge parity only (RULEBOOK tier 3) — but it's real collected data, not a stub.
    pub trash_size: u64,
    pub trash_approx: bool,
    pub disk_io_read_rate: f64,
    pub disk_io_write_rate: f64,
    /// Raw ioreg-derived battery health/thermal reading — kept only as an INPUT the `batteries`
    /// and `thermal` fields are built from (`collect_batteries`, and this struct's `thermal`
    /// field). It is no longer serialized under its own key: the old singular `"battery"` object
    /// this field used to drive was a misfiled home for exactly the four numbers `thermal` now
    /// carries correctly (RULEBOOK §3: "the engine's existing misfiled `battery` object... those
    /// are thermal's fields"), and it never carried `batteries`' percent/status/time_left/health
    /// at all. Re-shaping in place, not duplicating: emitting BOTH the old misfiled object and the
    /// new correct ones would print the same ioreg numbers twice under two different names.
    pub battery: Option<BatteryReadings>,
    pub proxy: ProxyStatus,
    pub network: Vec<NetworkStatus>,
    pub hardware: HardwareInfo,
    pub health_score: i32,
    pub health_msg: String,
    pub batteries: Vec<BatteryEntry>,
    pub thermal: ThermalInfo,
    pub gpu: Vec<GpuInfo>,
    pub bluetooth: Vec<BluetoothDevice>,
    pub top_processes: Vec<ProcessInfo>,
    /// The process-CPU watchdog CONFIG this `status` run used — an echo, not a live setting: this
    /// engine takes no `--proc-cpu-*` flags (unlike digger's CLI, `cmd/status/main.go`), so it is
    /// always `ProcessWatchOptions::default()`, which is digger's OWN flag defaults, not invented
    /// (see that impl's doc comment). Zero consumers in `MoleStatus.swift` — parity only.
    pub process_watch: ProcessWatchOptions,
    /// Processes that have been continuously at/above `process_watch.cpu_threshold` for the WHOLE
    /// `process_watch.window`. Always `[]` from `collect()`: a one-shot process's `ProcessWatcher`
    /// only ever sees ONE sample, and `ProcessWatcher::update`'s very first call always has
    /// `first_above == now`, so the elapsed-window check can never pass within a single
    /// invocation — see `collect`'s own comment at the call site. Zero consumers — parity only.
    pub process_alerts: Vec<ProcessAlert>,
    /// The health-score inputs this run could not measure, and why — empty on a healthy collection.
    ///
    /// See [`REQUIRED_HEALTH_INPUTS`] for what belongs here and [`Snapshot::nothing_was_measured`]
    /// for the case in which `status` refuses to answer at all.
    pub unavailable: Vec<UnavailableMetric>,
}

/// One health-score input that could not be read, named alongside the probe that failed and the
/// reason it failed.
///
/// The reason is a [`collect::CommandFailure`] rendered to text rather than the enum itself: this
/// crosses the JSON boundary into `metrics_unavailable`, where a GUI or agent wants a sentence, and
/// keeping the enum here would put a machine-readable discriminant one layer away from a
/// hand-written serializer that would have to invent names for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnavailableMetric {
    /// The snapshot field the caller wanted, spelled as it appears in the JSON: `cpu.usage`,
    /// `memory`, `disks`, `uptime_seconds`.
    pub metric: &'static str,
    /// The probe, as argv — `sysctl -n kern.boottime`, `df -kl`, `ps aux`. Named because "memory is
    /// unavailable" sends someone hunting and "`sysctl -n hw.memsize` could not be started" does not.
    pub probe: &'static str,
    /// Rendered [`collect::CommandFailure`]: `could not be started (…)`, `exited 1`, `timed out
    /// after 3s`.
    pub reason: String,
}

/// The four inputs [`calculate_health_score`] actually reads a NUMBER from, and therefore the four
/// whose absence makes the score mean less than it appears to.
///
/// Battery, thermal, disk-IO and memory pressure are deliberately NOT here. Each is legitimately
/// absent on a healthy machine — a Mac mini has no battery, and `health_of` passes
/// `ThermalStatus::default()`/`DiskIoStatus::default()` on purpose because this engine does not
/// collect either — so gating the score on them would report a degradation on hardware that is
/// working perfectly. These four have no such excuse: every Mac has a boot time, a physical memory
/// size, a root filesystem and a process table.
pub const REQUIRED_HEALTH_INPUTS: [&str; 4] = ["cpu.usage", "memory", "disks", "uptime_seconds"];

impl Snapshot {
    /// True when NONE of [`REQUIRED_HEALTH_INPUTS`] could be measured — the state in which the whole
    /// snapshot is fabricated zeros and `status` must refuse rather than serve it.
    ///
    /// This is the exact condition behind the bug: with the collectors unreachable, every field came
    /// back `0`/`""`/`[]`, every penalty branch in `calculate_health_score` is a `>` comparison that
    /// zero cannot trip, and the score sat at its initial `100` with the message `"Excellent"`. A
    /// populated-looking payload and a confident verdict, from nothing.
    pub fn nothing_was_measured(&self) -> bool {
        REQUIRED_HEALTH_INPUTS
            .iter()
            .all(|m| self.unavailable.iter().any(|u| u.metric == *m))
    }

    /// One line per unmeasured input, for the refusal message and the degraded score message.
    pub fn unavailable_summary(&self) -> String {
        self.unavailable
            .iter()
            .map(|u| format!("{} ({}: {})", u.metric, u.probe, u.reason))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// A small, fully-measured snapshot for tests that need SOME snapshot (the `status --watch`
    /// frame tests) without sampling the machine. Not a golden: nothing about its values is
    /// contractual beyond "nothing is unavailable".
    #[cfg(test)]
    pub(crate) fn sample_for_tests() -> Snapshot {
        Snapshot {
            collected_at: "2026-01-01T00:00:00Z".into(),
            host: "test-host".into(),
            platform: "darwin".into(),
            procs: 42,
            uptime_secs: 3600,
            cpu_usage: 12.5,
            cpu_core_count: 2,
            cpu_logical_cpu: 2,
            cpu_per_core: vec![10.0, 15.0],
            health_score: 95,
            health_msg: "Excellent".into(),
            ..Snapshot::default()
        }
    }

    /// The opposite: a snapshot in which none of the health inputs could be measured, each
    /// naming the probe `collect_with` names for it.
    #[cfg(test)]
    pub(crate) fn unmeasured_for_tests() -> Snapshot {
        let probe = |metric: &str| -> &'static str {
            match metric {
                "cpu.usage" => "ps -Aceo … / ps aux",
                "memory" => "sysctl -n hw.memsize",
                "disks" => "df -kl",
                _ => "sysctl -n kern.boottime",
            }
        };
        Snapshot {
            unavailable: REQUIRED_HEALTH_INPUTS
                .iter()
                .map(|m| UnavailableMetric {
                    metric: m,
                    probe: probe(m),
                    reason: "could not be started (No such file or directory)".into(),
                })
                .collect(),
            ..Snapshot::default()
        }
    }
}

/// Compute the health score for a snapshot's metrics. Pure — split out so it's tested without IO.
/// Thermal (CPU temp) and disk-IO aren't collected yet, so they contribute no penalty (0).
///
/// `unavailable` does not change the ARITHMETIC — there is no defensible way to guess a penalty for
/// a reading that does not exist — it changes what the score is allowed to CLAIM. With anything
/// missing, the number is a strict upper bound (every absent input contributes zero penalty), so the
/// message leads with `Degraded` and names what was not measured, instead of a bare band label that
/// reads as a verdict. `health_score` itself stays an `i32` and is never null or absent:
/// `MoleStatus.swift` is the app's ONE strict `Codable` decoder and does `try c.decode(Int.self,
/// forKey: .healthScore)`, so a null there does not degrade the health ring — it throws, and the
/// dashboard, history charts, MetricsStore and QueryServer all blank together. The case where there
/// is genuinely no number to report is handled a level up, by refusing the whole command
/// ([`Snapshot::nothing_was_measured`]), which never reaches that decoder at all.
pub fn health_of(s: &Snapshot) -> (i32, String) {
    // The health score reads the PRIMARY disk (root) first.
    let root_pct = s
        .disks
        .iter()
        .find(|d| d.mount == "/")
        .or_else(|| s.disks.first())
        .map(|d| d.used_percent)
        .unwrap_or(0.0);
    let batteries: Vec<BatteryStatus> = s
        .battery
        .iter()
        .map(|b| BatteryStatus {
            cycle_count: b.cycles as i64,
            capacity: b.capacity as i64,
        })
        .collect();
    let (score, msg) = calculate_health_score(
        &CpuStatus { usage: s.cpu_usage },
        &MemoryStatus {
            used_percent: s.memory.used_percent,
            pressure: s.memory_pressure.clone(),
        },
        &[DiskStatus {
            used_percent: root_pct,
        }],
        &DiskIoStatus::default(),
        &ThermalStatus::default(),
        &batteries,
        s.uptime_secs,
    );
    if s.unavailable.is_empty() {
        return (score, msg);
    }
    let missing = s
        .unavailable
        .iter()
        .map(|u| u.metric)
        .collect::<Vec<_>>()
        .join(", ");
    (
        score,
        format!("Degraded — not measured: {missing}. Upper bound: {msg}"),
    )
}

/// Run every collector and assemble a snapshot.
///
/// Off-platform and failed collectors still degrade to empties — that is unchanged and correct for
/// the optional panes (a Mac mini reports no batteries; a machine with no GPU reports no GPUs). What
/// IS new is that the four inputs the health score reads are collected through their `_checked`
/// forms and their failures recorded in [`Snapshot::unavailable`], so the difference between "this
/// disk is 0% full" and "`df` could not be run" survives all the way to the JSON. `cli.rs`'s
/// `status` arm refuses outright when none of them could be read.
///
/// One-shot: a fresh [`cpu::CpuSampler`], which costs one [`cpu::MIN_SAMPLE_WINDOW`] of sleep
/// before the pass (the trade `top -l 2` makes for its second sample, and what the oracle's
/// one-shot `status --json` pays too). `status --watch` keeps a sampler across frames through
/// [`collect_with`] and pays nothing.
pub fn collect() -> Snapshot {
    collect_with(&mut cpu::CpuSampler::new())
}

/// [`collect`] with the CPU sampler held by the caller, so a long-lived `--watch` measures each
/// frame's CPU over the whole previous interval instead of sleeping out a fresh window per tick.
pub fn collect_with(sampler: &mut cpu::CpuSampler) -> Snapshot {
    collect_with_watch(
        sampler,
        &mut ProcessWatcher::new(ProcessWatchOptions::default()),
        std::time::Duration::ZERO,
    )
}

pub(crate) fn collect_with_watch(
    sampler: &mut cpu::CpuSampler,
    watcher: &mut ProcessWatcher,
    elapsed: std::time::Duration,
) -> Snapshot {
    // CPU FIRST, before any other collector runs — digger's `collectCPUInto` ordering (commit
    // a6d1a98): the reading is a delta over a window, and a window laid across the pass measures
    // the burst where `top`, `ps`, `system_profiler` and `ioreg` fan out — the collector watching
    // itself, which reported roughly double the machine's idle usage (Burrow #335). The one-shot
    // path sleeps out the window here; a watch already has a full interval behind it.
    if !sampler.has_baseline() {
        sampler.prime(&mut cpu::read_ticks);
    }
    let cpu_reading = sampler.sample(
        std::time::Instant::now(),
        true,
        &mut cpu::read_ticks,
        &mut std::thread::sleep,
    );

    let mut unavailable: Vec<UnavailableMetric> = Vec::new();
    let mut note = |metric: &'static str, probe: &'static str, e: collect::CommandFailure| {
        unavailable.push(UnavailableMetric {
            metric,
            probe,
            reason: e.to_string(),
        });
    };

    let collected_at = collect::collect_collected_at();
    let host = collect::collect_hostname();
    let platform = collect::collect_platform();

    let uptime_secs = match collect::collect_uptime_secs_checked() {
        Ok(v) => v,
        Err(e) => {
            note("uptime_seconds", "sysctl -n kern.boottime", e);
            0
        }
    };
    // `procs` only — `cpu_usage` used to come from this same `top -l 2` sample; FIX 2 (below)
    // takes it from `cpu_per_core`'s own average instead, so the usage half of this pair is
    // discarded here (still one shared spawn for `procs`, not an extra one).
    let (_, procs) = collect::collect_cpu_usage_and_procs();
    let (cpu_load1, cpu_load5, cpu_load15) = collect::collect_loadavg();
    let (cpu_core_count, cpu_logical_cpu) = collect::collect_cpu_counts();
    let memory = match collect::collect_memory_checked() {
        Ok(m) => m,
        Err((e, partial)) => {
            note("memory", "sysctl -n hw.memsize / vm_stat", e);
            partial
        }
    };
    let memory_pressure = collect::collect_memory_pressure();

    // FIX 1 (RULEBOOK): full disk pipeline, now actually matching digger's
    // `collectDisksWithCorrections` (metrics_disk.go:60-136) end to end — raw partitions -> dedupe
    // by base device -> CORRECT total against diskutil -> drop <1GiB volumes -> dedupe by
    // (fstype,total) -> re-dedupe by base device [lower-priority RULEBOOK fix: digger only marks a
    // base device "seen" AFTER a partition survives every filter above, so this must run again
    // here, not just once up front — see `disk::dedupe_by_base_device`'s doc comment] -> CORRECT
    // apfs used/used_percent against Finder/diskutil -> enrich with `external` (diskutil) -> sort
    // internal-first/largest-first -> cap at 3. `external` must be populated before the sort, since
    // the sort key depends on it.
    //
    // This comment previously claimed exact parity while two correction steps
    // (`correct_disk_totals`/`correct_apfs_usages`, wired in below) were entirely missing —
    // `correct_disk_total_bytes`/`extract_plist_uint` existed in `disk.rs` with no caller. On APFS,
    // `df -k /` reports the sealed ~12GB system snapshot's usage against the real multi-hundred-GB
    // container, so `used`/`used_percent` came out ~40x too low on the volume that matters most,
    // inverting the health score's headroom signal. Measured live, same machine, same second,
    // pre-fix: oracle `used_percent=99.27`/"Good: Disk Almost Full" vs this engine
    // `used_percent=2.50`/"Excellent" — RULEBOOK §3's boxed warning.
    let disks = match collect::collect_disks_checked() {
        Ok(d) => d,
        Err(e) => {
            note("disks", "df -kl", e);
            Vec::new()
        }
    };
    let disks = super::disk::dedupe_by_base_device(disks);
    let disks = correct_disk_totals(disks);
    let disks = super::disk::skip_tiny_volumes(disks);
    let disks = super::disk::dedupe_by_fstype_and_total(disks);
    let disks = super::disk::dedupe_by_base_device(disks);
    let mut disks = correct_apfs_usages(disks);
    enrich_disks_with_external(&mut disks);
    let disks = super::disk::sort_and_cap_disks(disks);

    // tier-3, zero consumers (RULEBOOK): total bytes under ~/.Trash, bounded to a 2s walk budget
    // so a huge Trash can't turn `status` into the next unbounded-shell-out hang.
    let (trash_size, trash_approx) = collect::collect_trash_size();

    let battery = collect::collect_battery();
    let root_disk_total = disks
        .iter()
        .find(|d| d.mount == "/")
        .map(|d| d.total)
        .unwrap_or(0);
    let hardware = collect_hardware(memory.total, root_disk_total);

    // `disk_io` is NEVER computed from a rate: the golden's own `disk_io` is `{read_rate: 0,
    // write_rate: 0}` — the shipping conductor is exactly as one-shot as this engine, so it never
    // had a rate to report either. The app's `SnapshotPatcher` (`MetricsCore.swift`) fills this
    // from a native IOKit reading, but ONLY `if moRead == 0, moWrite == 0` — a fabricated
    // non-zero value here would make the patcher stand down and ship a stale/invented number
    // (computed from however old the persisted baseline happened to be) in place of the correct
    // native one, which is long-running, holds its baseline in memory, and uses a monotonic
    // clock — everything a one-shot process can't have. Emitting zeros is not a simplification;
    // it's what the oracle does.
    let disk_io_read_rate = 0.0;
    let disk_io_write_rate = 0.0;

    // ONE `ps` spawn feeds `top_processes` (real top-5) and, only when the real per-core reading
    // above is unavailable, the `cpu.per_core` fallback estimate spread over the SAME sample.
    // Ahead of `health_of` below because health scoring reads `cpu_usage` as an input.
    let ps_result = collect::collect_processes_checked();
    let all_processes = match &ps_result {
        Ok(p) => p.clone(),
        Err(_) => Vec::new(),
    };
    let top_processes = process::top_processes(&all_processes, 5);
    // The real reading when the sampler has one (`per_core_estimated: false`, `cpu.usage` the
    // tick-weighted total); otherwise digger's own fallback (`fallbackCPUUtilization`): the `ps`
    // aggregate spread evenly, flagged estimated, `cpu.usage` its mean. A `ps` failure is noted
    // as `cpu.usage` only on that fallback path — it is then the field whose honesty is at stake,
    // since an unreadable `ps` would put a fabricated `0.0` into the health score.
    let (cpu_usage, cpu_per_core, cpu_per_core_estimated) = match cpu_reading {
        Ok(r) => (r.total, r.per_core, false),
        Err(_) => {
            if let Err(e) = ps_result {
                note("cpu.usage", "ps -Aceo … / ps aux", e);
            }
            let per_core = process::estimate_per_core(&all_processes, cpu_logical_cpu);
            let usage = process::cpu_usage_from_per_core(&per_core);
            (usage, per_core, true)
        }
    };

    // Network rates DO need the persisted baseline: nothing on the app side fills them in
    // (`SnapshotPatcher` touches disk_io/gpu/thermal only — no `network` branch exists in
    // `MetricsCore.swift`), so this engine is the only source of a live rate here. `status` is
    // one-shot with no in-memory baseline the way digger's long-lived Collector has, so the
    // previous sample is read back from disk (see `io_rate`) — the GUI polls `status` on a
    // timer, so from the second invocation onward this reproduces a real rate at no added
    // latency. A missing, corrupt, too-old, or future-dated baseline all degrade to "no
    // baseline" (0.0 rate for every interface), never a command failure or an amplified number.
    //
    // FIX 8 (RULEBOOK): `now_unix_ms` is captured HERE, immediately around the netstat read it
    // labels, not at the top of `collect()`. Everything above this point — `top -l 2`'s ~1.8s, the
    // disk pipeline's diskutil/osascript calls, the trash walk's 0-2s budget, `collect_processes`'s
    // `ps` spawn — runs BEFORE this, so a timestamp captured at function entry mislabels the
    // counters this baseline is FOR by a variable amount (worse the fuller the Trash is). Both the
    // elapsed-time computation below and the baseline this run SAVES for the next invocation need
    // to be anchored to when the counters were actually read, not to when `collect()` started.
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let prev = io_rate::load().filter(|p| io_rate::is_baseline_usable(p.at_unix_ms, now_unix_ms));
    let elapsed_secs = prev
        .as_ref()
        .map(|p| io_rate::elapsed_secs(p.at_unix_ms, now_unix_ms))
        .unwrap_or(io_rate::MIN_SAMPLE_INTERVAL_SECS);
    let prev_net_map: Option<HashMap<String, (u64, u64)>> = prev.as_ref().map(|p| {
        p.network
            .iter()
            .cloned()
            .map(|(n, i, o)| (n, (i, o)))
            .collect()
    });

    // `collect_net_interfaces` distinguishes "netstat couldn't run" (`None`) from "ran and found
    // zero interfaces" (`Some(vec![])`) — a failed read must never be saved as the new baseline,
    // or the NEXT successful read would diff real cumulative bytes against a bogus all-zero
    // "previous" sample and report an absurd rate (this is exactly the bug the deleted disk-IO
    // collector had). On a failed read there's nothing to show for THIS call either (an empty
    // `network[]`, unavoidable without a "last known good" display cache this design doesn't
    // have), but the persisted baseline itself is left untouched for whenever netstat recovers.
    let net_read = collect::collect_net_interfaces();
    let no_interfaces = Vec::new();
    let net_interfaces = net_read.as_ref().unwrap_or(&no_interfaces);
    let ips = collect::collect_interface_ips();
    let network = super::network::build_network_status(
        net_interfaces,
        prev_net_map.as_ref(),
        elapsed_secs,
        &ips,
    );

    if let Some(good) = &net_read {
        io_rate::save(&IoSample {
            at_unix_ms: now_unix_ms,
            network: good
                .iter()
                .map(|i| (i.name.clone(), i.bytes_in, i.bytes_out))
                .collect(),
        });
    }

    // FIX 3 (RULEBOOK): env first, then scutil, then an active utun/tun interface — digger's own
    // precedence (`metrics_network.go::collectProxy`), which this engine had inverted (scutil
    // checked first, with no TUN fallback at all). Moved to here, after `net_interfaces` above, so
    // the TUN fallback can reuse that ALREADY-COLLECTED unfiltered netstat read instead of costing
    // a second shell-out (`network::collect_proxy_from_tun_interfaces` needs the unfiltered list,
    // not the noise-filtered `network[]` display array). Measured live, pre-fix: `HTTPS_PROXY` set
    // in the environment AND scutil's `HTTPSEnable:1` both true at once produced oracle
    // `type:"HTTP"` vs this engine's `type:"HTTPS"`, same instant, same machine.
    let proxy = collect::collect_proxy(net_interfaces);

    // tier-2: batteries / thermal / gpu / bluetooth / cpu.{p,e}_core_count / memory.cached.
    // `decodeIfPresent` in MoleStatus means none of these THROW when missing — they just leave a
    // feature permanently dead, so every one of them is populated here rather than left at its
    // zero `Default`.
    let (cpu_p_core_count, cpu_e_core_count) = collect::collect_core_topology();

    // tier-3, zero consumers: the process-CPU watchdog config echo + its current alerts. This
    // engine has no `--proc-cpu-*` flags, so `process_watch` is always digger's own CLI defaults
    // (`ProcessWatchOptions::default()`). Feeding the SAME `all_processes` sample already spent on
    // `top_processes`/`cpu_per_core` above into a fresh `ProcessWatcher` is real wiring, not a
    // hardcoded stub — but it is provably always `[]` here: `ProcessWatcher::update`'s first-ever
    // call always has `first_above == now`, so the "continuously above threshold for the whole
    // window" check can never pass within the single sample a one-shot process gets. Persisting
    // watcher state across invocations (the only way to ever see a real alert) is out of scope for
    // a field nothing in the app reads.
    let process_watch = ProcessWatchOptions::default();
    let process_alerts = watcher.update_at(elapsed, Some(&collected_at), &all_processes);

    // `batteries` reuses the ioreg dump already spent on `battery` above (no second `ioreg -rn
    // AppleSmartBattery` spawn) for its cycle-count/capacity preference.
    let batteries = collect::collect_batteries(battery.as_ref());

    // `thermal`: cpu_temp/gpu_temp/fan_count are honest, hardcoded zeros — digger never computes
    // them either (see `battery::parse_fan_speed`'s doc comment) — and battery_temp/system_power/
    // adapter_power/battery_power are the SAME ioreg-derived numbers `battery` already carries,
    // re-shaped into their correct container instead of the old misfiled one.
    let fan_speed = collect::collect_fan_speed();
    let battery_thermal = battery
        .as_ref()
        .map(|b| b.thermal.clone())
        .unwrap_or_default();
    let thermal = ThermalInfo {
        cpu_temp: 0.0,
        gpu_temp: 0.0,
        battery_temp: battery_thermal.battery_temp,
        fan_speed,
        fan_count: 0,
        system_power: battery_thermal.system_power,
        adapter_power: battery_thermal.adapter_power,
        battery_power: battery_thermal.battery_power,
    };

    let gpu = collect::collect_gpu();
    let bluetooth = collect::collect_bluetooth();

    let mut snapshot = Snapshot {
        collected_at,
        host,
        platform,
        procs,
        uptime_secs,
        cpu_usage,
        cpu_load1,
        cpu_load5,
        cpu_load15,
        cpu_core_count,
        cpu_logical_cpu,
        cpu_per_core,
        cpu_per_core_estimated,
        cpu_p_core_count,
        cpu_e_core_count,
        memory,
        memory_pressure,
        disks,
        trash_size,
        trash_approx,
        disk_io_read_rate,
        disk_io_write_rate,
        battery,
        proxy,
        network,
        hardware,
        health_score: 0,
        health_msg: String::new(),
        batteries,
        thermal,
        gpu,
        bluetooth,
        top_processes,
        process_watch,
        process_alerts,
        unavailable,
    };
    // Scored over the assembled snapshot, so the score reads the same fields the JSON carries.
    let (health_score, health_msg) = health_of(&snapshot);
    snapshot.health_score = health_score;
    snapshot.health_msg = health_msg;
    snapshot
}

/// FIX 1 (RULEBOOK): correct each disk's `total` against `diskutil info -plist <mount>` when it
/// differs from the statfs-derived total by more than 1 GiB. Matches digger's
/// `collectDisksWithCorrections` calling `correctDiskTotalBytes` on every candidate partition
/// BEFORE the <1GiB filter and the (fstype,total) dedupe (`metrics_disk.go:87-90`) — the corrected
/// total is what those two downstream filters key on, so this must run before both, not after.
fn correct_disk_totals(disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    disks
        .into_iter()
        .map(|mut d| {
            let diskutil_total = super::disk::get_diskutil_total_bytes(&d.mount);
            d.total = super::disk::correct_disk_total_bytes(d.total, diskutil_total);
            d
        })
        .collect()
}

/// FIX 1 (RULEBOOK) — THE headline fix in this slice: correct each APFS disk's `used`/
/// `used_percent`/`free` against Finder (root volume only) or `diskutil`'s `APFSContainerFree`.
/// Matches digger's `correctAPFSDiskUsage`, called only for volumes that already survived the
/// <1GiB filter, the (fstype,total) dedupe, AND the base-device dedupe (`metrics_disk.go:99-103`
/// runs at literal append time) — which is why this runs after all three, and after
/// `correct_disk_totals`, whose corrected `total` this needs.
///
/// On APFS, `df -k /` (and gopsutil's `disk.Usage`, reading the same statfs data) reports the
/// SEALED ~12GB system snapshot's usage against the full multi-hundred-GB CONTAINER total — two
/// different denominators for the same row — so without this, `used`/`used_percent` come out ~40x
/// too low on the volume that matters most, and the health score inverts its single most important
/// signal. Measured live, same machine, same second, pre-fix: oracle `used_percent=99.27`
/// ("Good: Disk Almost Full") vs this engine `used_percent=2.50` ("Excellent") — RULEBOOK §3's
/// boxed warning. `disks[].used`/`used_percent` were previously WRONG despite
/// `correct_disk_total_bytes`/`extract_plist_uint` already existing in `disk.rs` with no caller.
///
/// ROBUSTNESS FIX (this slice): `correct_apfs_disk_usage` can only actually FIX the root volume
/// via tier 1 (Finder/`osascript`) — tier 2 (diskutil) structurally cannot rescue the
/// under-reporting shape of this bug (see that function's "KNOWN FRAGILITY" paragraph), so a
/// headless/SSH/sandboxed-CI/Automation-denied environment silently falls through to tier 3 (raw,
/// still ~40x wrong) with nothing to distinguish it from a genuinely healthy disk. `d.uncorrected`
/// (the function's third return value) makes that failure visible as an ADDITIVE
/// `disks[].uncorrected` JSON key (RULEBOOK RULE 1 — an extra key can't break Swift's `Codable`,
/// which ignores unknown keys) instead of leaving it silent.
///
/// The `free` recompute below is skipped in exactly that case, on purpose: `free = total - used`
/// is a derived identity, so if it always ran, `used + free == total` would hold trivially for
/// EVERY row, correct or not — quietly defeating `value_diff.py`'s `invariants_status` check of
/// that exact identity, which today is the one detector that can catch this class of bug from the
/// engine's own output with no oracle running at all. Leaving `d.free` at whatever `parse_df_k`'s
/// raw `df` "Available" column already put there (measured live on this machine: raw `used`
/// =12.57GB against raw `free`=3.81GB and `total`=494GB — used+free is nowhere near total) means
/// the invariant is honestly violated precisely when, and only when, `uncorrected` is true, so the
/// flag and the independent oracle-free invariant agree instead of one silently overriding the
/// other. This is not a second correction: the raw `free` reading is not touched or recomputed,
/// only NOT overwritten with a value derived from the number we already know may be wrong.
fn correct_apfs_usages(disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    disks
        .into_iter()
        .map(|mut d| {
            if !d.fstype.eq_ignore_ascii_case("apfs") {
                return d;
            }
            let finder = if d.mount == "/" {
                super::disk::get_finder_startup_disk_free_bytes()
            } else {
                None
            };
            let container_free = super::disk::get_apfs_container_free_bytes(&d.mount);
            let (used, used_percent, uncorrected) = super::disk::correct_apfs_disk_usage(
                &d.mount,
                d.total,
                d.used,
                finder,
                container_free,
            );
            d.used = used;
            d.used_percent = used_percent;
            d.uncorrected = uncorrected;
            if !uncorrected {
                d.free = d.total.saturating_sub(d.used);
            }
            // else: leave `d.free` as the raw, independently-sourced `df` reading — see the doc
            // comment above for why recomputing it here would erase the one detector that can
            // catch this failure without an oracle.
            d
        })
        .collect()
}

/// Fill in each disk's `external` flag via `diskutil info`, caching one lookup per physical base
/// device (`disk3s1s1` and `disk3s5` share `disk3`) so a machine with several partitions of the
/// same disk doesn't shell out once per partition.
fn enrich_disks_with_external(disks: &mut [DiskUsage]) {
    let mut cache: HashMap<String, bool> = HashMap::new();
    for d in disks.iter_mut() {
        let base = super::disk::base_device_name(&d.device).to_string();
        let external = *cache
            .entry(base)
            .or_insert_with(|| super::disk::collect_disk_external(&d.device, &d.mount));
        d.external = external;
    }
}

// --- JSON (zero-dep, hand-rolled) ---

use crate::json::escape as esc;

/// A JSON number for a float, trimmed to one decimal. Only `gpu[].usage` still uses this — every
/// OTHER percentage this module emits (`cpu.usage`, `memory.used_percent`, `disks[].used_percent`,
/// `batteries[].percent`) switched to [`num_full`] instead, because the oracle emits all four at
/// full precision (e.g. `cpu.usage=27.582972588453686`, not `27.6`) and rounding them here was a
/// real contract mismatch, not just cosmetic: `value_diff.py` brackets each engine reading between
/// two oracle samples, and a rounded figure can sit measurably outside where an unrounded
/// same-instant reading belongs. `gpu[].usage` doesn't have that problem — this engine's GPU usage
/// is always the sentinel `-1.0` or a hardcoded `0.0`, never a live fractional reading (see
/// `collect_gpu`'s doc comment in `collect.rs`) — so leaving it on `num1` costs nothing and isn't
/// part of this fix.
/// Guards non-finite input: `format!("{v:.1}")` on NaN/inf prints the bare words `NaN`/`inf`,
/// which are not valid JSON literals — spliced unquoted into the output that would break the
/// WHOLE document's parse, not just this one field, so every other correct field goes down with
/// it. 0.0 is a safe, decodable stand-in (matches this module's other non-finite guard, `num_full`).
fn num1(v: f64) -> String {
    if v.is_finite() {
        format!("{v:.1}")
    } else {
        "0.0".to_string()
    }
}

/// A JSON number for a float at FULL precision — unlike `num1`, this does not round to one
/// decimal. The rate/load fields this slice adds (`rx_rate_mbs`, `disk_io.read_rate`, `load1`,
/// ...) are small (0 to low tens) and idle-machine values are commonly < 0.1; rounding to one
/// decimal would print a real 0.0187 MB/s as a misleading, signal-destroying "0.0".
fn num_full(v: f64) -> String {
    if v.is_finite() {
        format!("{v}")
    } else {
        "0".to_string()
    }
}

/// `uncorrected` is an ADDITIVE key (RULEBOOK RULE 1: absent from every golden, since it doesn't
/// exist in the real shipping oracle's contract at all — Swift `Codable` ignores unknown keys, so
/// this cannot break `MoleStatus`'s strict decode). It surfaces `DiskUsage::uncorrected` — see that
/// field's doc comment, and `correct_apfs_usages`'s, for what it means and why it exists. Always
/// emitted, never behind a conditional, so a consumer never needs special-case decoding to read it.
fn disk_json(d: &DiskUsage) -> String {
    format!(
        "{{\"mount\":{},\"device\":{},\"fstype\":{},\"total\":{},\"used\":{},\"free\":{},\"used_percent\":{},\"uncorrected\":{},\"external\":{}}}",
        esc(&d.mount),
        esc(&d.device),
        esc(&d.fstype),
        d.total,
        d.used,
        d.free,
        // FIX (RULEBOOK): full precision, not `num1` — the oracle emits `disks[].used_percent` at
        // full precision (e.g. `98.58012316928169`, not `98.6`). See `num1`'s doc comment.
        num_full(d.used_percent),
        d.uncorrected,
        d.external
    )
}

fn process_json(p: &ProcessInfo) -> String {
    let mut out = format!(
        "{{\"pid\":{},\"ppid\":{},\"name\":{},\"command\":{},\"cpu\":{},\"memory\":{}",
        p.pid,
        p.ppid,
        esc(&p.name),
        esc(&p.command),
        num_full(p.cpu),
        num_full(p.memory),
    );
    // digger's `memory_bytes` carries Go's `json:"memory_bytes,omitempty"` tag — the key vanishes
    // whenever the value is 0, not just when it's unmeasured (`ProcessInfo.memoryBytes: UInt64?`
    // on the Swift side exists BECAUSE of this: it's optional precisely because the key can be
    // absent). Matched here rather than always emitting it.
    if p.memory_bytes > 0 {
        out.push_str(&format!(",\"memory_bytes\":{}", p.memory_bytes));
    }
    out.push('}');
    out
}

/// Serialize a snapshot to the status JSON contract. Pure.
pub fn to_json(s: &Snapshot) -> String {
    let disks = s.disks.iter().map(disk_json).collect::<Vec<_>>().join(",");
    let per_core = s
        .cpu_per_core
        .iter()
        .map(|v| num_full(*v))
        .collect::<Vec<_>>()
        .join(",");
    let mut out = format!(
        "{{\"collected_at\":{},\"host\":{},\"platform\":{},\"procs\":{},\
\"health_score\":{},\"health_score_msg\":{},\"uptime_seconds\":{},\"uptime\":{},\
\"cpu\":{{\"usage\":{},\"load1\":{},\"load5\":{},\"load15\":{},\"core_count\":{},\"logical_cpu\":{},\
\"per_core\":[{}],\"per_core_estimated\":{},\"p_core_count\":{},\"e_core_count\":{}}},\
\"memory\":{{\"total\":{},\"used\":{},\"available\":{},\"used_percent\":{},\"swap_used\":{},\"swap_total\":{},\"cached\":{},\"pressure\":{}}},\
\"disks\":[{}],\"trash_size\":{},\"trash_approx\":{},\
\"disk_io\":{{\"read_rate\":{},\"write_rate\":{}}},\
\"proxy\":{{\"enabled\":{},\"type\":{},\"host\":{}}}",
        esc(&s.collected_at),
        esc(&s.host),
        esc(&s.platform),
        s.procs,
        s.health_score,
        esc(&s.health_msg),
        s.uptime_secs,
        // Purely derived from `uptime_secs` immediately above — no separate Snapshot field, so
        // the two can never drift apart. `format_uptime` is the SAME formatter `health.rs` already
        // ports from digger (`formatUptime` in `cmd/status/metrics_health.go`'s sibling); verified
        // in the golden-anchored test below to reproduce the golden's OWN "3d 2h" from the golden's
        // OWN uptime_seconds (267575), not just internal self-consistency.
        esc(&super::health::format_uptime(s.uptime_secs)),
        // FIX (RULEBOOK): full precision, not `num1` — the oracle emits `cpu.usage` at full
        // precision (e.g. `27.582972588453686`, not `27.6`). See `num1`'s doc comment. This also
        // makes `cpu.usage` exactly equal `mean(cpu.per_core)` (already full-precision below)
        // rather than differing from it by a rounding step, restoring the identity FIX 2 above
        // establishes in the underlying f64 values but which rounding here was quietly breaking
        // again at serialization time.
        num_full(s.cpu_usage),
        num_full(s.cpu_load1),
        num_full(s.cpu_load5),
        num_full(s.cpu_load15),
        s.cpu_core_count,
        s.cpu_logical_cpu,
        per_core,
        s.cpu_per_core_estimated,
        s.cpu_p_core_count,
        s.cpu_e_core_count,
        s.memory.total,
        s.memory.used,
        s.memory.available,
        // FIX (RULEBOOK): full precision, not `num1` — the oracle emits `memory.used_percent` at
        // full precision (e.g. `81.28560384114583`, not `81.3`). See `num1`'s doc comment.
        num_full(s.memory.used_percent),
        s.memory.swap_used,
        s.memory.swap_total,
        s.memory.cached,
        esc(&s.memory_pressure),
        disks,
        s.trash_size,
        s.trash_approx,
        num_full(s.disk_io_read_rate),
        num_full(s.disk_io_write_rate),
        s.proxy.enabled,
        esc(&s.proxy.kind),
        esc(&s.proxy.host),
    );
    // metrics_unavailable — an ADDITIVE key (RULEBOOK RULE 1: Swift `Codable` ignores unknown keys,
    // so this cannot break `MoleStatus`'s strict decode, and no golden carries it because the real
    // shipping oracle has no equivalent). ALWAYS emitted, `[]` on a healthy collection, so a
    // consumer reads one shape and never has to treat a missing key as "everything was fine".
    //
    // This is the machine-readable half of the honesty fix. `health_score_msg` says "Degraded — not
    // measured: disks" in prose for a human; this says WHICH probe failed and HOW, which is the
    // difference between a user knowing something is wrong and knowing that `df -kl` timed out
    // after 3s because a volume is wedged. It is also the key that lets a caller tell a genuinely
    // idle machine from one where nothing was collected — the distinction whose absence let this
    // command report `health_score: 100, "Excellent"` from an entirely empty snapshot.
    let unavailable = s
        .unavailable
        .iter()
        .map(|u| {
            format!(
                "{{\"metric\":{},\"probe\":{},\"reason\":{}}}",
                esc(u.metric),
                esc(u.probe),
                esc(&u.reason)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"metrics_unavailable\":[{unavailable}]"));

    let net = s
        .network
        .iter()
        .map(|n| {
            format!(
                "{{\"name\":{},\"bytes_in\":{},\"bytes_out\":{},\"rx_rate_mbs\":{},\"tx_rate_mbs\":{},\"ip\":{}}}",
                esc(&n.name),
                n.bytes_in,
                n.bytes_out,
                num_full(n.rx_rate_mbs),
                num_full(n.tx_rate_mbs),
                esc(&n.ip),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"network\":[{net}]"));

    // network_history — derived from `s.network` (already top-3-capped by the time it reaches
    // here), not stored separately: see `network::network_history_from`'s doc comment for why a
    // fresh single-element sample IS the correct one-shot answer, matching what even the real
    // oracle's own JSON mode produces.
    let nh = network::network_history_from(&s.network);
    out.push_str(&format!(
        ",\"network_history\":{{\"rx_history\":[{}],\"tx_history\":[{}]}}",
        nh.rx_history
            .iter()
            .map(|v| num_full(*v))
            .collect::<Vec<_>>()
            .join(","),
        nh.tx_history
            .iter()
            .map(|v| num_full(*v))
            .collect::<Vec<_>>()
            .join(","),
    ));

    let hw = &s.hardware;
    out.push_str(&format!(
        ",\"hardware\":{{\"model\":{},\"cpu_model\":{},\"total_ram\":{},\"disk_size\":{},\"os_version\":{},\"refresh_rate\":{}}}",
        esc(&hw.model),
        esc(&hw.cpu_model),
        esc(&hw.total_ram),
        esc(&hw.disk_size),
        esc(&hw.os_version),
        esc(&hw.refresh_rate)
    ));
    // thermal — ALWAYS present, never behind an `if let`: see `ThermalInfo`'s doc comment for why
    // an absent key would permanently disable the app's native fan/cpu-temp/gpu-temp fill.
    out.push_str(&format!(
        ",\"thermal\":{{\"cpu_temp\":{},\"gpu_temp\":{},\"battery_temp\":{},\"fan_speed\":{},\"fan_count\":{},\"system_power\":{},\"adapter_power\":{},\"battery_power\":{}}}",
        num_full(s.thermal.cpu_temp),
        num_full(s.thermal.gpu_temp),
        num_full(s.thermal.battery_temp),
        s.thermal.fan_speed,
        s.thermal.fan_count,
        num_full(s.thermal.system_power),
        num_full(s.thermal.adapter_power),
        num_full(s.thermal.battery_power),
    ));

    // sensors — ALWAYS JSON null. Not a stub: digger's own sensor collection is source-disabled
    // (`cmd/status/metrics.go::collectFull`, right where `collectSensors` would be called: "Sensors
    // disabled - CPU temp already shown in CPU card"), so `collected.sensorStats` is permanently
    // nil and the golden's own `sensors` is `null` too — there is no structure to invent here.
    out.push_str(",\"sensors\":null");

    let batteries = s
        .batteries
        .iter()
        .map(|b| {
            format!(
                "{{\"percent\":{},\"status\":{},\"time_left\":{},\"health\":{},\"cycle_count\":{},\"capacity\":{}}}",
                // FIX (RULEBOOK): full precision, not `num1` — the oracle emits `batteries[].percent`
                // at full precision (see `num1`'s doc comment); `pmset`'s own reading is normally a
                // whole number, but rounding it through `num1` was still the wrong formatter to use
                // for a field the contract expects at full precision.
                num_full(b.percent),
                esc(&b.status),
                esc(&b.time_left),
                esc(&b.health),
                b.cycle_count,
                b.capacity,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"batteries\":[{batteries}]"));

    let gpu = s
        .gpu
        .iter()
        .map(|g| {
            format!(
                "{{\"name\":{},\"usage\":{},\"memory_used\":{},\"memory_total\":{},\"core_count\":{},\"note\":{}}}",
                esc(&g.name),
                num1(g.usage),
                g.memory_used,
                g.memory_total,
                g.core_count,
                esc(&g.note),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"gpu\":[{gpu}]"));

    let bluetooth = s
        .bluetooth
        .iter()
        .map(|d| {
            format!(
                "{{\"name\":{},\"connected\":{},\"battery\":{}}}",
                esc(&d.name),
                d.connected,
                esc(&d.battery),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"bluetooth\":[{bluetooth}]"));

    let top_processes = s
        .top_processes
        .iter()
        .map(process_json)
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"top_processes\":[{top_processes}]"));

    out.push_str(&format!(
        ",\"process_watch\":{{\"enabled\":{},\"cpu_threshold\":{},\"window\":{}}}",
        s.process_watch.enabled,
        num_full(s.process_watch.cpu_threshold),
        esc(&format_go_duration_secs(s.process_watch.window.as_secs())),
    ));
    let process_alerts = s
        .process_alerts
        .iter()
        .map(process_alert_json)
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!(",\"process_alerts\":[{process_alerts}]"));

    out.push('}');
    out
}

/// `ProcessAlert` -> JSON, matching digger's `ProcessAlert` struct (`cmd/status/process_watch.go`)
/// field-for-field. `triggered_at` is the first firing sample's RFC3339 wall-clock timestamp;
/// elapsed-window decisions still use a separate monotonic clock.
fn process_alert_json(a: &ProcessAlert) -> String {
    format!(
        "{{\"pid\":{},\"name\":{},\"command\":{},\"cpu\":{},\"threshold\":{},\"window\":{},\"triggered_at\":{},\"status\":{}}}",
        a.pid,
        esc(&a.name),
        esc(&a.command),
        num_full(a.cpu),
        num_full(a.threshold),
        esc(&format_go_duration_secs(a.window.as_secs())),
        esc(a.triggered_at_text.as_deref().unwrap_or("")),
        esc(&a.status),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_alert_timestamp_is_a_wall_clock_string() {
        let stamp = "2026-09-06T10:01:00.000000+08:00";
        let mut watcher = ProcessWatcher::new(ProcessWatchOptions {
            enabled: true,
            cpu_threshold: 100.0,
            window: std::time::Duration::from_secs(1),
        });
        let hot = [ProcessInfo {
            pid: 42,
            cpu: 140.0,
            ..Default::default()
        }];
        watcher.update_at(std::time::Duration::ZERO, Some(stamp), &hot);
        let alerts = watcher.update_at(std::time::Duration::from_secs(1), Some(stamp), &hot);
        let value = crate::json::Json::parse(&process_alert_json(&alerts[0])).unwrap();
        assert_eq!(
            value
                .get("triggered_at")
                .and_then(crate::json::Json::as_str),
            Some(stamp)
        );
    }
    use crate::json::Json;

    fn disk(mount: &str, pct: f64) -> DiskUsage {
        DiskUsage {
            mount: mount.into(),
            device: "/dev/x".into(),
            fstype: "apfs".into(),
            total: 1000,
            used: 500,
            free: 500,
            used_percent: pct,
            ..Default::default()
        }
    }

    /// An all-zero snapshot is exactly what the collectors used to hand the scorer when none of
    /// them could run, and this pins WHY that produced a perfect score rather than an obvious
    /// failure: every penalty branch in `calculate_health_score` is a strict `>` comparison, so
    /// zero trips none of them and the score never leaves the 100 it starts from.
    ///
    /// The arithmetic is not the bug and is deliberately not changed here — there is no defensible
    /// penalty to invent for a reading that does not exist. What changes is the CLAIM: with
    /// anything unmeasured the message must not read as a verdict.
    #[test]
    fn zero_inputs_score_100_which_is_precisely_why_the_message_must_say_it_was_not_measured() {
        let (score, msg) = health_of(&Snapshot::default());
        assert_eq!(
            (score, msg.as_str()),
            (100, "Excellent"),
            "this is the shape the bug shipped: nothing measured, top marks"
        );

        // The same zeros, now carrying the fact that they are not readings.
        let unavailable: Vec<UnavailableMetric> = REQUIRED_HEALTH_INPUTS
            .iter()
            .map(|metric| UnavailableMetric {
                metric,
                probe: "probe",
                reason: "could not be started".to_string(),
            })
            .collect();
        let (score, msg) = health_of(&Snapshot {
            unavailable,
            ..Default::default()
        });
        assert_eq!(score, 100, "the arithmetic is unchanged — the claim is not");
        assert!(
            !msg.starts_with("Excellent"),
            "an unmeasured score must never lead with a band label: {msg}"
        );
        assert!(
            msg.starts_with("Degraded"),
            "it must announce itself as degraded first: {msg}"
        );
        for metric in REQUIRED_HEALTH_INPUTS {
            assert!(
                msg.contains(metric),
                "the message must name every unmeasured input, missing {metric}: {msg}"
            );
        }
    }

    /// `nothing_was_measured` is the switch `cli.rs` refuses on, so it has to be exactly "all four",
    /// never "any" and never "some". Driven off `REQUIRED_HEALTH_INPUTS` itself rather than a
    /// hand-typed list, so adding a fifth input cannot leave this test silently checking four.
    #[test]
    fn nothing_was_measured_means_all_of_the_required_inputs_not_merely_some() {
        let with = |metrics: &[&'static str]| Snapshot {
            unavailable: metrics
                .iter()
                .map(|m| UnavailableMetric {
                    metric: m,
                    probe: "probe",
                    reason: "could not be started".to_string(),
                })
                .collect(),
            ..Snapshot::default()
        };
        assert!(
            !with(&[]).nothing_was_measured(),
            "a clean collection is not a failed one"
        );
        assert!(
            with(&REQUIRED_HEALTH_INPUTS).nothing_was_measured(),
            "every required input missing IS the refusal case"
        );
        // Every proper subset must still serve the snapshot: losing one pane is a degradation, and
        // refusing the whole command over it would throw away readings that are real.
        for held_back in REQUIRED_HEALTH_INPUTS {
            let some: Vec<&'static str> = REQUIRED_HEALTH_INPUTS
                .iter()
                .copied()
                .filter(|m| *m != held_back)
                .collect();
            assert!(
                !with(&some).nothing_was_measured(),
                "with {held_back} still measured this must remain a partial answer, not a refusal"
            );
        }
    }

    /// `metrics_unavailable` is ALWAYS emitted, `[]` included. A key that appears only on failure
    /// forces every consumer to treat "absent" as "fine", which is the same ambiguity this whole
    /// change exists to remove — and an absent key is indistinguishable from an older engine that
    /// never had one.
    #[test]
    fn metrics_unavailable_is_always_present_and_carries_the_probe_and_the_reason() {
        let healthy = to_json(&Snapshot::default());
        let parsed = Json::parse(&healthy).expect("to_json must emit valid JSON");
        assert_eq!(
            parsed.get("metrics_unavailable"),
            Json::parse("[]").ok().as_ref(),
            "a clean collection still carries the key, empty: {healthy}"
        );

        let degraded = to_json(&Snapshot {
            unavailable: vec![UnavailableMetric {
                metric: "disks",
                probe: "df -kl",
                reason: "timed out after 3s".to_string(),
            }],
            ..Snapshot::default()
        });
        let parsed = Json::parse(&degraded).expect("to_json must emit valid JSON");
        let expected =
            Json::parse(r#"[{"metric":"disks","probe":"df -kl","reason":"timed out after 3s"}]"#)
                .unwrap();
        assert_eq!(
            parsed.get("metrics_unavailable"),
            Some(&expected),
            "the entry must carry which metric, which probe, and why: {degraded}"
        );
    }

    #[test]
    fn health_uses_root_disk_and_battery() {
        // A hot machine on a nearly-full root, with a worn battery → a low score with issues.
        let mem = MemoryUsage {
            used_percent: 95.0,
            ..Default::default()
        };
        let disks = vec![disk("/Volumes/ext", 10.0), disk("/", 98.0)];
        let batt = Some(BatteryReadings {
            cycles: 950,
            capacity: 60,
            ..Default::default()
        });
        let (score, msg) = health_of(&Snapshot {
            cpu_usage: 95.0,
            memory: mem,
            memory_pressure: "critical".into(),
            disks,
            battery: batt,
            uptime_secs: 20 * 86_400,
            ..Default::default()
        });
        assert!(score < 55, "heavy load → low score, got {score}");
        assert!(msg.contains("High CPU"), "{msg}");
        assert!(msg.contains("Disk Almost Full"), "{msg}"); // root (98%), not the ext volume
        assert!(msg.contains("Restart Recommended"), "{msg}"); // 20-day uptime
    }

    #[test]
    fn to_json_matches_the_vendored_golden_for_every_field_this_module_owns() {
        // Load the anonymized public status fixture directly so every captured key, optional
        // field and sentinel remains covered. `scripts/check_fixtures.py` verifies its approved
        // contents; see `FIXTURE_PROVENANCE.md` for the captured authority and anonymization.
        let golden_json: &str = include_str!("status.golden.json");
        let golden = Json::parse(golden_json).expect("vendored golden must parse");
        let g = |key: &str| {
            golden
                .get(key)
                .unwrap_or_else(|| panic!("golden.{key} missing"))
        };
        let gs = |v: &Json| v.as_str().expect("expected a string").to_string();
        let gu = |v: &Json| v.as_u64().expect("expected a non-negative int");
        let gi = |v: &Json| v.as_i64().expect("expected an int");
        let gf = |v: &Json| v.as_f64().expect("expected a number");
        let gb = |v: &Json| v.as_bool().expect("expected a bool");

        let g_cpu = g("cpu");
        let g_mem = g("memory");
        let g_proxy = g("proxy");
        let g_disks = g("disks")
            .as_array()
            .expect("golden.disks must be an array");
        let g_network = g("network")
            .as_array()
            .expect("golden.network must be an array");
        assert!(
            !g_disks.is_empty() && !g_network.is_empty(),
            "golden must carry real rows to anchor against"
        );

        // Build the disks/network Vecs from EVERY golden row (not just row 0), read back through
        // the golden's own accessors — never retyped as a literal.
        let disks: Vec<DiskUsage> = g_disks
            .iter()
            .map(|d| {
                let total = gu(d.get("total").unwrap());
                let used = gu(d.get("used").unwrap());
                DiskUsage {
                    mount: gs(d.get("mount").unwrap()),
                    device: gs(d.get("device").unwrap()),
                    fstype: gs(d.get("fstype").unwrap()),
                    total,
                    used,
                    free: total.saturating_sub(used), // not in the golden; not under test here
                    used_percent: gf(d.get("used_percent").unwrap()),
                    // Not in the golden either — the real shipping oracle's contract has no such
                    // key, since this field is this engine's own addition (RULE 1: additive,
                    // never a replacement). `false` is the honest choice to feed through THIS
                    // test: the golden's own numbers are a real, successfully-collected capture
                    // from the shipping program, i.e. exactly what a `false` ("not uncorrected")
                    // row looks like. See `to_json_flags_an_uncorrected_apfs_disk_and_keeps_its_
                    // raw_free_honest` below for the `true` case, which has no golden analog to
                    // anchor to at all.
                    uncorrected: false,
                    external: gb(d.get("external").unwrap()),
                }
            })
            .collect();

        let network: Vec<NetworkStatus> = g_network
            .iter()
            .map(|n| NetworkStatus {
                name: gs(n.get("name").unwrap()),
                bytes_in: 0, // not in the golden — this module's own extra, not under test here
                bytes_out: 0,
                rx_rate_mbs: gf(n.get("rx_rate_mbs").unwrap()),
                tx_rate_mbs: gf(n.get("tx_rate_mbs").unwrap()),
                ip: gs(n.get("ip").unwrap()),
            })
            .collect();

        // The 9 tier-2 fields this test extends coverage to: `decodeIfPresent` in MoleStatus means
        // none of these throw when missing, so an empty golden array here would be exactly the
        // "golden with an empty spine is blind" trap RULEBOOK §3b warns about — assert real rows
        // exist before trusting anything built from them.
        let g_thermal = g("thermal");
        let g_batteries = g("batteries")
            .as_array()
            .expect("golden.batteries must be an array");
        let g_gpu = g("gpu").as_array().expect("golden.gpu must be an array");
        let g_bluetooth = g("bluetooth")
            .as_array()
            .expect("golden.bluetooth must be an array");
        let g_top_processes = g("top_processes")
            .as_array()
            .expect("golden.top_processes must be an array");
        let g_per_core = g_cpu
            .get("per_core")
            .and_then(Json::as_array)
            .expect("golden.cpu.per_core must be an array");
        // tier-3 (RULEBOOK): zero consumers in MoleStatus.swift, needed only for judge parity.
        let g_process_watch = g("process_watch");
        assert!(
            !g_batteries.is_empty()
                && !g_gpu.is_empty()
                && !g_bluetooth.is_empty()
                && !g_top_processes.is_empty()
                && !g_per_core.is_empty(),
            "golden must carry real rows to anchor every tier-2 field against"
        );

        let cpu_per_core: Vec<f64> = g_per_core
            .iter()
            .map(|v| v.as_f64().expect("cpu.per_core element must be a number"))
            .collect();

        let batteries: Vec<BatteryEntry> = g_batteries
            .iter()
            .map(|b| BatteryEntry {
                percent: gf(b.get("percent").unwrap()),
                status: gs(b.get("status").unwrap()),
                time_left: gs(b.get("time_left").unwrap()),
                health: gs(b.get("health").unwrap()),
                cycle_count: gi(b.get("cycle_count").unwrap()) as i32,
                capacity: gi(b.get("capacity").unwrap()) as i32,
            })
            .collect();

        let gpu: Vec<GpuInfo> = g_gpu
            .iter()
            .map(|el| GpuInfo {
                name: gs(el.get("name").unwrap()),
                usage: gf(el.get("usage").unwrap()),
                memory_used: gu(el.get("memory_used").unwrap()),
                memory_total: gu(el.get("memory_total").unwrap()),
                core_count: gi(el.get("core_count").unwrap()),
                note: gs(el.get("note").unwrap()),
            })
            .collect();

        let bluetooth: Vec<BluetoothDevice> = g_bluetooth
            .iter()
            .map(|d| BluetoothDevice {
                name: gs(d.get("name").unwrap()),
                connected: gb(d.get("connected").unwrap()),
                battery: gs(d.get("battery").unwrap()),
            })
            .collect();

        let top_processes: Vec<ProcessInfo> = g_top_processes
            .iter()
            .map(|p| ProcessInfo {
                pid: gi(p.get("pid").unwrap()) as i32,
                ppid: gi(p.get("ppid").unwrap()) as i32,
                name: gs(p.get("name").unwrap()),
                command: gs(p.get("command").unwrap()),
                cpu: gf(p.get("cpu").unwrap()),
                memory: gf(p.get("memory").unwrap()),
                memory_bytes: p.get("memory_bytes").map(gu).unwrap_or(0),
            })
            .collect();

        let thermal = ThermalInfo {
            cpu_temp: gf(g_thermal.get("cpu_temp").unwrap()),
            gpu_temp: gf(g_thermal.get("gpu_temp").unwrap()),
            battery_temp: gf(g_thermal.get("battery_temp").unwrap()),
            fan_speed: gi(g_thermal.get("fan_speed").unwrap()) as i32,
            fan_count: gi(g_thermal.get("fan_count").unwrap()) as i32,
            system_power: gf(g_thermal.get("system_power").unwrap()),
            adapter_power: gf(g_thermal.get("adapter_power").unwrap()),
            battery_power: gf(g_thermal.get("battery_power").unwrap()),
        };

        let s = Snapshot {
            collected_at: gs(g("collected_at")),
            host: gs(g("host")),
            platform: gs(g("platform")),
            procs: gu(g("procs")),
            uptime_secs: gu(g("uptime_seconds")),
            cpu_usage: gf(g_cpu.get("usage").unwrap()),
            cpu_load1: gf(g_cpu.get("load1").unwrap()),
            cpu_load5: gf(g_cpu.get("load5").unwrap()),
            cpu_load15: gf(g_cpu.get("load15").unwrap()),
            cpu_core_count: gi(g_cpu.get("core_count").unwrap()),
            cpu_logical_cpu: gi(g_cpu.get("logical_cpu").unwrap()),
            cpu_per_core,
            cpu_p_core_count: gi(g_cpu.get("p_core_count").unwrap()),
            cpu_e_core_count: gi(g_cpu.get("e_core_count").unwrap()),
            memory: MemoryUsage {
                total: gu(g_mem.get("total").unwrap()),
                used: gu(g_mem.get("used").unwrap()),
                available: gu(g_mem.get("available").unwrap()),
                used_percent: gf(g_mem.get("used_percent").unwrap()),
                swap_used: gu(g_mem.get("swap_used").unwrap()),
                swap_total: gu(g_mem.get("swap_total").unwrap()),
                cached: gu(g_mem.get("cached").unwrap()),
            },
            // A per-sample fact (whether the real tick reading succeeded), not a captured value:
            // the golden's `false` is THAT capture's digger succeeding. Here the literal is the
            // fallback shape, and the assertion below checks the serializer round-trips it.
            cpu_per_core_estimated: true,
            memory_pressure: gs(g_mem.get("pressure").unwrap()),
            disks,
            // Exact passthrough, no derived math — read straight from the golden like every other
            // plain collected field above.
            trash_size: gu(g("trash_size")),
            trash_approx: gb(g("trash_approx")),
            // This module NEVER computes a disk_io rate (see `collect`'s doc comment) — it always
            // emits {0,0}, which is what the golden itself carries too (the oracle is one-shot
            // just like this engine), so the round-trip matches without reading it back.
            disk_io_read_rate: 0.0,
            disk_io_write_rate: 0.0,
            // Raw-ioreg input only (see the field's doc comment) — `thermal`/`batteries` below are
            // built straight from the golden instead, so this doesn't need to be populated too.
            battery: None,
            proxy: ProxyStatus {
                enabled: gb(g_proxy.get("enabled").unwrap()),
                kind: gs(g_proxy.get("type").unwrap()),
                host: gs(g_proxy.get("host").unwrap()),
            },
            network,
            hardware: HardwareInfo::default(), // not this slice's fields
            health_score: gi(g("health_score")) as i32,
            health_msg: gs(g("health_score_msg")),
            batteries,
            thermal,
            gpu,
            bluetooth,
            top_processes,
            // This engine's hardcoded default happens to BE digger's CLI-flag default — checked
            // value-for-value against the golden below, same as every other field this module owns,
            // rather than read back from the golden into the input (which would only prove
            // serialization, not that the chosen DEFAULT is correct).
            process_watch: ProcessWatchOptions::default(),
            // Always empty from `collect()` — see the field's own doc comment on `Snapshot`.
            process_alerts: Vec::new(),
            // The golden was captured from a real machine on which everything WAS measured, so the
            // shape it anchors is the healthy one: empty here, and `metrics_unavailable: []` in the
            // output. The degraded shape has no golden — the shipping oracle has no equivalent key
            // — and is pinned by `cli`'s end-to-end reproduction instead.
            unavailable: Vec::new(),
        };

        let json = to_json(&s);
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(!json.contains(",,"), "no trailing/double comma");
        let engine = Json::parse(&json).expect("to_json must emit valid JSON");

        // Value-for-value against the golden's OWN values, iterating its keys rather than
        // picking them by hand, for every field this module is responsible for.
        for key in [
            "collected_at",
            "host",
            "platform",
            "procs",
            "health_score",
            "health_score_msg",
            "uptime_seconds",
            "disk_io",
        ] {
            assert_eq!(engine.get(key), golden.get(key), "top-level {key}");
        }

        let e_cpu = engine.get("cpu").expect("engine must emit cpu");
        for key in [
            "load1",
            "load5",
            "load15",
            "core_count",
            "logical_cpu",
            "p_core_count",
            "e_core_count",
        ] {
            assert_eq!(e_cpu.get(key), g_cpu.get(key), "cpu.{key}");
        }
        // `per_core` is formatted at FULL precision (`num_full`, not the rounding `num1`), so this
        // is exact equality, not a tolerance check — see `to_json`'s per_core-building comment.
        let e_per_core = e_cpu
            .get("per_core")
            .and_then(Json::as_array)
            .expect("engine must emit cpu.per_core");
        assert_eq!(e_per_core.len(), g_per_core.len());
        for (e, g) in e_per_core.iter().zip(g_per_core.iter()) {
            assert_eq!(e.as_f64(), g.as_f64(), "cpu.per_core[] element");
        }

        // FIX (RULEBOOK): `memory.used_percent`, `disks[].used_percent` and `batteries[].percent`
        // used to round through `num1` (1 decimal), so they were never bit-identical to the
        // golden's full-precision float and needed a tolerance check rather than exact equality.
        // They now serialize via `num_full` (see `to_json`'s call sites), matching the oracle's own
        // full precision, so all three are checked with plain `assert_eq!` below instead. This
        // helper survives for `gpu[].usage` only, which stays on `num1` — this engine's GPU usage
        // is always the sentinel `-1.0`/hardcoded `0.0`, never a live fractional reading (see
        // `collect_gpu`'s doc comment), so a tolerance check there is still the right shape even
        // though in practice the golden's own `-1` passes it exactly either way.
        let assert_rounds_to =
            |engine_val: Option<&Json>, golden_val: Option<&Json>, path: &str| {
                let e = engine_val
                    .and_then(Json::as_f64)
                    .unwrap_or_else(|| panic!("engine missing {path}"));
                let g = golden_val
                    .and_then(Json::as_f64)
                    .unwrap_or_else(|| panic!("golden missing {path}"));
                assert!(
                    (e - g).abs() < 0.05 + 1e-9,
                    "{path}: engine {e} must be the golden's {g} rounded to 1 decimal"
                );
            };

        let e_mem = engine.get("memory").expect("engine must emit memory");
        for key in [
            "total",
            "used",
            "available",
            "swap_used",
            "swap_total",
            "cached",
            "pressure",
        ] {
            assert_eq!(e_mem.get(key), g_mem.get(key), "memory.{key}");
        }
        // Exact, not `assert_rounds_to` — `memory.used_percent` now serializes via `num_full`.
        assert_eq!(
            e_mem.get("used_percent").and_then(Json::as_f64),
            g_mem.get("used_percent").and_then(Json::as_f64),
            "memory.used_percent"
        );

        let e_proxy = engine.get("proxy").expect("engine must emit proxy");
        for key in ["enabled", "type", "host"] {
            assert_eq!(e_proxy.get(key), g_proxy.get(key), "proxy.{key}");
        }

        let e_disks = engine
            .get("disks")
            .and_then(Json::as_array)
            .expect("engine must emit a disks array");
        assert_eq!(e_disks.len(), g_disks.len());
        for (e, g) in e_disks.iter().zip(g_disks.iter()) {
            for key in ["mount", "device", "fstype", "total", "used", "external"] {
                assert_eq!(e.get(key), g.get(key), "disks[].{key}");
            }
            // Exact, not `assert_rounds_to` — `disks[].used_percent` now serializes via `num_full`.
            assert_eq!(
                e.get("used_percent").and_then(Json::as_f64),
                g.get("used_percent").and_then(Json::as_f64),
                "disks[].used_percent"
            );
            // Not golden-anchored (see the `uncorrected: false` comment on the DiskUsage literal
            // above) — asserted directly, same treatment as `cpu.per_core_estimated` elsewhere in
            // this test, since neither has a golden-side value to read back.
            assert_eq!(
                e.get("uncorrected"),
                Some(&Json::Bool(false)),
                "disks[].uncorrected must be present and false for a successfully-collected row"
            );
        }

        let e_network = engine
            .get("network")
            .and_then(Json::as_array)
            .expect("engine must emit a network array");
        assert_eq!(e_network.len(), g_network.len());
        for (e, g) in e_network.iter().zip(g_network.iter()) {
            for key in ["name", "rx_rate_mbs", "tx_rate_mbs", "ip"] {
                assert_eq!(e.get(key), g.get(key), "network[].{key}");
            }
        }

        // thermal — ALWAYS present (see `ThermalInfo`'s doc comment); every field is `num_full`
        // (exact), not `num1` (rounded), so this is exact equality throughout.
        let e_thermal = engine
            .get("thermal")
            .expect("engine must emit thermal (never behind an Option)");
        for key in [
            "cpu_temp",
            "gpu_temp",
            "battery_temp",
            "fan_speed",
            "fan_count",
            "system_power",
            "adapter_power",
            "battery_power",
        ] {
            assert_eq!(e_thermal.get(key), g_thermal.get(key), "thermal.{key}");
        }

        let e_batteries = engine
            .get("batteries")
            .and_then(Json::as_array)
            .expect("engine must emit a batteries array");
        assert_eq!(e_batteries.len(), g_batteries.len());
        for (e, g) in e_batteries.iter().zip(g_batteries.iter()) {
            for key in ["status", "time_left", "health", "cycle_count", "capacity"] {
                assert_eq!(e.get(key), g.get(key), "batteries[].{key}");
            }
            // Exact, not `assert_rounds_to` — `percent` now serializes via `num_full`.
            assert_eq!(
                e.get("percent").and_then(Json::as_f64),
                g.get("percent").and_then(Json::as_f64),
                "batteries[].percent"
            );
        }

        let e_gpu = engine
            .get("gpu")
            .and_then(Json::as_array)
            .expect("engine must emit a gpu array");
        assert_eq!(e_gpu.len(), g_gpu.len());
        for (e, g) in e_gpu.iter().zip(g_gpu.iter()) {
            for key in ["name", "memory_used", "memory_total", "core_count", "note"] {
                assert_eq!(e.get(key), g.get(key), "gpu[].{key}");
            }
            assert_rounds_to(e.get("usage"), g.get("usage"), "gpu[].usage");
        }

        let e_bluetooth = engine
            .get("bluetooth")
            .and_then(Json::as_array)
            .expect("engine must emit a bluetooth array");
        assert_eq!(e_bluetooth.len(), g_bluetooth.len());
        for (e, g) in e_bluetooth.iter().zip(g_bluetooth.iter()) {
            for key in ["name", "connected", "battery"] {
                assert_eq!(e.get(key), g.get(key), "bluetooth[].{key}");
            }
        }

        let e_top_processes = engine
            .get("top_processes")
            .and_then(Json::as_array)
            .expect("engine must emit a top_processes array");
        assert_eq!(e_top_processes.len(), g_top_processes.len());
        for (e, g) in e_top_processes.iter().zip(g_top_processes.iter()) {
            for key in ["pid", "ppid", "name", "command", "memory_bytes"] {
                assert_eq!(e.get(key), g.get(key), "top_processes[].{key}");
            }
            // `cpu`/`memory` are `num_full` (exact), unlike the rounded percentage fields above.
            assert_eq!(e.get("cpu"), g.get("cpu"), "top_processes[].cpu");
            assert_eq!(e.get("memory"), g.get("memory"), "top_processes[].memory");
        }

        // tier-3 (RULEBOOK): zero consumers in MoleStatus.swift today (verified: none of these
        // eight keys — uptime, trash_size, trash_approx, network_history, sensors, process_watch,
        // process_alerts, cpu.per_core_estimated — appear in its CodingKeys), needed only for
        // judge parity. Golden-anchored value-for-value wherever the golden's own value IS what
        // this engine should reproduce; documented as a deliberate divergence where it structurally
        // can't be.

        // uptime: derived from uptime_seconds via format_uptime (see the arg list above) — checked
        // against the golden's OWN "uptime" string, not just internal self-consistency.
        assert_eq!(
            engine.get("uptime").and_then(Json::as_str),
            golden.get("uptime").and_then(Json::as_str),
            "uptime"
        );

        // trash_size / trash_approx: exact passthrough, no rounding.
        assert_eq!(
            engine.get("trash_size"),
            golden.get("trash_size"),
            "trash_size"
        );
        assert_eq!(
            engine.get("trash_approx"),
            golden.get("trash_approx"),
            "trash_approx"
        );

        // cpu.per_core_estimated: NOT compared to the golden's own `false` — it is a per-sample
        // fact (did the real tick reading succeed), so the literal above set it and the JSON must
        // carry what the literal said.
        assert_eq!(
            e_cpu.get("per_core_estimated"),
            Some(&Json::Bool(true)),
            "cpu.per_core_estimated round-trips the snapshot's own value"
        );

        // network_history: sum of the (already top-3-capped) `network` rows, wrapped as
        // single-element arrays — checked against the golden's OWN network_history, not merely
        // internal consistency with the engine's own network array. This also happens to prove
        // the "sum the TRUNCATED list" derivation is right: summing the golden's OWN
        // network[].rx_rate_mbs/tx_rate_mbs reproduces the golden's OWN
        // network_history.rx_history[0]/tx_history[0] exactly.
        let e_nh = engine
            .get("network_history")
            .expect("engine must emit network_history");
        let g_nh = g("network_history");
        for side in ["rx_history", "tx_history"] {
            let e_arr = e_nh
                .get(side)
                .and_then(Json::as_array)
                .unwrap_or_else(|| panic!("engine.network_history.{side} must be an array"));
            let g_arr = g_nh
                .get(side)
                .and_then(Json::as_array)
                .unwrap_or_else(|| panic!("golden.network_history.{side} must be an array"));
            assert_eq!(e_arr.len(), g_arr.len(), "network_history.{side} length");
            for (e, g) in e_arr.iter().zip(g_arr.iter()) {
                assert_eq!(e.as_f64(), g.as_f64(), "network_history.{side}[]");
            }
        }

        // sensors: always JSON null — see `to_json`'s comment at the splice site. The golden's own
        // value is null too, so this doubles as a golden-anchored check, not just a hardcoded one.
        assert_eq!(engine.get("sensors"), Some(&Json::Null), "sensors");
        assert_eq!(
            golden.get("sensors"),
            Some(&Json::Null),
            "golden's own sensors must be null too — confirms this isn't a stale assumption"
        );

        // process_watch: this engine's hardcoded default happens to be digger's own CLI-flag
        // default, so — unlike most "always constant" fields in this module — it IS checked
        // value-for-value against the golden.
        let e_pw = engine
            .get("process_watch")
            .expect("engine must emit process_watch");
        assert_eq!(
            e_pw.get("enabled"),
            g_process_watch.get("enabled"),
            "process_watch.enabled"
        );
        assert_eq!(
            e_pw.get("window"),
            g_process_watch.get("window"),
            "process_watch.window"
        );
        assert_eq!(
            e_pw.get("cpu_threshold").and_then(Json::as_f64),
            g_process_watch.get("cpu_threshold").and_then(Json::as_f64),
            "process_watch.cpu_threshold"
        );

        // process_alerts: always [] from a one-shot invocation — see the field's doc comment on
        // `Snapshot`. The golden's own value is [] too.
        assert_eq!(
            engine
                .get("process_alerts")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0),
            "process_alerts"
        );
        assert_eq!(
            golden
                .get("process_alerts")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0),
            "golden's own process_alerts must be empty too"
        );
    }

    #[test]
    // check_tests: no-golden — there is no capture of the shipping oracle failing to correct a
    // disk (Finder/osascript refused), because the oracle is the ONE side that structurally cannot
    // demonstrate its own failure to a golden file. This test pins the engine's OWN robustness
    // behaviour (RULEBOOK RULE 1: an additive field) directly, the same way
    // `to_json_always_emits_the_tier2_containers_even_with_nothing_collected` below pins structural
    // facts no golden captures either.
    fn to_json_flags_an_uncorrected_apfs_disk_and_keeps_its_raw_free_honest() {
        // Same root-volume numbers as `apfs_usage_correction_flags_uncorrected_when_finder_fails_
        // on_the_root_volume` in disk.rs (same live measurement behind RULEBOOK §3's boxed
        // warning): `correct_apfs_usages` would produce exactly this row if Finder/osascript gave
        // nothing and diskutil gave nothing either — headless, over SSH, sandboxed CI, or
        // Automation/TCC denied. `free` is left at the RAW `df` reading (not `total - used`) —
        // see `correct_apfs_usages`'s doc comment for why recomputing it here would hide the
        // failure from `value_diff.py`'s `used + free == total` invariant.
        let total = 494_384_795_648u64;
        let raw_used = 12_573_351_936u64;
        let raw_free = 3_807_326_208u64; // this machine's own `df -k /` Available column, live
        let s = Snapshot {
            disks: vec![DiskUsage {
                mount: "/".into(),
                device: "/dev/disk3s1s1".into(),
                fstype: "apfs".into(),
                total,
                used: raw_used,
                free: raw_free,
                used_percent: raw_used as f64 / total as f64 * 100.0,
                uncorrected: true,
                external: false,
            }],
            ..Default::default()
        };
        let parsed = Json::parse(&to_json(&s)).expect("to_json must emit valid JSON");
        let disk = &parsed.get("disks").and_then(Json::as_array).unwrap()[0];

        assert_eq!(
            disk.get("uncorrected"),
            Some(&Json::Bool(true)),
            "the failure must be visible on the wire, not silent"
        );
        // RULEBOOK §3h: never invent a number where an honest one exists. `used`/`free` must be
        // exactly the raw inputs, byte for byte — not silently "fixed", not zeroed, not dropped.
        assert_eq!(disk.get("used").and_then(Json::as_u64), Some(raw_used));
        assert_eq!(disk.get("free").and_then(Json::as_u64), Some(raw_free));
        // The property the whole slice is built around: when `uncorrected` is true, `used + free`
        // must NOT equal `total` — that gap is exactly what lets `value_diff.py`'s internal
        // invariant (`invariants_status`, "used + free == total") catch this from the engine's own
        // row alone, with no oracle running. If this ever equalled `total` again, the invariant
        // would go back to being trivially satisfied on every row and this whole detector would go
        // blind again, silently.
        let used = disk.get("used").and_then(Json::as_u64).unwrap();
        let free = disk.get("free").and_then(Json::as_u64).unwrap();
        let total_out = disk.get("total").and_then(Json::as_u64).unwrap();
        assert_ne!(
            used + free,
            total_out,
            "an uncorrected row must honestly disagree with itself, not paper over the failure"
        );
    }

    #[test]
    // check_tests: no-golden — Snapshot::default() (nothing collected) has no oracle capture: the
    // reference machine that produced status.golden.json has real battery/GPU/bluetooth/process
    // data for all of these. See this test's own body comment for the full reasoning.
    fn to_json_always_emits_the_tier2_containers_even_with_nothing_collected() {
        // Distinct from the golden-anchored test above on purpose: there is no golden for "a
        // machine with no battery/GPU/bluetooth/processes collected" — the reference machine has
        // all of them — so this is a structural/presence check of `Snapshot::default()`, not a
        // contract-value check. What it pins: (1) the OLD misfiled singular `"battery"` key must
        // never reappear now that its data moved into `thermal`/`batteries` (RULEBOOK §3), and (2)
        // every tier-2 container is ALWAYS emitted — `thermal` as an object, the rest as arrays —
        // never omitted, matching digger's own non-optional serialization of every one of these
        // fields (RULEBOOK §1: decodeIfPresent tolerates a missing key, but digger never sends one).
        let s = Snapshot {
            health_score: 100,
            health_msg: "Excellent".into(),
            ..Default::default()
        };
        let j = to_json(&s);
        let parsed = Json::parse(&j).expect("to_json must emit valid JSON even when empty");

        assert!(
            !j.contains("\"battery\":"),
            "the old misfiled singular `battery` key must be gone, not merely empty: {j}"
        );
        assert_eq!(
            parsed.get("disks").and_then(Json::as_array).map(<[_]>::len),
            Some(0)
        );
        assert_eq!(
            parsed
                .get("batteries")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0)
        );
        assert_eq!(
            parsed.get("gpu").and_then(Json::as_array).map(<[_]>::len),
            Some(0)
        );
        assert_eq!(
            parsed
                .get("bluetooth")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0)
        );
        assert_eq!(
            parsed
                .get("top_processes")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0)
        );
        assert_eq!(
            parsed
                .get("cpu")
                .and_then(|c| c.get("per_core"))
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0)
        );
        // thermal is an OBJECT (never an array, never omitted) even with nothing collected.
        let thermal = parsed
            .get("thermal")
            .expect("thermal must be present even when everything else is empty/default");
        assert_eq!(thermal.get("cpu_temp").and_then(Json::as_f64), Some(0.0));
        assert_eq!(thermal.get("fan_count").and_then(Json::as_i64), Some(0));

        // tier-3 containers: ALSO always present even with nothing collected, same rule as tier-2
        // above — a future refactor must not be able to put one of these behind a conditional that
        // skips it whenever some unrelated field is zero/empty.
        assert!(
            parsed.get("uptime").and_then(Json::as_str).is_some(),
            "uptime must be present (and a string) even when uptime_secs is 0"
        );
        assert_eq!(parsed.get("trash_size").and_then(Json::as_u64), Some(0));
        assert_eq!(
            parsed.get("trash_approx").and_then(Json::as_bool),
            Some(false)
        );
        assert_eq!(parsed.get("sensors"), Some(&Json::Null));
        assert!(
            parsed
                .get("cpu")
                .and_then(|c| c.get("per_core_estimated"))
                .and_then(Json::as_bool)
                .is_some(),
            "cpu.per_core_estimated must be present even with nothing collected"
        );

        // network_history is present and, per its own doc comment, holds EXACTLY one sample per
        // side even when `network` is empty — never zero elements (an empty array here would be
        // the same "decodes clean, renders empty" trap RULEBOOK §6 calls out for other lists,
        // even though nothing currently reads this field) and never more than one from a single
        // invocation.
        let nh = parsed
            .get("network_history")
            .expect("network_history must be present when empty too");
        let rx = nh
            .get("rx_history")
            .and_then(Json::as_array)
            .expect("rx_history must be an array");
        let tx = nh
            .get("tx_history")
            .and_then(Json::as_array)
            .expect("tx_history must be an array");
        assert_eq!(
            rx.len(),
            1,
            "exactly one sample even with an empty network[]"
        );
        assert_eq!(tx.len(), 1);
        assert_eq!(rx[0].as_f64(), Some(0.0));
        assert_eq!(tx[0].as_f64(), Some(0.0));

        // process_watch is present (it's a config echo, not derived from collected data, so it's
        // populated even here) and process_alerts is an always-empty array, never omitted.
        let pw = parsed
            .get("process_watch")
            .expect("process_watch must be present even when empty too");
        assert!(pw.get("enabled").and_then(Json::as_bool).is_some());
        assert_eq!(
            parsed
                .get("process_alerts")
                .and_then(Json::as_array)
                .map(<[_]>::len),
            Some(0)
        );
    }

    #[test]
    // check_tests: no-golden — this is a self-consistency check of `to_json`'s OWN output (no
    // oracle value is asserted), so there is nothing to load a golden for.
    fn json_cpu_usage_exactly_equals_the_mean_of_json_per_core_not_merely_close_to_it() {
        // FIX (RULEBOOK): before switching `cpu.usage` from `num1` (rounds to 1 decimal) to
        // `num_full`, `cpu.usage` and `mean(cpu.per_core)` were computed from the identical f64
        // (`process::cpu_usage_from_per_core`, see FIX 2's doc comment on `collect()`), but
        // serializing ONLY `cpu.usage` through a rounding formatter reintroduced a gap between them
        // at the JSON layer — measured live, pre-fix: `11.3000` (rounded `cpu.usage`) beside
        // `11.2929` (the true mean of the full-precision `per_core` array), a real, if small,
        // internal contradiction in a single response. Both fields now go through `num_full`, so
        // this must hold EXACTLY, not just within a tolerance.
        let s = Snapshot {
            cpu_usage: 11.292857142857143,
            cpu_per_core: vec![11.292857142857143; 14],
            ..Default::default()
        };
        let parsed = Json::parse(&to_json(&s)).expect("to_json must emit valid JSON");
        let usage = parsed
            .get("cpu")
            .and_then(|c| c.get("usage"))
            .and_then(Json::as_f64)
            .expect("cpu.usage must be present");
        let per_core = parsed
            .get("cpu")
            .and_then(|c| c.get("per_core"))
            .and_then(Json::as_array)
            .expect("cpu.per_core must be an array");
        let mean: f64 = per_core
            .iter()
            .map(|v| v.as_f64().expect("per_core element must be a number"))
            .sum::<f64>()
            / per_core.len() as f64;
        assert_eq!(
            usage, mean,
            "cpu.usage must exactly equal mean(cpu.per_core) once both are full precision"
        );
        // Not a round number — if either field were still going through `num1`'s 1-decimal
        // rounding, this specific value would expose it (11.292857… rounds to 11.3, which is NOT
        // equal to the unrounded 11.292857142857143).
        assert!(
            (usage - 11.3).abs() > 1e-6,
            "sanity check: this test's input must not happen to be round-number-safe"
        );
    }
}
