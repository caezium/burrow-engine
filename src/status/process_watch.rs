//! The process CPU watchdog — ported from digger's `cmd/status/process_watch.go`. A process must
//! stay at or above the CPU threshold continuously for the whole window before it alerts; any dip
//! resets it, and PID reuse (a different ppid/command on the same pid) starts fresh tracking.
//!
//! Pure w.r.t. the clock: `update` takes `now` (a monotonic `Duration` since an arbitrary base) so
//! the whole thing is testable without real time. Feeding it the process list is the collector's job.

use super::process::ProcessInfo;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProcessWatchOptions {
    pub enabled: bool,
    pub cpu_threshold: f64,
    pub window: Duration,
}

impl Default for ProcessWatchOptions {
    /// digger's CLI flag defaults (`cmd/status/main.go`): `--proc-cpu-alerts` defaults to `true`,
    /// `--proc-cpu-threshold` to `100`, `--proc-cpu-window` to 5 minutes. This engine exposes no
    /// equivalent flags — `status` takes no arguments at all — so this is the ONLY config `status`
    /// ever echoes under `process_watch`, and it is not invented: it matches the golden's own
    /// `process_watch: {enabled:true, cpu_threshold:100, window:"5m0s"}` value-for-value (verified
    /// in `snapshot.rs`'s golden-anchored test, not just asserted here).
    fn default() -> Self {
        ProcessWatchOptions {
            enabled: true,
            cpu_threshold: 100.0,
            window: Duration::from_secs(5 * 60),
        }
    }
}

/// Format a WHOLE-SECOND `Duration` the way Go's `time.Duration.String()` does — read off Go's own
/// algorithm (`time/format.go`), not guessed: seconds are always printed, minutes are prefixed only
/// once the total reaches a minute, hours only once it reaches an hour (`45s`, `5m0s`, `1h1m1s`).
/// This engine only ever feeds it whole-second `process_watch`/`ProcessAlert` windows, so the
/// sub-second-precision branches of Go's real formatter (which only trigger under a second) are not
/// reproduced — there is no input in this codebase that would ever reach them. `ProcessWatchConfig`
/// (`cmd/status/process_watch.go`) serializes `Window` via this exact `.String()` call, and the
/// golden's `process_watch.window` — `"5m0s"` for a 5-minute `Duration` — is that call's real
/// output, which is what pins the shape here rather than Go's docs alone.
pub fn format_go_duration_secs(total_secs: u64) -> String {
    let secs = total_secs % 60;
    let total_mins = total_secs / 60;
    if total_mins == 0 {
        return format!("{secs}s");
    }
    let mins = total_mins % 60;
    let hours = total_mins / 60;
    if hours == 0 {
        return format!("{mins}m{secs}s");
    }
    format!("{hours}h{mins}m{secs}s")
}

/// A fired watchdog alert (a process that has been hot for the full window).
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessAlert {
    pub pid: i32,
    pub name: String,
    pub command: String,
    pub cpu: f64,
    pub threshold: f64,
    pub window: Duration,
    pub triggered_at: Duration,
    /// The sample's wall-clock timestamp when the alert first fired. Kept separately from the
    /// monotonic clock used to measure the window, so the wire timestamp remains stable.
    pub triggered_at_text: Option<String>,
    pub status: String,
}

/// A process is identified by pid + ppid + command; when a pid is reused by a different process
/// these differ, so the old tracking is dropped and the new one starts fresh.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Identity {
    pid: i32,
    ppid: i32,
    command: String,
}

#[derive(Debug, Default)]
struct Tracked {
    info: ProcessInfo,
    first_above: Option<Duration>,
    triggered_at: Option<Duration>,
    triggered_at_text: Option<String>,
    current_above: bool,
}

pub struct ProcessWatcher {
    options: ProcessWatchOptions,
    tracks: HashMap<Identity, Tracked>,
}

impl ProcessWatcher {
    pub fn new(options: ProcessWatchOptions) -> Self {
        ProcessWatcher {
            options,
            tracks: HashMap::new(),
        }
    }

    /// Feed the latest process sample at time `now`; returns the currently-firing alerts.
    pub fn update(&mut self, now: Duration, processes: &[ProcessInfo]) -> Vec<ProcessAlert> {
        self.update_at(now, None, processes)
    }

    pub(crate) fn update_at(
        &mut self,
        now: Duration,
        wall_time: Option<&str>,
        processes: &[ProcessInfo],
    ) -> Vec<ProcessAlert> {
        if !self.options.enabled {
            return Vec::new();
        }
        let mut seen: HashSet<Identity> = HashSet::with_capacity(processes.len());
        for proc in processes {
            if proc.pid <= 0 {
                continue;
            }
            let key = Identity {
                pid: proc.pid,
                ppid: proc.ppid,
                command: proc.command.clone(),
            };
            seen.insert(key.clone());
            let track = self.tracks.entry(key).or_default();
            track.info = proc.clone();
            track.current_above = proc.cpu >= self.options.cpu_threshold;

            if track.current_above {
                let first = *track.first_above.get_or_insert(now);
                if now.saturating_sub(first) >= self.options.window && track.triggered_at.is_none()
                {
                    track.triggered_at = Some(now);
                    track.triggered_at_text = wall_time.map(str::to_string);
                }
            } else {
                track.first_above = None;
                track.triggered_at = None;
                track.triggered_at_text = None;
            }
        }
        // Drop processes that vanished this sample (also how PID reuse is handled).
        self.tracks.retain(|key, _| seen.contains(key));
        self.snapshot()
    }

    /// The currently-firing alerts, ordered: earliest-triggered first, then hottest, then lowest pid.
    pub fn snapshot(&self) -> Vec<ProcessAlert> {
        if !self.options.enabled {
            return Vec::new();
        }
        let mut alerts: Vec<ProcessAlert> = self
            .tracks
            .values()
            .filter(|t| t.current_above && t.triggered_at.is_some())
            .map(|t| ProcessAlert {
                pid: t.info.pid,
                name: t.info.name.clone(),
                command: t.info.command.clone(),
                cpu: t.info.cpu,
                threshold: self.options.cpu_threshold,
                window: self.options.window,
                triggered_at: t.triggered_at.unwrap(),
                triggered_at_text: t.triggered_at_text.clone(),
                status: "active".to_string(),
            })
            .collect();
        alerts.sort_by(|a, b| {
            use std::cmp::Ordering::Equal;
            a.triggered_at
                .cmp(&b.triggered_at)
                .then(b.cpu.partial_cmp(&a.cpu).unwrap_or(Equal))
                .then(a.pid.cmp(&b.pid))
        });
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(threshold: f64, window_secs: u64) -> ProcessWatchOptions {
        ProcessWatchOptions {
            enabled: true,
            cpu_threshold: threshold,
            window: Duration::from_secs(window_secs),
        }
    }

    fn proc(pid: i32, ppid: i32, command: &str, cpu: f64) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            command: command.into(),
            cpu,
            ..Default::default()
        }
    }

    fn mins(m: u64) -> Duration {
        Duration::from_secs(m * 60)
    }

    #[test]
    fn triggers_only_after_a_continuous_window() {
        let mut w = ProcessWatcher::new(opts(100.0, 5 * 60));
        let hot = [proc(42, 1, "stress", 140.0)];
        assert!(w.update(mins(0), &hot).is_empty());
        assert!(w.update(mins(4), &hot).is_empty());
        let alerts = w.update(mins(5), &hot);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].status, "active");
    }

    #[test]
    fn firing_timestamp_is_retained_until_the_process_cools() {
        let mut w = ProcessWatcher::new(opts(100.0, 60));
        let hot = [proc(42, 1, "stress", 140.0)];
        let first = "2026-09-06T10:01:00Z";
        let later = "2026-09-06T10:02:00Z";
        assert!(w.update_at(mins(0), Some(first), &hot).is_empty());
        let alerts = w.update_at(mins(1), Some(first), &hot);
        assert_eq!(alerts[0].triggered_at_text.as_deref(), Some(first));
        let alerts = w.update_at(mins(2), Some(later), &hot);
        assert_eq!(alerts[0].triggered_at_text.as_deref(), Some(first));
        let cool = [proc(42, 1, "stress", 10.0)];
        assert!(w.update_at(mins(3), Some(later), &cool).is_empty());
        assert!(w.update_at(mins(4), Some(later), &hot).is_empty());
        let alerts = w.update_at(mins(5), Some(later), &hot);
        assert_eq!(alerts[0].triggered_at_text.as_deref(), Some(later));
    }

    #[test]
    fn a_dip_resets_the_window() {
        let mut w = ProcessWatcher::new(opts(100.0, 5 * 60));
        let hot = [proc(42, 1, "stress", 140.0)];
        let cool = [proc(42, 1, "stress", 30.0)];
        w.update(mins(0), &hot);
        w.update(mins(4), &hot);
        assert!(
            w.update(Duration::from_secs(4 * 60 + 30), &cool).is_empty(),
            "dip resets"
        );
        assert!(
            w.update(mins(9), &hot).is_empty(),
            "fresh window not yet full"
        );
        assert_eq!(
            w.update(mins(14), &hot).len(),
            1,
            "alerts after a second full window"
        );
    }

    #[test]
    fn pid_reuse_starts_fresh() {
        let mut w = ProcessWatcher::new(opts(100.0, 2 * 60));
        let first = [proc(42, 1, "/usr/bin/stress", 140.0)];
        let reused = [proc(42, 99, "/usr/local/bin/node /tmp/server.js", 135.0)];
        w.update(mins(0), &first);
        assert_eq!(
            w.update(mins(2), &first).len(),
            1,
            "first process alerts after its window"
        );
        assert!(
            w.update(mins(3), &reused).is_empty(),
            "pid reuse resets tracking"
        );
        assert_eq!(
            w.update(mins(5), &reused).len(),
            1,
            "reused pid alerts only after its own window"
        );
    }

    #[test]
    fn disabled_watcher_never_alerts() {
        let mut w = ProcessWatcher::new(ProcessWatchOptions {
            enabled: false,
            cpu_threshold: 1.0,
            window: Duration::ZERO,
        });
        assert!(w.update(mins(10), &[proc(1, 0, "x", 999.0)]).is_empty());
    }

    #[test]
    fn default_options_match_diggers_cli_flag_defaults() {
        let o = ProcessWatchOptions::default();
        assert!(o.enabled);
        assert_eq!(o.cpu_threshold, 100.0);
        assert_eq!(o.window, Duration::from_secs(300));
    }

    // check_tests: no-golden — a pure formatter unit test with no serializer call in its body
    // (asserts against `format_go_duration_secs` directly, not `to_json`), so RULEBOOK §3e's
    // golden-loading rule doesn't apply to it; the one value this DOES need to match a captured
    // oracle string ("5m0s") is pinned separately in `snapshot.rs`'s `include_str!`-anchored test.
    // This table only pins the general algorithm (Go's minute/hour thresholds) against values no
    // golden carries.
    #[test]
    fn format_go_duration_secs_matches_gos_algorithm() {
        let cases: &[(u64, &str)] = &[
            (0, "0s"),
            (5, "5s"),
            (59, "59s"),
            (60, "1m0s"),
            (90, "1m30s"),
            (300, "5m0s"), // the golden's own process_watch.window value
            (3600, "1h0m0s"),
            (3661, "1h1m1s"),
        ];
        for &(secs, want) in cases {
            assert_eq!(
                format_go_duration_secs(secs),
                want,
                "format_go_duration_secs({secs})"
            );
        }
    }
}
