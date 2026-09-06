//! CPU utilisation sampled over a REAL window — the port of digger's `cmd/status/metrics_cpu.go`
//! after commit `a6d1a98` ("sample CPU over a real window instead of a 100ms self-inflicted
//! slice", Burrow #335).
//!
//! Two readings of the per-core tick counters behind Mach's `host_processor_info`
//! (`PROCESSOR_CPU_LOAD_INFO`: user/system/idle/nice ticks per logical CPU, credited at
//! `kern.clockrate` hz = 100) are turned into per-core busy percentages and a tick-weighted total.
//! What that fixes, in the oracle's words and reproduced here:
//!
//! - **The window must be wide.** 100ms accrues ~10 ticks per core, so every per-core reading
//!   collapses onto a multiple of ~1/10 (the 0 / 9.09 / 55.56 / 66.67 values of #335). The minimum
//!   window is [`MIN_SAMPLE_WINDOW`] (600ms, ~60 ticks), and a long-lived sampler — `status
//!   --watch` — reuses the previous frame's reading as the baseline, so its window is the whole
//!   refresh interval and it never sleeps for a sample.
//! - **The total is tick-weighted, not the mean of the per-core percentages.** A parked core that
//!   accrued one busy tick reads 100% and would swing an unweighted mean as hard as a fully
//!   sampled core; summing busy and total ticks first weights every core by the time it actually
//!   accounted for (`cpuPercentFromTimes`).
//! - **Sample before the pass, not across it.** The engine's other collectors fan out to
//!   `system_profiler`, `ioreg`, `top` and `ps`; a window laid over that burst measures the
//!   collector watching itself. `snapshot::collect_with` samples CPU first.
//!
//! This engine had regressed all three: `cpu.per_core` was the aggregate of `ps`'s `%CPU` column
//! spread evenly over the cores (never a per-core reading at all, hence `per_core_estimated:
//! true` on every sample), and `cpu.usage` was that estimate's mean. That path survives as the
//! fallback, exactly as `fallbackCPUUtilization` is digger's fallback.
//!
//! The arithmetic ([`percent_from_ticks`]) and the baseline policy ([`CpuSampler::sample`]) are
//! pure and driven by an injected tick reader + sleep, so the Go commit's fixture tests port
//! verbatim; only [`read_ticks`] touches Mach, and only on macOS (an `extern "C"` into libSystem —
//! no crate, same as `platform::effective_uid`).

use std::time::{Duration, Instant};

/// The shortest window a percentage is reported from — 600ms, ~60 ticks per core at 100hz, which
/// puts per-core quantisation under 2 points (`minCPUSampleWindow`).
pub const MIN_SAMPLE_WINDOW: Duration = Duration::from_millis(600);

/// How stale a cached baseline may be before it describes a long-gone average rather than "now"
/// and is resampled (`maxCPUSampleWindow`).
pub const MAX_SAMPLE_WINDOW: Duration = Duration::from_secs(300);

/// One logical CPU's cumulative tick counters — the four `CPU_STATE_*` slots
/// `PROCESSOR_CPU_LOAD_INFO` reports, widened from the kernel's `u32`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoreTicks {
    pub user: u64,
    pub system: u64,
    pub idle: u64,
    pub nice: u64,
}

impl CoreTicks {
    /// A snapshot from (busy, idle) — the shape the oracle's fixtures are written in (`ticks(…)`
    /// in `metrics_cpu_sample_test.go` fills `User` and `Idle` only).
    pub const fn busy_idle(busy: u64, idle: u64) -> CoreTicks {
        CoreTicks {
            user: busy,
            system: 0,
            idle,
            nice: 0,
        }
    }
}

/// Busy and total tick deltas between two readings of one CPU. Each counter's delta is floored at
/// zero so a reset cannot produce a negative (`cpuBusyTotal`); the kernel's `u32` counters wrap
/// every ~497 days at 100hz, which reads as one reset — one under-reported frame — rather than a
/// bogus 100%.
fn busy_total(prev: &CoreTicks, cur: &CoreTicks) -> (f64, f64) {
    let delta = |a: u64, b: u64| b.saturating_sub(a) as f64;
    let busy =
        delta(prev.user, cur.user) + delta(prev.system, cur.system) + delta(prev.nice, cur.nice);
    let idle = delta(prev.idle, cur.idle);
    (busy, busy + idle)
}

fn clamp_percent(v: f64) -> f64 {
    v.clamp(0.0, 100.0)
}

/// Two per-CPU tick snapshots → `(total, per_core, ticks)`: per-core busy percentages, the
/// tick-weighted total (summed busy over summed total ticks — NOT the mean of `per_core`, see the
/// module doc), and the total tick delta the window accrued, so a caller can tell a genuinely idle
/// machine from a window that closed before the counters advanced (`cpuPercentFromTimes`).
///
/// `prev` and `cur` must describe the same cores; extra entries in either are ignored.
pub fn percent_from_ticks(prev: &[CoreTicks], cur: &[CoreTicks]) -> (f64, Vec<f64>, f64) {
    let mut per_core = vec![0.0; cur.len()];
    let mut total_busy = 0.0;
    let mut ticks = 0.0;
    for (i, (p, c)) in prev.iter().zip(cur).enumerate() {
        let (busy, all) = busy_total(p, c);
        if all > 0.0 {
            per_core[i] = clamp_percent(busy / all * 100.0);
        }
        total_busy += busy;
        ticks += all;
    }
    if ticks <= 0.0 {
        return (0.0, per_core, 0.0);
    }
    (clamp_percent(total_busy / ticks * 100.0), per_core, ticks)
}

/// A reading: the tick-weighted total and the per-core percentages, from one real window.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuReading {
    pub total: f64,
    pub per_core: Vec<f64>,
}

/// The baseline-holding sampler (digger's `Collector.prevCPUTimes`/`lastCPUAt`). One per process:
/// a one-shot `status` makes one, sleeps out a window, and is done; `status --watch` keeps one
/// across frames so each frame's window is the previous interval.
#[derive(Debug, Default)]
pub struct CpuSampler {
    baseline: Option<(Vec<CoreTicks>, Instant)>,
}

impl CpuSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the first tick baseline now (`primeCPUCounters`) so the window a one-shot run has to
    /// wait out is as short as possible. A failed read leaves no baseline; `sample` copes.
    pub fn prime(&mut self, read: &mut impl FnMut() -> Result<Vec<CoreTicks>, String>) {
        if let Ok(t) = read() {
            if !t.is_empty() {
                self.baseline = Some((t, Instant::now()));
            }
        }
    }

    /// Whether a baseline exists — what `status --watch` relies on to skip the sleep.
    pub fn has_baseline(&self) -> bool {
        self.baseline.is_some()
    }

    /// The reading since the cached baseline (`cpuUsageSinceBaseline`), then advance the baseline
    /// to this reading.
    ///
    /// - A baseline between [`MIN_SAMPLE_WINDOW`] and [`MAX_SAMPLE_WINDOW`] old is used as is: no
    ///   sleep, one tick read.
    /// - `may_block: false` (a fast refresh) never sleeps: a young baseline is divided by anyway
    ///   (noisier, but real), and only a wholly missing one gives up — leaving a baseline for next
    ///   time.
    /// - `may_block: true` (the slow, one-shot path) sleeps out whatever the window is still short
    ///   by — the REMAINDER when a baseline is merely young, a full window when it is missing or
    ///   stale — through `sleep`, then reads again.
    ///
    /// `Err` means "unavailable", never 0%: a window that accrued no ticks is unmeasurable, and
    /// reporting it as idle would put a fabricated number into the health score.
    pub fn sample(
        &mut self,
        now: Instant,
        may_block: bool,
        read: &mut impl FnMut() -> Result<Vec<CoreTicks>, String>,
        sleep: &mut impl FnMut(Duration),
    ) -> Result<CpuReading, String> {
        let mut cur = read()?;
        if cur.is_empty() {
            return Err("no per-cpu times available".into());
        }
        let mut now = now;
        let (mut baseline, elapsed) = match &self.baseline {
            Some((b, at)) if b.len() == cur.len() => {
                let elapsed = now.saturating_duration_since(*at);
                if elapsed > Duration::ZERO {
                    (Some(b.clone()), elapsed)
                } else {
                    (None, Duration::ZERO)
                }
            }
            _ => (None, Duration::ZERO),
        };
        let usable =
            baseline.is_some() && elapsed >= MIN_SAMPLE_WINDOW && elapsed <= MAX_SAMPLE_WINDOW;
        if !usable {
            if !may_block {
                if baseline.is_none() {
                    self.baseline = Some((cur, now));
                    return Err("cpu baseline not ready".into());
                }
                // Young baseline on the fast path: a sub-window delta is still a measurement.
            } else {
                let wait = match baseline {
                    Some(_) if elapsed < MIN_SAMPLE_WINDOW => MIN_SAMPLE_WINDOW - elapsed,
                    _ => {
                        baseline = Some(cur.clone());
                        MIN_SAMPLE_WINDOW
                    }
                };
                sleep(wait);
                let fresh = read()?;
                if fresh.len() != cur.len() {
                    return Err("cpu core count changed mid-sample".into());
                }
                cur = fresh;
                now = Instant::now();
            }
        }
        let prev = baseline.expect("a baseline exists on every path that reaches here");
        let (total, per_core, ticks) = percent_from_ticks(&prev, &cur);
        self.baseline = Some((cur, now));
        if ticks <= 0.0 {
            return Err("cpu sample window accrued no ticks".into());
        }
        Ok(CpuReading { total, per_core })
    }
}

/// Read every logical CPU's tick counters through Mach `host_processor_info`. macOS only; the
/// call cannot fail for a normal process, and the buffer it hands back is returned to the kernel
/// with `vm_deallocate`, the host port with `mach_port_deallocate`, so a long `--watch` leaks
/// neither.
#[cfg(target_os = "macos")]
pub fn read_ticks() -> Result<Vec<CoreTicks>, String> {
    const PROCESSOR_CPU_LOAD_INFO: i32 = 2;
    const CPU_STATE_MAX: usize = 4;
    const KERN_SUCCESS: i32 = 0;
    extern "C" {
        static mach_task_self_: u32;
        fn mach_host_self() -> u32;
        fn host_processor_info(
            host: u32,
            flavor: i32,
            out_processor_count: *mut u32,
            out_processor_info: *mut *mut i32,
            out_processor_info_cnt: *mut u32,
        ) -> i32;
        fn vm_deallocate(target_task: u32, address: usize, size: usize) -> i32;
        fn mach_port_deallocate(task: u32, name: u32) -> i32;
    }
    let mut count: u32 = 0;
    let mut info: *mut i32 = std::ptr::null_mut();
    let mut info_count: u32 = 0;
    // SAFETY: every pointer is to a local the kernel fills; `info` is a kernel-allocated buffer of
    // `info_count` `i32`s that we read within bounds and then hand back exactly once.
    unsafe {
        let host = mach_host_self();
        let kr = host_processor_info(
            host,
            PROCESSOR_CPU_LOAD_INFO,
            &mut count,
            &mut info,
            &mut info_count,
        );
        let _ = mach_port_deallocate(mach_task_self_, host);
        if kr != KERN_SUCCESS || info.is_null() {
            return Err(format!("host_processor_info failed with kern_return {kr}"));
        }
        let words = std::slice::from_raw_parts(info, info_count as usize);
        let cores = (count as usize).min(words.len() / CPU_STATE_MAX);
        let ticks = (0..cores)
            .map(|i| {
                let w = &words[i * CPU_STATE_MAX..(i + 1) * CPU_STATE_MAX];
                CoreTicks {
                    user: w[0] as u32 as u64,
                    system: w[1] as u32 as u64,
                    idle: w[2] as u32 as u64,
                    nice: w[3] as u32 as u64,
                }
            })
            .collect();
        let _ = vm_deallocate(
            mach_task_self_,
            info as usize,
            info_count as usize * std::mem::size_of::<i32>(),
        );
        Ok(ticks)
    }
}

/// Off macOS there is no `host_processor_info`; the caller falls back to the `ps` estimate.
#[cfg(not(target_os = "macos"))]
pub fn read_ticks() -> Result<Vec<CoreTicks>, String> {
    Err("per-core cpu ticks are unavailable on this platform".into())
}

#[cfg(test)]
mod tests {
    //! The oracle's `metrics_cpu_sample_test.go` (commit `a6d1a98`), fixture for fixture. The
    //! tick reader and the sleep are injected, so no test waits out a real window.
    use super::*;
    use std::cell::RefCell;

    fn ticks(pairs: &[(u64, u64)]) -> Vec<CoreTicks> {
        pairs
            .iter()
            .map(|&(b, i)| CoreTicks::busy_idle(b, i))
            .collect()
    }

    fn approx(got: f64, want: f64, label: &str) {
        assert!(
            (got - want).abs() <= 0.01,
            "{label} = {got:.4}, want {want:.4}"
        );
    }

    /// A reader handing out `samples` in order, counting the calls; an empty sequence errors.
    fn stub(
        samples: Vec<Vec<CoreTicks>>,
    ) -> (
        impl FnMut() -> Result<Vec<CoreTicks>, String>,
        std::rc::Rc<RefCell<usize>>,
    ) {
        let calls = std::rc::Rc::new(RefCell::new(0usize));
        let c = calls.clone();
        let reader = move || {
            let mut n = c.borrow_mut();
            let s = samples
                .get(*n)
                .cloned()
                .ok_or_else(|| "no more stubbed samples".to_string());
            *n += 1;
            s
        };
        (reader, calls)
    }

    fn no_sleep() -> impl FnMut(Duration) {
        |d| panic!("must not sleep, slept {d:?}")
    }

    /// `TestCPUTotalIsTickWeightedNotMeanOfCores`: one parked core with a single busy tick beside
    /// three fully-sampled, almost-idle cores. An unweighted mean says ~28%; the tick-weighted
    /// answer is ~4%. Burrow #335 was this shape of over-report.
    #[test]
    fn total_is_tick_weighted_not_the_mean_of_cores() {
        let prev = ticks(&[(0, 0), (0, 0), (0, 0), (0, 0)]);
        let cur = ticks(&[(1, 0), (4, 96), (4, 96), (4, 96)]);
        let (total, per_core, tick_total) = percent_from_ticks(&prev, &cur);
        approx(per_core[0], 100.0, "per_core[0]");
        approx(per_core[1], 4.0, "per_core[1]");
        approx(tick_total, 301.0, "tick total");
        approx(total, 13.0 / 301.0 * 100.0, "total");
        let mean = per_core.iter().sum::<f64>() / per_core.len() as f64;
        assert!(
            mean - total >= 20.0,
            "the unweighted mean ({mean:.2}) must overstate the tick-weighted total ({total:.2})"
        );
    }

    /// `TestCPUPercentClampsCounterResets`.
    #[test]
    fn counter_resets_floor_to_zero() {
        let prev = ticks(&[(500, 500)]);
        let cur = ticks(&[(10, 20)]);
        let (total, per_core, tick_total) = percent_from_ticks(&prev, &cur);
        assert_eq!((total, per_core[0], tick_total), (0.0, 0.0, 0.0));
    }

    /// `TestCPUUsesCachedBaselineWithoutBlocking`: a baseline wide enough to use is consumed
    /// directly — no sleeping, and no discarding it in favour of a fresh short window.
    #[test]
    fn a_usable_baseline_is_consumed_without_blocking() {
        let mut s = CpuSampler {
            baseline: Some((
                ticks(&[(0, 0), (0, 0)]),
                Instant::now() - Duration::from_secs(1),
            )),
        };
        let (mut read, calls) = stub(vec![ticks(&[(25, 75), (75, 25)])]);
        let r = s
            .sample(Instant::now(), true, &mut read, &mut no_sleep())
            .expect("reading");
        assert_eq!(
            *calls.borrow(),
            1,
            "a single tick read against the cached baseline"
        );
        approx(r.per_core[0], 25.0, "per_core[0]");
        approx(r.per_core[1], 75.0, "per_core[1]");
        approx(r.total, 50.0, "total");
    }

    /// `TestCPUResamplesWhenBaselineIsStale`: a baseline older than the maximum window describes
    /// a long-gone average, so the sampler takes a fresh window instead of dividing by it.
    #[test]
    fn a_stale_baseline_forces_a_fresh_window() {
        let mut s = CpuSampler {
            baseline: Some((ticks(&[(0, 0)]), Instant::now() - 2 * MAX_SAMPLE_WINDOW)),
        };
        let (mut read, calls) = stub(vec![ticks(&[(1000, 1000)]), ticks(&[(1030, 1070)])]);
        let slept = RefCell::new(Vec::new());
        let r = s
            .sample(Instant::now(), true, &mut read, &mut |d| {
                slept.borrow_mut().push(d)
            })
            .expect("reading");
        assert_eq!(
            *calls.borrow(),
            2,
            "stale baseline: a fresh window (2 reads)"
        );
        assert_eq!(slept.borrow().as_slice(), [MIN_SAMPLE_WINDOW]);
        approx(r.total, 30.0, "total");
    }

    /// A merely-young baseline is extended, not discarded: the sleep is the REMAINDER of the
    /// window and the reading spans the whole of it.
    #[test]
    fn a_young_baseline_sleeps_only_the_remainder() {
        let mut s = CpuSampler {
            baseline: Some((
                ticks(&[(0, 0)]),
                Instant::now() - Duration::from_millis(400),
            )),
        };
        let (mut read, calls) = stub(vec![ticks(&[(10, 10)]), ticks(&[(20, 40)])]);
        let slept = RefCell::new(Vec::new());
        let r = s
            .sample(Instant::now(), true, &mut read, &mut |d| {
                slept.borrow_mut().push(d)
            })
            .expect("reading");
        assert_eq!(*calls.borrow(), 2);
        let waited = slept.borrow()[0];
        assert!(
            waited > Duration::from_millis(150) && waited <= Duration::from_millis(200),
            "slept the remainder of 600ms, not a full window: {waited:?}"
        );
        approx(
            r.total,
            20.0 / 60.0 * 100.0,
            "total spans from the ORIGINAL baseline",
        );
    }

    /// `TestCPUFastPathNeverBlocks`: no baseline at all, `may_block: false` → an error, no sleep,
    /// and a baseline left for the next refresh.
    #[test]
    fn the_fast_path_never_blocks() {
        let mut s = CpuSampler::new();
        let (mut read, _) = stub(vec![ticks(&[(10, 90)])]);
        let err = s
            .sample(Instant::now(), false, &mut read, &mut no_sleep())
            .expect_err("no baseline");
        assert!(err.contains("baseline"), "{err}");
        assert!(
            s.has_baseline(),
            "the fast path leaves a baseline for the next refresh"
        );
    }

    /// `TestCPUZeroTickWindowIsAnError`: a window that closes before the counters advance is
    /// unmeasurable, not idle.
    #[test]
    fn a_zero_tick_window_is_an_error_not_idle() {
        let base = ticks(&[(100, 100)]);
        let mut s = CpuSampler {
            baseline: Some((base.clone(), Instant::now() - Duration::from_millis(1))),
        };
        let (mut read, _) = stub(vec![base]);
        assert!(s
            .sample(Instant::now(), false, &mut read, &mut no_sleep())
            .is_err());
    }

    /// `TestCPUSampleWindowIsWideEnoughToResolvePercentPoints`: 100ms only accrues ~10 ticks per
    /// core at macOS's 100hz, which is what quantised per-core readings to ~10% steps in #335.
    #[test]
    fn the_sample_window_resolves_percent_points() {
        const DARWIN_TICK_HZ: f64 = 100.0;
        let ticks_per_core = MIN_SAMPLE_WINDOW.as_secs_f64() * DARWIN_TICK_HZ;
        assert!(
            ticks_per_core >= 50.0,
            "{MIN_SAMPLE_WINDOW:?} yields only {ticks_per_core:.0} ticks per core; per-core \
             readings quantise to {:.1}% steps",
            100.0 / ticks_per_core
        );
    }

    /// The watch shape: prime, then every later sample reuses the previous frame as its baseline
    /// — one read per frame, no sleep, `per_core` from the real deltas.
    #[test]
    fn watch_frames_reuse_the_previous_frame_as_baseline() {
        let mut s = CpuSampler::new();
        let (mut read, calls) = stub(vec![
            ticks(&[(0, 0), (0, 0)]),
            ticks(&[(60, 40), (10, 90)]),
            ticks(&[(120, 80), (60, 140)]),
        ]);
        s.prime(&mut read);
        assert!(s.has_baseline());
        let t1 = Instant::now() + Duration::from_secs(2);
        let r1 = s.sample(t1, false, &mut read, &mut no_sleep()).unwrap();
        assert_eq!(r1.per_core, vec![60.0, 10.0]);
        approx(r1.total, 35.0, "frame 1 total");
        let r2 = s
            .sample(
                t1 + Duration::from_secs(2),
                false,
                &mut read,
                &mut no_sleep(),
            )
            .unwrap();
        assert_eq!(r2.per_core, vec![60.0, 50.0]);
        approx(r2.total, 55.0, "frame 2 total");
        assert_eq!(*calls.borrow(), 3, "one read per frame after priming");
    }

    /// The real reader, on the platform that has it: one entry per logical CPU and counters that
    /// move — which is all that can be asserted without pinning the machine.
    #[cfg(target_os = "macos")]
    #[test]
    fn host_processor_info_reads_one_entry_per_core() {
        let first = read_ticks().expect("host_processor_info");
        assert!(!first.is_empty());
        assert!(first
            .iter()
            .any(|c| c.user + c.system + c.idle + c.nice > 0));
        let again = read_ticks().unwrap();
        assert_eq!(again.len(), first.len());
    }
}
