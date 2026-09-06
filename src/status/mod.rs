//! System status — the engine reimplementation of digger's `cmd/status`.
//!
//! `cmd/status` is large and mostly native-syscall metric collection (IOKit/SMC/gopsutil), which
//! lands here incrementally. The pure kernels come first (bottom-up, like analyze): `health` — the
//! 0-100 system-health score and its severity helpers — is a pure function of already-collected
//! metrics, so it ports and tests cleanly ahead of the collectors. The TUI (`view.go`) is not
//! ported; the GUI renders its own status.

pub mod battery;
pub mod bluetooth;
pub mod collect;
pub mod cpu;
pub mod disk;
pub mod gpu;
pub mod hardware;
pub mod health;
pub mod io_rate;
pub mod network;
pub mod process;
pub mod process_watch;
pub mod snapshot;

/// Delta between two readings of a monotonic cumulative counter (bytes read, packets, …), clamping
/// a counter reset (current < previous, e.g. after a device re-enumerates) to 0 instead of
/// underflowing. Shared by the disk-IO and network rate collectors. From digger's `counterDelta`.
pub fn counter_delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_delta_clamps_reset() {
        assert_eq!(counter_delta(150, 100), 50);
        assert_eq!(counter_delta(10, 100), 0); // reset → 0, not underflow
    }
}
