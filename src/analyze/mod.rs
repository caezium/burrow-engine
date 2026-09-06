//! Disk analysis — the engine reimplementation of digger's `cmd/analyze`.
//!
//! Ported bottom-up from the Go original: the pure helpers first (this is where `cleanable`,
//! and later `insights`/`format`, land), then the directory scanner that uses them. The
//! interactive TUI half of `cmd/analyze` (Bubble Tea view/update) is NOT ported — that's the
//! GUI's job; the engine owns only the headless scan + classification + JSON contract.

pub mod cleanable;
pub mod insights;
pub mod json;
pub mod scanner;
