//! burrow-engine — the Burrow core.
//!
//! The library that powers every Burrow surface: burrow-cli wraps it for agents and
//! scripts; the macOS and Windows GUIs wrap it (today via the bundled CLI) for humans.
//! Logic migrates here from burrow-cli slice by slice; the legacy mo-fork snapshot
//! (burrow-digger) shrinks as this crate grows.

pub mod analyze;
pub mod clean;
pub mod cli;
pub mod dupes;
pub mod envelope;
pub mod evict;
pub mod history;
pub mod installer;
pub mod json;
pub mod macho;
pub mod net;
pub mod optimize;
pub mod orphan;
pub mod photos;
pub mod platform;
pub mod purge;
mod reviewed_plan;
pub mod rules;
pub mod sentinel;
pub mod status;
pub mod trash;
pub mod uninstall;
pub mod units;
