//! Cleaning — the engine reimplementation of digger's bash `lib/clean` + safety core.
//!
//! Ported safety-first: the guardrails before the destructive sweeps. THREE of them, matching the
//! three digger runs before it deletes anything. Two are `safe_clean`'s own
//! (`bin/clean.sh:600-612`): [`protect`] is the unconditional 7-stage filter that applies no matter
//! what the user configured, and [`whitelist`] is the user's own protection list — plus, when they
//! have no list at all, the built-in defaults digger falls back to. Both are pure and both are
//! applied in one place ([`plan::cleanable_paths`]), so every clean target inherits them.
//!
//! The third is [`validate`], which digger runs one call deeper, inside `safe_remove`
//! (`lib/core/file_ops.sh:224-226`) and `mole_delete` (`:522`) rather than in `safe_clean` — which is
//! why an earlier reading of this code modelled the oracle as "two filters, then remove" and missed
//! it. It refuses control characters, `..` components, critical system paths, symlinks aimed at
//! critical system paths, and (again, on the NORMALIZED path) anything [`protect`] protects.
//! [`execute`] applies it at the removal site so every remover inherits it.

pub mod execute;
pub mod format;
pub mod plan;
pub mod plan_file;
pub mod protect;
mod protect_data;
pub mod stream;
pub mod tool_delegate;
pub mod validate;
pub mod whitelist;
