//! Project-artifact purge — detection + protection core, the engine port of digger's `purge`.
//!
//! `purge` reclaims heavy build artifacts (node_modules, target, .venv, DerivedData, …) from
//! project directories under the user's code roots. This module is the SAFE foundation: the
//! canonical target/indicator tables, project-root detection, the config-file parser, and — most
//! importantly — `is_protected_purge_artifact`, the guard that stops purge from deleting a `bin/`
//! that isn't a .NET build output, a `vendor/` that can't be regenerated, or Xcode's global
//! DerivedData. The directory-walk scan and the destructive removal are deliberately deferred to
//! later slices; nothing here deletes anything. Ported verbatim from lib/clean/{purge_shared,
//! project}.sh so the behavior (and its protections) match digger exactly.

use crate::clean::execute::{
    remove_guarded, remove_one_reported, CleanEvent, CleanOutcome, Guarded, Removal, RemovalError,
};
use crate::clean::protect::ProtectionMode;
use std::path::Path;

/// Canonical purge targets — heavy, regenerable project build-artifact directory names.
pub const PURGE_TARGETS: &[&str] = &[
    "node_modules",
    "target",        // Rust, Maven
    "build",         // Gradle, various
    "dist",          // JS builds
    "venv",          // Python
    ".venv",         // Python
    ".pytest_cache", // Python (pytest)
    ".mypy_cache",   // Python (mypy)
    ".tox",          // Python (tox)
    ".nox",          // Python (nox)
    ".ruff_cache",   // Python (ruff)
    ".gradle",       // Gradle local
    "__pycache__",   // Python
    ".next",         // Next.js
    ".nuxt",         // Nuxt.js
    ".output",       // Nuxt.js
    "vendor",        // PHP Composer (guarded; see is_protected_purge_artifact)
    "bin",           // .NET build output (guarded)
    "obj",           // C# / Unity
    ".turbo",        // Turborepo cache
    ".parcel-cache", // Parcel bundler
    ".dart_tool",    // Flutter/Dart
    ".zig-cache",    // Zig
    "zig-out",       // Zig
    ".angular",      // Angular
    ".svelte-kit",   // SvelteKit
    ".astro",        // Astro
    "coverage",      // Coverage reports
    "DerivedData",   // Xcode (guarded)
    "Pods",          // CocoaPods
    ".cxx",          // React Native Android NDK
    ".expo",         // Expo
    ".build",        // Swift Package Manager
];

/// Monorepo markers — their presence makes a directory a project root.
pub const MONOREPO_INDICATORS: &[&str] =
    &["lerna.json", "pnpm-workspace.yaml", "nx.json", "rush.json"];

/// Single-project markers — their presence makes a directory a project root.
pub const PROJECT_INDICATORS: &[&str] = &[
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pyproject.toml",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "pubspec.yaml",
    "Package.swift",
    "Makefile",
    "build.zig",
    "build.zig.zon",
    ".git",
];

/// The default code roots scanned when the user has no purge-paths config.
pub fn default_search_paths(home: &str) -> Vec<String> {
    [
        "www",
        "dev",
        "Projects",
        "GitHub",
        "Code",
        "Workspace",
        "Repos",
        "Development",
        "Library/CloudStorage",
    ]
    .iter()
    .map(|sub| format!("{home}/{sub}"))
    .collect()
}

/// Whether `dir` looks like a project root (has any monorepo or project indicator).
pub fn is_project_root(dir: &Path) -> bool {
    MONOREPO_INDICATORS
        .iter()
        .chain(PROJECT_INDICATORS.iter())
        .any(|ind| dir.join(ind).exists())
}

/// Parse a purge-paths config: one path per line, `#` comments and blanks skipped, leading `~`
/// expanded to `home`. Pure (the fs case-canonicalization digger also does is a separate wrapper).
pub fn parse_paths_config(text: &str, home: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            if let Some(rest) = l.strip_prefix('~') {
                format!("{home}{rest}")
            } else {
                l.to_string()
            }
        })
        .collect()
}

// --- project-type detection (marker files), for the vendor/bin protection rules ---

fn is_php_project_root(dir: &Path) -> bool {
    dir.join("composer.json").is_file()
}

/// A `bin/` directory is a .NET build output when its parent has a C#/F#/VB project file AND it
/// contains a `Debug/` or `Release/` subdir. Only then is purging `bin/` safe.
pub fn is_dotnet_bin_dir(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) != Some("bin") {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let has_proj = std::fs::read_dir(parent)
        .map(|entries| {
            entries.flatten().any(|e| {
                matches!(
                    e.path().extension().and_then(|x| x.to_str()),
                    Some("csproj") | Some("fsproj") | Some("vbproj")
                )
            })
        })
        .unwrap_or(false);
    has_proj && (path.join("Debug").is_dir() || path.join("Release").is_dir())
}

/// Whether a `vendor/` directory must be protected (can't be safely regenerated). PHP Composer
/// vendor regenerates via `composer install` → NOT protected; Rails/Go vendor and any unknown
/// vendor → protected (conservative).
pub fn is_protected_vendor_dir(path: &Path) -> bool {
    if path.file_name().and_then(|n| n.to_str()) != Some("vendor") {
        return false;
    }
    let Some(parent) = path.parent() else {
        return true;
    };
    if is_php_project_root(parent) {
        return false; // composer install regenerates it
    }
    // Rails vendor, Go vendor, and any unknown vendor type all protect in digger — so anything
    // that isn't a PHP-Composer vendor is protected (conservative).
    true
}

/// The purge safety guard: whether an artifact directory must NEVER be purged. `bin/` is protected
/// unless it's a .NET build output; `vendor/` per [`is_protected_vendor_dir`]; global Xcode
/// DerivedData (`~/Library/Developer/Xcode/DerivedData`) is protected but project-local DerivedData
/// is not. Everything else is purgeable. Matches digger's `is_protected_purge_artifact`.
pub fn is_protected_purge_artifact(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("bin") => !is_dotnet_bin_dir(path),
        Some("vendor") => is_protected_vendor_dir(path),
        Some("DerivedData") => path
            .to_string_lossy()
            .contains("/Library/Developer/Xcode/DerivedData"),
        _ => false,
    }
}

/// Depth (relative to a search path) at which purge looks for artifacts. `PURGE_TARGETS`-named
/// dirs are collected at depth 1..=6; CACHEDIR.TAG-marked dirs at depth 2..=7 (digger's min+1..max+1).
const MAX_DEPTH: usize = 6;
const CACHE_MAX_DEPTH: usize = MAX_DEPTH + 1;

/// A purge candidate: an artifact directory and its size on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub path: String,
    /// Measured on disk at scan time; `dir_size`'s signed total is clamped at the scan boundary,
    /// so nothing downstream re-clamps.
    pub size_bytes: u64,
}

/// Walk `search_paths` for purge candidates (read-only). At each search path, `PURGE_TARGETS`-named
/// directories (depth 1..=6) and CACHEDIR.TAG-marked cache directories (depth 2..=7) are collected,
/// gated by [`is_safe_project_artifact`] semantics (a top-level artifact only counts when the search
/// path is itself a project root). Matched artifacts are pruned (not descended into). The result is
/// nested-deduped (no artifact inside another kept artifact) and protection-filtered, then sized.
pub fn scan(search_paths: &[String]) -> Vec<Artifact> {
    let mut found: Vec<String> = Vec::new();
    for sp in search_paths {
        let root = Path::new(sp);
        if !root.is_dir() {
            continue;
        }
        let sp_is_project = is_project_root(root);
        walk(root, 1, sp_is_project, &mut found);
    }
    found.sort();
    found.dedup();
    let deduped = filter_nested_artifacts(found);
    deduped
        .into_iter()
        .filter(|p| !is_protected_purge_artifact(Path::new(p)))
        .map(|p| {
            let size_bytes = crate::analyze::scanner::dir_size(Path::new(&p)).max(0) as u64;
            Artifact {
                path: p,
                size_bytes,
            }
        })
        .collect()
}

/// Classify only the reviewed paths, with the same depth, pruning and protection rules as scan.
/// A bad or changed entry refuses the whole plan before any removal begins.
pub fn from_reviewed_paths(paths: &[String], roots: &[String]) -> Result<Vec<Artifact>, String> {
    paths
        .iter()
        .map(|path| {
            if !reviewed_path_allowed(Path::new(path), roots) {
                return Err(format!(
                    "reviewed purge path is no longer an allowed artifact: {path}"
                ));
            }
            Ok(Artifact {
                path: path.clone(),
                size_bytes: crate::analyze::scanner::dir_size(Path::new(path)).max(0) as u64,
            })
        })
        .collect()
}

fn reviewed_path_allowed(path: &Path, roots: &[String]) -> bool {
    if !path.is_dir() || is_protected_purge_artifact(path) {
        return false;
    }
    roots.iter().any(|root| {
        let root = Path::new(root);
        let Some(parts) = crate::reviewed_plan::relative_components(path, root) else {
            return false;
        };
        let mut current = root.to_path_buf();
        for (index, part) in parts.iter().enumerate() {
            current.push(part);
            let depth = index + 1;
            let name = part.to_str().unwrap_or("");
            let target = depth <= MAX_DEPTH && PURGE_TARGETS.contains(&name);
            let cache = (2..=CACHE_MAX_DEPTH).contains(&depth)
                && crate::analyze::cleanable::has_valid_cache_dir_tag(&current);
            if target || cache {
                return depth == parts.len() && (depth >= 2 || is_project_root(root));
            }
            if matches!(name, ".git" | "Library" | ".Trash") || depth >= CACHE_MAX_DEPTH {
                return false;
            }
        }
        false
    })
}

fn walk(dir: &Path, depth: usize, sp_is_project: bool, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        // lstat via file_type(): never follow symlinked dirs (avoids loops, matches find default).
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();

        let is_target = depth <= MAX_DEPTH && PURGE_TARGETS.contains(&name.as_str());
        let is_cache = (2..=CACHE_MAX_DEPTH).contains(&depth)
            && crate::analyze::cleanable::has_valid_cache_dir_tag(&path);
        if is_target || is_cache {
            // is_safe_project_artifact: safe when nested >=1 level under the search path (depth>=2
            // here), or the search path itself is a project root (top-level artifact).
            if depth >= 2 || sp_is_project {
                out.push(path.to_string_lossy().into_owned());
            }
            continue; // prune: never descend into a matched artifact
        }
        // Never descend into VCS/system trees.
        if matches!(name.as_str(), ".git" | "Library" | ".Trash") {
            continue;
        }
        if depth < CACHE_MAX_DEPTH {
            walk(&path, depth + 1, sp_is_project, out);
        }
    }
}

/// Drop any path nested inside another kept path (e.g. a `node_modules` inside a kept `node_modules`).
/// Sorted prefix-dedup with a trailing-slash guard so `/a/b` doesn't swallow `/a/bc`.
pub fn filter_nested_artifacts(mut paths: Vec<String>) -> Vec<String> {
    paths.sort();
    let mut kept: Vec<String> = Vec::new();
    let mut last_prefix = String::new();
    for p in paths {
        let with_slash = format!("{p}/");
        if last_prefix.is_empty() || !with_slash.starts_with(&last_prefix) {
            kept.push(p);
            last_prefix = with_slash;
        }
    }
    kept
}

use crate::json::escape as esc;

const RULE: &str = "======================================================================";

/// Human-readable report text alongside the structured fields (contract-conformance: the
/// shipping oracle emits ANSI human text for `purge`/`clean`/`optimize`, not JSON, and the
/// app's action path parses THAT text — `Ansi.strip` then `parseTaskReport(lines).summary` —
/// to recover freed-bytes for both the GUI report cards and the MCP action tools' `summary`
/// field. Not a byte-for-byte reproduction of `bin/purge.sh` (colors, the live scan spinner,
/// and a `Free: <disk free space>` reading are dropped — decorative, and this binary has no
/// disk-free reader); it reuses the same section markers (`➤`/`→`) and the same "Would free: …
/// | Items: …" wording so a human reads the same shape. NOTE: fed through the real
/// `parseTaskReport`, neither the oracle's own "Would free: …" line nor this one matches
/// `mergeSummaryFields` (it only recognises "potential space" / "tracked cleanup" / "free space
/// change" / "free space now" — all `clean`-only phrasing), so `summary` is `nil` for purge on
/// BOTH sides. That's parity with the oracle, not a regression: verified with the Gate 1 harness.
fn render_dry_run_text(artifacts: &[Artifact], total: u64) -> String {
    let mut out = String::new();
    out.push_str("→ DRY RUN MODE, No project artifacts will be removed\n\n");
    out.push_str("Purge Project Artifacts\n\n");
    if artifacts.is_empty() {
        out.push_str("No old project artifacts to clean.\n");
    } else {
        out.push_str("➤ Project Artifacts\n");
        for a in artifacts {
            out.push_str(&format!(
                "  → {}, {}\n",
                a.path,
                crate::clean::format::bytes_to_human(a.size_bytes)
            ));
        }
    }
    out.push('\n');
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Dry run complete - no changes made\n");
    if total > 0 {
        out.push_str(&format!(
            "Would free: {} | Items: {}\n",
            crate::clean::format::bytes_to_human(total),
            artifacts.len()
        ));
    } else {
        out.push_str("No old project artifacts to clean.\n");
    }
    out.push_str(RULE);
    out
}

/// Same idea as [`render_dry_run_text`] for a completed (`--apply`) purge: "Space freed: … |
/// Items: …" is `bin/purge.sh`'s real live-mode wording, and is equally unrecognised by
/// `mergeSummaryFields` — verified empirically, see [`render_dry_run_text`].
fn render_outcome_text(outcome: &PurgeOutcome) -> String {
    let mut out = String::new();
    out.push_str("Purge Project Artifacts\n\n");
    if !outcome.removed.is_empty() {
        out.push_str("➤ Project Artifacts\n");
        for a in &outcome.removed {
            out.push_str(&format!(
                "  ✓ {}, {}\n",
                a.path,
                crate::clean::format::bytes_to_human(a.bytes())
            ));
        }
    }
    if !outcome.protected.is_empty() {
        out.push_str("➤ Protected\n");
        for p in &outcome.protected {
            out.push_str(&format!("  • {p}, skipped (protected)\n"));
        }
    }
    if !outcome.errors.is_empty() {
        out.push_str("➤ Errors\n");
        for RemovalError { path: p, error: e } in &outcome.errors {
            out.push_str(&format!("  ✗ {p}: {e}\n"));
        }
    }
    out.push('\n');
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Purge complete\n");
    // bash only ever `rm -rf`s, so "Space freed" is the truth there; the default path here moves
    // to the Trash, which frees nothing until it is emptied, and the line says so.
    if outcome.moved_to_trash_bytes > 0 {
        out.push_str(&format!(
            "Moved to Trash: {} | Items: {}\n",
            crate::clean::format::bytes_to_human(outcome.accounted_bytes()),
            outcome.removed.len()
        ));
    } else if outcome.freed_bytes > 0 {
        out.push_str(&format!(
            "Space freed: {} | Items: {}\n",
            crate::clean::format::bytes_to_human(outcome.freed_bytes),
            outcome.removed.len()
        ));
    } else {
        out.push_str("No old project artifacts to clean.\n");
    }
    out.push_str(RULE);
    out
}

/// Serialize the dry-run purge report (zero-dep):
/// `{dry_run:true,artifacts:[{path,size_bytes}],count:N,total_bytes:B,text:S}`.
/// `text` is additive — every prior field is untouched — see [`render_dry_run_text`].
pub fn to_json(artifacts: &[Artifact]) -> String {
    let total: u64 = artifacts.iter().map(|a| a.size_bytes).sum();
    let items = artifacts
        .iter()
        .map(|a| {
            format!(
                "{{\"path\":{},\"size_bytes\":{}}}",
                esc(&a.path),
                a.size_bytes
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = render_dry_run_text(artifacts, total);
    format!(
        "{{\"dry_run\":true,\"artifacts\":[{items}],\"count\":{},\"total_bytes\":{total},\"text\":{}}}",
        artifacts.len(),
        esc(&text)
    )
}

/// Resolve the search paths: the user's `~/.config/mole/purge_paths` config if present + non-empty,
/// else the built-in [`default_search_paths`]. (Env-overridable via `PURGE_PATHS_CONFIG`.)
pub fn resolve_search_paths(home: &str) -> Vec<String> {
    let config = std::env::var("PURGE_PATHS_CONFIG")
        .unwrap_or_else(|_| format!("{home}/.config/mole/purge_paths"));
    if let Ok(text) = std::fs::read_to_string(&config) {
        let paths = parse_paths_config(&text, home);
        if !paths.is_empty() {
            return paths;
        }
    }
    default_search_paths(home)
}

/// The result of a destructive purge run — the same [`CleanOutcome`] `clean` reports through, so
/// the byte accounting, the `protected` bucket and the history logging are shared rather than
/// re-spelled here. `removed[].label` is the artifact's directory name (`node_modules`, `target`).
pub type PurgeOutcome = CleanOutcome;

/// Remove each artifact directory through the shared guarded remover
/// ([`crate::clean::execute::remove_guarded`]) — the same rails `clean` runs, because that is what
/// the oracle does: `lib/clean/project.sh:1658` removes via `safe_remove`, which opens with
/// `validate_path_for_deletion` (`file_ops.sh:224`). Before that, the purge-specific guard
/// [`is_protected_purge_artifact`] is re-checked per item (defense in depth — even though the scan
/// already filtered, a `bin/` or `vendor/` that isn't regenerable must never be removed here).
/// `permanent` selects the removal mode: `false` (the default) routes each survivor through the
/// real macOS Trash ([`crate::trash::move_to_trash`]); `true` removes it immediately via
/// `fs::remove_dir_all` — irreversible. Errors (including a failed recoverable delete) and
/// protected skips are collected, not fatal — a Trash failure on one artifact is never a reason to
/// hard-delete it instead or to abort the rest of the run. A byte count is billed only once the
/// path is verified gone (RULEBOOK §3m), and an artifact that vanished between scan and apply is
/// dropped without an error, exactly like bash's `if [[ -e "$item_path" ]]` (`project.sh:1657`).
pub fn execute(artifacts: &[Artifact], permanent: bool) -> PurgeOutcome {
    execute_with(artifacts, permanent, |_| {})
}

/// [`execute`] emitting a [`CleanEvent`] per artifact as it is processed — the unit of the
/// `purge --stream` feed, the same events `clean --stream` emits so one reader serves both.
pub fn execute_with(
    artifacts: &[Artifact],
    permanent: bool,
    emit: impl FnMut(CleanEvent<'_>),
) -> PurgeOutcome {
    execute_with_remover(artifacts, permanent, emit, remove_one_reported)
}

pub fn execute_reviewed_with(
    artifacts: &[Artifact],
    roots: &[String],
    permanent: bool,
    emit: impl FnMut(CleanEvent<'_>),
) -> PurgeOutcome {
    execute_checked_with_remover(artifacts, permanent, emit, remove_one_reported, |path| {
        reviewed_path_allowed(path, roots)
    })
}

/// [`execute_with`] with the per-artifact removal function injected — the seam that makes the
/// permanent/recoverable dispatch testable without a real Trash call. See
/// `crate::clean::execute`'s identically-shaped split for why (its `remove_one`'s doc comment
/// explains the reasoning once, applying equally here).
fn execute_with_remover(
    artifacts: &[Artifact],
    permanent: bool,
    emit: impl FnMut(CleanEvent<'_>),
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
) -> PurgeOutcome {
    execute_checked_with_remover(artifacts, permanent, emit, remover, |_| true)
}

fn execute_checked_with_remover(
    artifacts: &[Artifact],
    permanent: bool,
    mut emit: impl FnMut(CleanEvent<'_>),
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
    allowed: impl Fn(&Path) -> bool,
) -> PurgeOutcome {
    let mut outcome = PurgeOutcome::default();
    for a in artifacts {
        let path = Path::new(&a.path);
        // Defense in depth: never remove a protected artifact, even if it reached this list.
        if !allowed(path) || is_protected_purge_artifact(path) {
            outcome.protected.push(a.path.clone());
            emit(CleanEvent::Protected { path: &a.path });
            continue;
        }
        // `bin/purge.sh` never exports MOLE_UNINSTALL_MODE and never consults the whitelist
        // (`safe_remove`, not `safe_clean`) — so the cleanup regime, with no whitelist.
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match remove_guarded(
            &a.path,
            a.size_bytes,
            &[],
            permanent,
            ProtectionMode::Cleanup,
            &remover,
        ) {
            Guarded::Protected => {
                outcome.protected.push(a.path.clone());
                emit(CleanEvent::Protected { path: &a.path });
            }
            Guarded::Missing => {}
            Guarded::Removed(freed) => {
                outcome.record_removed(&a.path, &label, freed, permanent);
                emit(CleanEvent::Removed {
                    path: &a.path,
                    size: match freed {
                        crate::clean::execute::Freed::Bytes(n) => n,
                        _ => 0,
                    },
                });
            }
            Guarded::Failed(e) => {
                emit(CleanEvent::Failed {
                    path: &a.path,
                    error: &e,
                });
                outcome.errors.push(RemovalError {
                    path: a.path.clone(),
                    error: e,
                });
            }
        }
    }
    outcome
}

/// The `purge --stream` DRY-RUN lines: one `would_remove` per artifact, then the preview `done`
/// totalling them — the same lines `clean --stream` emits (see [`crate::clean::stream`]).
pub fn preview_stream_lines(artifacts: &[Artifact]) -> Vec<String> {
    use crate::clean::stream::{preview_done_line, would_remove_line};
    let mut lines: Vec<String> = artifacts
        .iter()
        .map(|a| would_remove_line(&a.path, a.size_bytes))
        .collect();
    let total: u64 = artifacts.iter().map(|a| a.size_bytes).sum();
    lines.push(preview_done_line(total, artifacts.len()));
    lines
}

/// Serialize a destructive purge outcome:
/// `{dry_run:false,freed_bytes,moved_to_trash_bytes,removed:[{path,size_bytes}],errors:[{path,error}],protected:[…],text:S}`.
/// `removed[].size_bytes` is what this run can PROVE left that path (0 when the remover reported
/// success but the path is still there), so it sums to `freed_bytes + moved_to_trash_bytes`
/// exactly; on the default path `freed_bytes` is 0 because a Trash move frees no space.
pub fn outcome_to_json(outcome: &PurgeOutcome) -> String {
    let removed = outcome
        .removed
        .iter()
        .map(|a| format!("{{\"path\":{},\"size_bytes\":{}}}", esc(&a.path), a.bytes()))
        .collect::<Vec<_>>()
        .join(",");
    let errors = outcome
        .errors
        .iter()
        .map(|e| format!("{{\"path\":{},\"error\":{}}}", esc(&e.path), esc(&e.error)))
        .collect::<Vec<_>>()
        .join(",");
    let protected = outcome
        .protected
        .iter()
        .map(|p| esc(p))
        .collect::<Vec<_>>()
        .join(",");
    let text = render_outcome_text(outcome);
    format!(
        "{{\"dry_run\":false,\"freed_bytes\":{},\"moved_to_trash_bytes\":{},\"removed\":[{removed}],\"errors\":[{errors}],\"protected\":[{protected}],\"text\":{}}}",
        outcome.freed_bytes,
        outcome.moved_to_trash_bytes,
        esc(&text)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow_purge_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reviewed_plan_selects_only_listed_scannable_artifacts() {
        let root = scratch("reviewed_exact");
        let reviewed = root.join("project/target");
        std::fs::create_dir_all(&reviewed).unwrap();
        std::fs::write(reviewed.join("output"), "reviewed").unwrap();
        let late = root.join("project/node_modules");
        std::fs::create_dir_all(&late).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let paths = vec![reviewed.to_string_lossy().into_owned()];
        let artifacts = from_reviewed_paths(&paths, &roots).unwrap();
        assert_eq!(
            artifacts.iter().map(|a| &a.path).collect::<Vec<_>>(),
            paths.iter().collect::<Vec<_>>()
        );
        let outcome = execute_checked_with_remover(
            &artifacts,
            true,
            |_| {},
            |path, _| {
                assert_eq!(path, reviewed);
                std::fs::remove_dir_all(path).unwrap();
                Ok(Removal::Removed)
            },
            |path| reviewed_path_allowed(path, &roots),
        );
        assert_eq!(outcome.removed.len(), 1);
        assert!(
            late.is_dir(),
            "a candidate discovered after review must stay outside apply"
        );
        let arbitrary = root.join("project/documents");
        std::fs::create_dir_all(&arbitrary).unwrap();
        assert!(from_reviewed_paths(&[arbitrary.to_string_lossy().into_owned()], &roots).is_err());
        let nested = late.join("nested/target");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(
            from_reviewed_paths(&[nested.to_string_lossy().into_owned()], &roots).is_err(),
            "scan prunes a matched ancestor"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn reviewed_plan_refuses_a_parent_replaced_by_a_symlink_at_apply() {
        let root = scratch("reviewed_alias");
        let reviewed = root.join("project/target");
        std::fs::create_dir_all(&reviewed).unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let paths = vec![reviewed.to_string_lossy().into_owned()];
        let artifacts = from_reviewed_paths(&paths, &roots).unwrap();
        std::fs::rename(root.join("project"), root.join("original")).unwrap();
        std::os::unix::fs::symlink(root.join("original"), root.join("project")).unwrap();
        assert!(from_reviewed_paths(&paths, &roots).is_err());
        let outcome = execute_checked_with_remover(
            &artifacts,
            true,
            |_| {},
            |_, _| panic!("must not remove"),
            |path| reviewed_path_allowed(path, &roots),
        );
        assert_eq!(outcome.protected, paths);
        assert!(root.join("original/target").is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn targets_and_indicators_present() {
        assert!(PURGE_TARGETS.contains(&"node_modules"));
        assert!(PURGE_TARGETS.contains(&".build"));
        assert!(PROJECT_INDICATORS.contains(&"Cargo.toml"));
        assert!(MONOREPO_INDICATORS.contains(&"pnpm-workspace.yaml"));
    }

    #[test]
    fn default_search_paths_are_home_relative() {
        let p = default_search_paths("/Users/x");
        assert!(p.contains(&"/Users/x/dev".to_string()));
        assert!(p.contains(&"/Users/x/Library/CloudStorage".to_string()));
    }

    #[test]
    fn is_project_root_detects_markers() {
        let dir = scratch("proj");
        assert!(!is_project_root(&dir));
        std::fs::write(dir.join("Cargo.toml"), "").unwrap();
        assert!(is_project_root(&dir), "Cargo.toml marks a project root");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_parse_skips_comments_and_expands_home() {
        let text = "# a comment\n\n  ~/dev/foo  \n/abs/path\n~/bar";
        let got = parse_paths_config(text, "/home/me");
        assert_eq!(got, vec!["/home/me/dev/foo", "/abs/path", "/home/me/bar"]);
    }

    #[test]
    fn bin_is_protected_unless_dotnet_build_output() {
        let root = scratch("bin");
        // A bare bin/ with no .NET context → protected.
        let plain = root.join("plain/bin");
        std::fs::create_dir_all(&plain).unwrap();
        assert!(
            is_protected_purge_artifact(&plain),
            "bare bin/ is protected"
        );

        // A .NET bin/: parent has a .csproj AND bin/ has Debug/ → NOT protected.
        let net = root.join("app/bin");
        std::fs::create_dir_all(net.join("Release")).unwrap();
        std::fs::write(root.join("app/App.csproj"), "").unwrap();
        assert!(is_dotnet_bin_dir(&net));
        assert!(!is_protected_purge_artifact(&net), ".NET bin/ is purgeable");

        // .csproj present but no Debug/Release subdir → still protected.
        let net2 = root.join("app2/bin");
        std::fs::create_dir_all(&net2).unwrap();
        std::fs::write(root.join("app2/App.csproj"), "").unwrap();
        assert!(
            is_protected_purge_artifact(&net2),
            "no Debug/Release → protected"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vendor_protected_except_for_php() {
        let root = scratch("vendor");
        // PHP (composer.json) → NOT protected.
        let php = root.join("php/vendor");
        std::fs::create_dir_all(&php).unwrap();
        std::fs::write(root.join("php/composer.json"), "").unwrap();
        assert!(!is_protected_purge_artifact(&php), "PHP vendor regenerates");

        // Go (go.mod) vendor → protected.
        let go = root.join("go/vendor");
        std::fs::create_dir_all(&go).unwrap();
        std::fs::write(root.join("go/go.mod"), "").unwrap();
        assert!(is_protected_purge_artifact(&go), "Go vendor is protected");

        // Unknown vendor → protected (conservative default).
        let unk = root.join("mystery/vendor");
        std::fs::create_dir_all(&unk).unwrap();
        assert!(
            is_protected_purge_artifact(&unk),
            "unknown vendor is protected"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn derived_data_global_protected_project_local_not() {
        let global = Path::new("/Users/x/Library/Developer/Xcode/DerivedData");
        assert!(
            is_protected_purge_artifact(global),
            "global Xcode DD protected"
        );
        let local = Path::new("/Users/x/Projects/App/DerivedData");
        assert!(
            !is_protected_purge_artifact(local),
            "project-local DD purgeable"
        );
    }

    #[test]
    fn ordinary_artifacts_are_not_protected() {
        for name in ["node_modules", "target", ".venv", "dist", "__pycache__"] {
            let p = std::path::PathBuf::from(format!("/Users/x/proj/{name}"));
            assert!(!is_protected_purge_artifact(&p), "{name} must be purgeable");
        }
    }

    #[test]
    fn filter_nested_drops_artifacts_inside_kept_ones() {
        let got = filter_nested_artifacts(vec![
            "/p/node_modules".into(),
            "/p/node_modules/dep/node_modules".into(),
            "/p/target".into(),
            "/p/node_modules_extra".into(), // NOT inside node_modules (trailing-slash guard)
        ]);
        assert!(got.contains(&"/p/node_modules".to_string()));
        assert!(got.contains(&"/p/target".to_string()));
        assert!(
            got.contains(&"/p/node_modules_extra".to_string()),
            "sibling not swallowed"
        );
        assert!(
            !got.contains(&"/p/node_modules/dep/node_modules".to_string()),
            "nested artifact dropped"
        );
    }

    #[test]
    fn scan_finds_project_artifacts_and_respects_protection_and_nesting() {
        let root = scratch("scan");
        // A project 1 level under the search root: search/proj (has Cargo.toml).
        let proj = root.join("proj");
        std::fs::create_dir_all(proj.join("node_modules/dep/node_modules")).unwrap();
        std::fs::create_dir_all(proj.join("target")).unwrap();
        std::fs::write(proj.join("Cargo.toml"), "").unwrap();
        std::fs::write(proj.join("node_modules/f.js"), "hello").unwrap();
        // A protected vendor (no composer.json -> unknown -> protected).
        std::fs::create_dir_all(proj.join("vendor")).unwrap();
        // A stray node_modules directly under the (non-project) search root -> depth 1, dropped.
        std::fs::create_dir_all(root.join("node_modules")).unwrap();

        let arts = scan(&[root.to_string_lossy().into_owned()]);
        // Normalize separators so the assertions hold on Windows (\) as well as unix (/).
        let paths: Vec<String> = arts.iter().map(|a| a.path.replace('\\', "/")).collect();
        let root_fwd = root.to_string_lossy().replace('\\', "/");
        assert!(
            paths.iter().any(|p| p.ends_with("/proj/node_modules")),
            "found: {paths:?}"
        );
        assert!(paths.iter().any(|p| p.ends_with("/proj/target")));
        assert!(
            !paths.iter().any(|p| p.contains("/dep/node_modules")),
            "nested node_modules pruned/deduped"
        );
        assert!(
            !paths.iter().any(|p| p.ends_with("/proj/vendor")),
            "unknown vendor protected"
        );
        assert!(
            !paths
                .iter()
                .any(|p| p == &format!("{root_fwd}/node_modules")),
            "top-level artifact under a non-project root is dropped"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn to_json_totals_sizes() {
        let arts = vec![
            Artifact {
                path: "/a/node_modules".into(),
                size_bytes: 100,
            },
            Artifact {
                path: "/b/target".into(),
                size_bytes: 50,
            },
        ];
        let j = to_json(&arts);
        assert!(j.contains("\"dry_run\":true"));
        assert!(j.contains("\"count\":2"));
        assert!(j.contains("\"total_bytes\":150"));
        assert!(j.contains("\"text\":\""), "text field is present: {j}");

        let empty = to_json(&[]);
        assert!(empty.contains("\"dry_run\":true"));
        assert!(empty.contains("\"artifacts\":[]"));
        assert!(empty.contains("\"count\":0"));
        assert!(empty.contains("\"total_bytes\":0"));
        assert!(
            empty.contains("\"text\":\""),
            "text field is present: {empty}"
        );
    }

    #[test]
    fn resolve_search_paths_prefers_config() {
        let dir = scratch("cfg");
        let cfg = dir.join("purge_paths");
        std::fs::write(&cfg, "~/only/this\n# comment\n").unwrap();
        std::env::set_var("PURGE_PATHS_CONFIG", &cfg);
        let paths = resolve_search_paths("/home/me");
        std::env::remove_var("PURGE_PATHS_CONFIG");
        assert_eq!(paths, vec!["/home/me/only/this"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn removed_item(path: &str, bytes: u64) -> crate::clean::execute::RemovedItem {
        crate::clean::execute::RemovedItem {
            path: path.into(),
            label: Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            freed: crate::clean::execute::Freed::Bytes(bytes),
        }
    }

    // Several tests below are `#[cfg(unix)]` because they push a REAL scratch path through the
    // shared deletion rails (`clean::execute::remove_guarded`), and off unix the rails' platform
    // guard (`clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS`, and the long comment at it)
    // refuses every path before the remover is ever consulted — so on Windows each of them would
    // observe `protected`, nothing removed, and a remover that was never called. That refusal is
    // deliberate and pinned by `the_deletion_rails_refuse_outright_on_a_platform_they_were_not_
    // written_for`; what these tests pin is what happens PAST the rails, which only unix reaches.
    #[cfg(unix)]
    #[test]
    fn execute_removes_artifacts_and_frees_bytes() {
        let root = scratch("exec");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(nm.join("dep")).unwrap();
        std::fs::write(nm.join("dep/a.js"), "x").unwrap();
        let arts = vec![Artifact {
            path: nm.to_string_lossy().into_owned(),
            size_bytes: 123,
        }];
        let out = execute(&arts, true);
        assert_eq!(out.removed.len(), 1);
        assert_eq!(out.freed_bytes, 1);
        assert!(out.errors.is_empty());
        assert!(!nm.exists(), "the artifact dir is gone");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_refuses_to_remove_a_protected_artifact() {
        // Defense in depth: even if a protected dir reaches execute, it is NEVER removed.
        let root = scratch("exec_prot");
        let vendor = root.join("vendor"); // no composer.json -> unknown -> protected
        std::fs::create_dir_all(&vendor).unwrap();
        let arts = vec![Artifact {
            path: vendor.to_string_lossy().into_owned(),
            size_bytes: 10,
        }];
        let out = execute(&arts, true);
        assert!(out.removed.is_empty(), "nothing removed");
        assert_eq!(out.protected, vec![vendor.to_string_lossy().into_owned()]);
        assert!(vendor.exists(), "protected vendor survives execute");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The deletion rails `clean` runs are the ones `purge` runs too, because the oracle removes
    /// through `safe_remove` → `validate_path_for_deletion` (`lib/clean/project.sh:1658`,
    /// `file_ops.sh:224`). Before this, `purge --apply` re-checked only the purge-specific guard,
    /// so a candidate that `should_protect_path` refuses in every other command sailed through here.
    #[cfg(unix)]
    #[test]
    fn apply_refuses_a_planted_protected_path_the_purge_guard_does_not_know_about() {
        let root = scratch("exec_rails_protected");
        // `*/Library/Logs/mole/*` is on the stage-5 denylist (`protect.rs`); `node_modules` is not
        // a name `is_protected_purge_artifact` has any opinion on.
        let planted = root.join("Library/Logs/mole/node_modules");
        std::fs::create_dir_all(&planted).unwrap();
        std::fs::write(planted.join("keep"), b"must survive").unwrap();
        assert!(
            !is_protected_purge_artifact(&planted),
            "fixture sanity: the purge guard alone would let this through"
        );
        let arts = vec![Artifact {
            path: planted.to_string_lossy().into_owned(),
            size_bytes: 12,
        }];
        let out = execute(&arts, true);
        assert!(out.removed.is_empty(), "{out:?}");
        assert!(out.errors.is_empty(), "a refusal is not an error: {out:?}");
        assert_eq!(out.protected, vec![planted.to_string_lossy().into_owned()]);
        assert_eq!(out.freed_bytes, 0);
        assert!(
            planted.join("keep").exists(),
            "the refused path is untouched"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn apply_refuses_a_path_that_fails_validation_and_never_calls_the_remover() {
        // `..` as a component and a control character are two of `validate_path_for_deletion`'s
        // refusals; neither is something the purge guard looks at.
        let root = scratch("exec_rails_invalid");
        let real = root.join("proj/node_modules");
        std::fs::create_dir_all(&real).unwrap();
        let traversal = format!("{}/proj/../proj/node_modules", root.to_string_lossy());
        let newline = format!("{}/proj/node\nmodules", root.to_string_lossy());
        let calls = std::cell::RefCell::new(0u32);
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            *calls.borrow_mut() += 1;
            Ok(Removal::Removed)
        };
        let arts = vec![
            Artifact {
                path: traversal.clone(),
                size_bytes: 1,
            },
            Artifact {
                path: newline.clone(),
                size_bytes: 1,
            },
        ];
        let out = execute_with_remover(&arts, true, |_| {}, remover);
        assert_eq!(out.protected, vec![traversal, newline], "{out:?}");
        assert!(out.removed.is_empty() && out.errors.is_empty(), "{out:?}");
        assert_eq!(
            *calls.borrow(),
            0,
            "a refused path never reaches the remover"
        );
        assert!(real.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_artifact_is_dropped_silently_like_bash() {
        // `lib/clean/project.sh:1657`: `if [[ -e "$item_path" ]]` — a vanished artifact is neither
        // removed nor an error, and contributes nothing to the counters.
        let arts = vec![Artifact {
            path: "/no/such/burrow_purge_dir".into(),
            size_bytes: 5,
        }];
        let out = execute(&arts, true);
        assert!(out.removed.is_empty());
        assert_eq!(out.freed_bytes, 0);
        if crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            assert!(out.errors.is_empty(), "{out:?}");
            assert!(out.protected.is_empty(), "{out:?}");
        }
    }

    // -- defect 2: permanent vs recoverable dispatch, via the injected remover (hermetic — see
    // clean::execute's identically-shaped tests for why the real Trash call isn't exercised here).

    #[cfg(unix)]
    #[test]
    fn permanent_false_is_the_default_and_reaches_the_remover_as_false() {
        let root = scratch("permanent_false");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let arts = vec![Artifact {
            path: nm.to_string_lossy().into_owned(),
            size_bytes: 1,
        }];
        let seen: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
        let remover = |_p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(permanent);
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&arts, false, |_| {}, remover);
        assert_eq!(out.removed.len(), 1);
        assert_eq!(seen.into_inner(), vec![false]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permanent_true_reaches_the_remover_as_true() {
        let root = scratch("permanent_true");
        let target = root.join("target");
        std::fs::create_dir_all(&target).unwrap();
        let arts = vec![Artifact {
            path: target.to_string_lossy().into_owned(),
            size_bytes: 1,
        }];
        let seen: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
        let remover = |_p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(permanent);
            Ok(Removal::Removed)
        };
        let _ = execute_with_remover(&arts, true, |_| {}, remover);
        assert_eq!(seen.into_inner(), vec![true]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_recoverable_delete_is_reported_as_an_error_never_a_fallback_hard_delete() {
        let root = scratch("recover_fail");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("still_here"), b"x").unwrap();
        let arts = vec![Artifact {
            path: nm.to_string_lossy().into_owned(),
            size_bytes: 1,
        }];
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            Err("trash unavailable".into())
        };
        let out = execute_with_remover(&arts, false, |_| {}, remover);
        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(out.errors.len(), 1);
        assert!(
            nm.exists() && nm.join("still_here").exists(),
            "a failed recoverable delete must not fall back to removing the artifact anyway"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// RULEBOOK §3m: a Trash move frees nothing, so the default path bills `moved_to_trash_bytes`
    /// and leaves `freed_bytes` at 0 — and the human line says where the bytes went.
    #[cfg(unix)]
    #[test]
    fn trash_mode_bills_moved_to_trash_bytes_never_freed_bytes() {
        let root = scratch("trash_billing");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("blob"), [b'x'; 700]).unwrap();
        let arts = vec![Artifact {
            path: nm.to_string_lossy().into_owned(),
            size_bytes: 700,
        }];
        let mover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            std::fs::remove_dir_all(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&arts, false, |_| {}, mover);
        assert_eq!(out.freed_bytes, 0, "{out:?}");
        assert_eq!(out.moved_to_trash_bytes, 700, "{out:?}");
        let j = outcome_to_json(&out);
        assert!(j.contains("\"freed_bytes\":0"), "{j}");
        assert!(j.contains("\"moved_to_trash_bytes\":700"), "{j}");
        let text = render_outcome_text(&out);
        assert!(text.contains("Moved to Trash: 700B | Items: 1"), "{text}");
        assert!(!text.contains("Space freed"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_remover_that_reports_success_without_deleting_is_billed_nothing() {
        let root = scratch("lying");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let arts = vec![Artifact {
            path: nm.to_string_lossy().into_owned(),
            size_bytes: 999_999,
        }];
        let lying =
            |_p: &Path, _permanent: bool| -> Result<Removal, String> { Ok(Removal::Removed) };
        for permanent in [false, true] {
            let out = execute_with_remover(&arts, permanent, |_| {}, lying);
            assert_eq!(out.freed_bytes, 0, "permanent={permanent}: {out:?}");
            assert_eq!(
                out.moved_to_trash_bytes, 0,
                "permanent={permanent}: {out:?}"
            );
            assert_eq!(out.removed.len(), 1);
            assert_eq!(out.removed[0].bytes(), 0);
        }
        assert!(nm.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn outcome_json_shape() {
        let out = PurgeOutcome {
            removed: vec![removed_item("/a/node_modules", 100)],
            freed_bytes: 100,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/b/target".into(),
                error: "boom".into(),
            }],
            protected: vec!["/c/vendor".into()],
        };
        let j = outcome_to_json(&out);
        assert!(j.contains("\"dry_run\":false"));
        assert!(j.contains("\"freed_bytes\":100"));
        assert!(j.contains("\"moved_to_trash_bytes\":0"), "{j}");
        assert!(j.contains("\"removed\":[{\"path\":\"/a/node_modules\",\"size_bytes\":100}]"));
        assert!(j.contains("\"errors\":[{\"path\":\"/b/target\",\"error\":\"boom\"}]"));
        assert!(j.contains("\"protected\":[\"/c/vendor\"]"));
        assert!(j.contains("\"text\":\""), "text field is present: {j}");
    }

    // -- text field: matched against bin/purge.sh's real wording (the oracle this module ports
    // from — see the module doc), not a shape invented for the test. `mergeSummaryFields` in the
    // app's real TaskReport.swift (origin/main) only recognises "potential space" / "tracked
    // cleanup" / "free space change" / "free space now" — none of which purge's own oracle text
    // ever contains, confirmed by running the golden's `text` through the actual parser (see the
    // repoint-redo Gate 1 harness). So purge's `summary` is nil on BOTH sides; these tests assert
    // the real oracle's wording is reproduced, not that a parser accepts it.

    #[test]
    fn dry_run_text_matches_purge_sh_wording_when_artifacts_found() {
        let arts = vec![
            Artifact {
                path: "/a/node_modules".into(),
                size_bytes: 1_000,
            },
            Artifact {
                path: "/b/target".into(),
                size_bytes: 500,
            },
        ];
        let total: u64 = arts.iter().map(|a| a.size_bytes).sum();
        let text = render_dry_run_text(&arts, total);
        assert!(
            text.contains("DRY RUN MODE"),
            "matches bin/purge.sh's dry-run banner: {text}"
        );
        assert!(text.contains("Purge Project Artifacts"));
        assert!(
            text.contains("Dry run complete - no changes made"),
            "matches bin/purge.sh's summary_heading for MOLE_DRY_RUN=1"
        );
        // bin/purge.sh: `summary_line="Would free: ${freed}"` (+ " | Items: $count" when > 0).
        // 1000 + 500 = 1500 bytes; bytes_to_human rounds KB half-up to a whole number -> "2KB".
        assert!(
            text.contains("Would free: 2KB | Items: 2"),
            "matches bin/purge.sh's dry-run summary line: {text}"
        );
        assert!(
            text.contains("/a/node_modules"),
            "artifact paths are listed: {text}"
        );
        assert!(text.contains("/b/target"));
    }

    #[test]
    fn dry_run_text_matches_purge_sh_wording_when_nothing_found() {
        let text = render_dry_run_text(&[], 0);
        // bin/purge.sh's else-branch: `summary_details+=("No old project artifacts to clean.")`.
        assert!(text.contains("No old project artifacts to clean."));
        assert!(!text.contains("Would free"));
    }

    #[test]
    fn outcome_text_matches_purge_sh_wording_when_items_removed() {
        let outcome = PurgeOutcome {
            removed: vec![removed_item("/a/node_modules", 2_000)],
            freed_bytes: 2_000,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/b/target".into(),
                error: "boom".into(),
            }],
            protected: vec!["/c/vendor".into()],
        };
        let text = render_outcome_text(&outcome);
        assert!(
            text.contains("Purge complete"),
            "matches bin/purge.sh's live summary_heading: {text}"
        );
        // bin/purge.sh: `summary_line="Space freed: ${freed}"` for a real (non-dry-run) run.
        assert!(
            text.contains("Space freed: 2KB | Items: 1"),
            "matches bin/purge.sh's live summary line: {text}"
        );
        assert!(text.contains("/a/node_modules"));
        assert!(
            text.contains("/c/vendor"),
            "protected paths are surfaced: {text}"
        );
        assert!(
            text.contains("/b/target"),
            "errored paths are surfaced: {text}"
        );
        assert!(text.contains("boom"));
    }

    #[test]
    fn text_never_trips_the_swift_parsers_summary_phrases() {
        // mergeSummaryFields (TaskReport.swift, origin/main) keys ONLY on these four phrases.
        // Purge's real oracle text never contains them (verified against the golden through the
        // actual Swift parser); this asserts the engine doesn't accidentally start matching one,
        // which would silently change what the MCP `summary` field reports for purge.
        let arts = vec![Artifact {
            path: "/a/node_modules".into(),
            size_bytes: 1_000,
        }];
        let dry = render_dry_run_text(&arts, 1_000).to_lowercase();
        let outcome = PurgeOutcome {
            removed: vec![removed_item("/a/node_modules", 1_000)],
            freed_bytes: 1_000,
            moved_to_trash_bytes: 0,
            errors: vec![],
            protected: vec![],
        };
        let applied = render_outcome_text(&outcome).to_lowercase();
        for phrase in [
            "potential space",
            "tracked cleanup",
            "free space change",
            "free space now",
        ] {
            assert!(
                !dry.contains(phrase),
                "dry-run text unexpectedly contains {phrase:?}"
            );
            assert!(
                !applied.contains(phrase),
                "applied text unexpectedly contains {phrase:?}"
            );
        }
    }
    /// `purge --stream` speaks `clean --stream`'s vocabulary — checked by parsing the lines with
    /// the engine's own reader and asserting the same keys `BurrowStreamReport.swift` reads:
    /// preview `would_remove{path,bytes}` … `done{dry_run,would_free_bytes,would_free_human,
    /// count}`; live `removed{path,bytes}` / `failed{path,error}` / `protected{path}` … `done{…}`.
    #[test]
    fn stream_lines_use_the_clean_stream_vocabulary() {
        use crate::json::Json;
        let arts = vec![
            Artifact {
                path: "/h/proj/node_modules".into(),
                size_bytes: 4096,
            },
            Artifact {
                path: "/h/proj/target".into(),
                size_bytes: 1024,
            },
        ];
        let lines = preview_stream_lines(&arts);
        assert_eq!(lines.len(), 3);
        let first = Json::parse(&lines[0]).unwrap();
        assert_eq!(
            first.get("event").and_then(Json::as_str),
            Some("would_remove")
        );
        assert_eq!(
            first.get("path").and_then(Json::as_str),
            Some("/h/proj/node_modules")
        );
        assert_eq!(first.get("bytes").and_then(Json::as_u64), Some(4096));
        let done = Json::parse(&lines[2]).unwrap();
        assert_eq!(done.get("event").and_then(Json::as_str), Some("done"));
        assert_eq!(done.get("dry_run").and_then(Json::as_bool), Some(true));
        assert_eq!(
            done.get("would_free_bytes").and_then(Json::as_u64),
            Some(5120)
        );
        assert_eq!(
            done.get("would_free_human").and_then(Json::as_str),
            Some(crate::clean::format::bytes_to_human(5120).as_str())
        );
        assert_eq!(done.get("count").and_then(Json::as_u64), Some(2));
        // Byte-identical to what `clean --stream` emits for the same path + size.
        assert_eq!(
            lines[0],
            crate::clean::stream::would_remove_ndjson(&crate::clean::plan::CleanCandidate {
                path: "/h/proj/node_modules".into(),
                label: "node_modules".into(),
                size: 4096,
            })
        );
    }

    /// Live: one event per artifact as it is processed, in order, with `failed` carrying the
    /// remover's error, `protected` the guard's refusal, and a vanished artifact emitting nothing
    /// (it is neither removed nor failed, `project.sh:1657`).
    #[cfg(unix)]
    #[test]
    fn live_stream_emits_one_event_per_artifact_as_it_happens() {
        use crate::clean::stream::{done_ndjson, event_ndjson};
        use crate::json::Json;
        let root = scratch("stream_live");
        let ok = root.join("proj/node_modules");
        let bad = root.join("proj/target");
        std::fs::create_dir_all(&ok).unwrap();
        std::fs::write(ok.join("blob"), [b'x'; 10]).unwrap();
        std::fs::create_dir_all(&bad).unwrap();
        let gone = root.join("proj/.gradle");
        let vendor = root.join("proj/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        let arts: Vec<Artifact> = [&ok, &bad, &gone, &vendor]
            .iter()
            .map(|p| Artifact {
                path: p.to_string_lossy().into_owned(),
                size_bytes: 10,
            })
            .collect();
        let remover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            if p.ends_with("target") {
                Err("disk says no".into())
            } else {
                std::fs::remove_dir_all(p).map_err(|e| e.to_string())?;
                Ok(Removal::Removed)
            }
        };
        let mut lines = Vec::new();
        let out = execute_with_remover(&arts, true, |ev| lines.push(event_ndjson(&ev)), remover);
        lines.push(done_ndjson(&out));
        let parsed: Vec<Json> = lines.iter().map(|l| Json::parse(l).unwrap()).collect();
        let events: Vec<&str> = parsed
            .iter()
            .map(|p| p.get("event").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(
            events,
            ["removed", "failed", "protected", "done"],
            "{lines:?}"
        );
        assert_eq!(
            parsed[0].get("path").and_then(Json::as_str),
            Some(ok.to_string_lossy().as_ref())
        );
        assert_eq!(parsed[0].get("bytes").and_then(Json::as_u64), Some(10));
        assert_eq!(
            parsed[1].get("error").and_then(Json::as_str),
            Some("disk says no")
        );
        assert_eq!(
            parsed[2].get("path").and_then(Json::as_str),
            Some(vendor.to_string_lossy().as_ref())
        );
        let done = &parsed[3];
        assert_eq!(done.get("freed_bytes").and_then(Json::as_u64), Some(10));
        assert_eq!(done.get("removed").and_then(Json::as_u64), Some(1));
        assert_eq!(done.get("failed").and_then(Json::as_u64), Some(1));
        assert_eq!(done.get("protected").and_then(Json::as_u64), Some(1));
        assert!(done.get("dry_run").is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
