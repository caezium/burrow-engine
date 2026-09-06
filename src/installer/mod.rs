//! Installer-file cleanup — the engine port of digger's `installer` command (bin/installer.sh).
//!
//! Finds leftover installer files (`.dmg`, `.pkg`, `.mpkg`, `.iso`, `.xip`, and installer-shaped
//! `.zip`s) in the usual download locations and, with `--apply`, removes them. Dry-run by default.
//! The classification is pure/tested; only the directory walk, the `zipinfo` probe, and the file
//! removal touch the filesystem. A `.zip` counts only when its contents include a `.app`/`.pkg`/
//! `.dmg`/`.xip` (checked without extracting) — an arbitrary archive is never treated as an
//! installer.

use crate::clean::execute::{
    remove_guarded, remove_one_reported, CleanOutcome, Freed, Guarded, Removal, RemovalError,
};
use crate::clean::protect::ProtectionMode;
use std::path::Path;

/// Direct installer extensions — any file with one of these is an installer.
pub const INSTALLER_EXTS: &[&str] = &["dmg", "pkg", "mpkg", "iso", "xip"];
/// How many zip entries to inspect before giving up on the installer-shape check.
const MAX_ZIP_ENTRIES: usize = 50;
/// Download-tree scan depth (files directly in a location or one level down).
const SCAN_MAX_DEPTH: usize = 2;

/// The download locations scanned for installer files.
pub fn scan_paths(home: &str) -> Vec<String> {
    [
        "Downloads",
        "Desktop",
        "Library/Downloads",
        "Library/Mobile Documents/com~apple~CloudDocs/Downloads",
        "Library/Containers/com.apple.mail/Data/Library/Mail Downloads",
        "Library/Application Support/Telegram Desktop",
        "Downloads/Telegram Desktop",
    ]
    .iter()
    .map(|sub| format!("{home}/{sub}"))
    .chain(std::iter::once("/Users/Shared/Downloads".to_string()))
    .collect()
}

/// The lowercased extension of a filename, if any.
fn ext_of(name: &str) -> Option<String> {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

/// Whether `name` is a direct installer (dmg/pkg/mpkg/iso/xip), case-insensitively.
pub fn is_direct_installer(name: &str) -> bool {
    ext_of(name).is_some_and(|e| INSTALLER_EXTS.contains(&e.as_str()))
}

/// Whether `name` has a `.zip` extension (candidate for the contents check).
pub fn is_zip(name: &str) -> bool {
    ext_of(name).as_deref() == Some("zip")
}

/// Pure classifier for a zip's entry listing (one path per line, e.g. `zipinfo -1` output): a zip
/// is installer-shaped when any of its first `MAX_ZIP_ENTRIES` entries is a `.app`/`.pkg`/`.dmg`/
/// `.xip` (as a path component or the entry itself) — matching digger's `\.(app|pkg|dmg|xip)(/|$)`.
pub fn zip_entries_look_like_installer(listing: &str) -> bool {
    listing.lines().take(MAX_ZIP_ENTRIES).any(|line| {
        ["app", "pkg", "dmg", "xip"]
            .iter()
            .any(|e| line.contains(&format!(".{e}/")) || line.ends_with(&format!(".{e}")))
    })
}

/// Whether a `.zip` file's contents look like an installer, probed without extracting via
/// `zipinfo -1` (falling back to `unzip -Z -1`). False if neither tool is available or on error.
pub fn is_installer_zip(path: &Path) -> bool {
    is_installer_zip_with(path, &crate::platform::run_command)
}

/// [`is_installer_zip`] with the listing tool's runner injected.
pub fn is_installer_zip_with(path: &Path, run: crate::platform::Runner<'_>) -> bool {
    zip_listing(path, run)
        .map(|l| zip_entries_look_like_installer(&l))
        .unwrap_or(false)
}

/// `zipinfo -1 <zip>`, then `unzip -Z -1 <zip>`, through `run`; the first that succeeds wins.
fn zip_listing(path: &Path, run: crate::platform::Runner<'_>) -> Option<String> {
    let p = path.to_str()?;
    for (prog, args) in [
        ("zipinfo", ["-1"].as_slice()),
        ("unzip", ["-Z", "-1"].as_slice()),
    ] {
        let mut argv: Vec<&str> = args.to_vec();
        argv.push(p);
        if let Some(out) = run(prog, &argv) {
            return Some(out);
        }
    }
    None
}

/// One installer file found on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installer {
    pub path: String,
    pub size_bytes: u64,
    /// The scan location it was found under (e.g. `~/Downloads`).
    pub source: String,
    /// The file's identity at scan time, re-checked before removal — see [`file_identity`].
    pub identity: Option<FileIdentity>,
}

/// What `mole_path_identity` (`lib/core/common.sh:43`) answers: `inode:<dev>:<ino>` of the file
/// itself. The oracle's installer records it per candidate at plan time and refuses to delete a
/// candidate whose identity has changed by the time it acts (`bin/installer.sh:598-613`), so a
/// file swapped out under the same name between the scan and the removal is never the one deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// The file's current identity, or `None` when it cannot be read (missing, or a platform with no
/// inode numbers — where the identity check is skipped, never failed, because it would otherwise
/// refuse every candidate on that platform).
#[cfg(unix)]
pub fn file_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| FileIdentity {
        dev: m.dev(),
        ino: m.ino(),
    })
}

#[cfg(not(unix))]
pub fn file_identity(_path: &Path) -> Option<FileIdentity> {
    None
}

/// Walk each scan path (depth 1..=2), classify installer files (skipping symlinks), and collect
/// them with their size + source location. Read-only.
pub fn scan(paths: &[String]) -> Vec<Installer> {
    scan_with(paths, &crate::platform::run_command)
}

/// [`scan`] with the zip-listing runner injected (the only subprocess a scan spawns).
pub fn scan_with(paths: &[String], run: crate::platform::Runner<'_>) -> Vec<Installer> {
    let mut found = Vec::new();
    for sp in paths {
        let root = Path::new(sp);
        if !root.is_dir() {
            continue;
        }
        walk(root, sp, 1, &mut found, run);
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    found.dedup();
    found
}

pub fn from_reviewed_paths(paths: &[String], roots: &[String]) -> Result<Vec<Installer>, String> {
    paths
        .iter()
        .map(|path| {
            let file = Path::new(path);
            let source = reviewed_source(file, roots).ok_or_else(|| {
                format!("reviewed installer path is no longer in a download location: {path}")
            })?;
            if !(is_direct_installer(path) || (is_zip(path) && is_installer_zip(file))) {
                return Err(format!("reviewed file is no longer an installer: {path}"));
            }
            let metadata = std::fs::metadata(file)
                .map_err(|e| format!("cannot read reviewed installer: {e}"))?;
            Ok(Installer {
                path: path.clone(),
                size_bytes: metadata.len(),
                source,
                identity: file_identity(file),
            })
        })
        .collect()
}

fn reviewed_source(path: &Path, roots: &[String]) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    roots
        .iter()
        .find(|root| {
            crate::reviewed_plan::relative_components(path, Path::new(root))
                .is_some_and(|parts| parts.len() <= SCAN_MAX_DEPTH)
        })
        .cloned()
}

fn walk(
    dir: &Path,
    source: &str,
    depth: usize,
    out: &mut Vec<Installer>,
    run: crate::platform::Runner<'_>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue; // skip symlinks explicitly (matches digger)
        }
        let path = e.path();
        if ft.is_dir() {
            if depth < SCAN_MAX_DEPTH {
                walk(&path, source, depth + 1, out, run);
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let is_installer =
            is_direct_installer(&name) || (is_zip(&name) && is_installer_zip_with(&path, run));
        if is_installer {
            let size_bytes = e.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(Installer {
                path: path.to_string_lossy().into_owned(),
                size_bytes,
                source: source.to_string(),
                identity: file_identity(&path),
            });
        }
    }
}

use crate::json::escape as esc;

fn installer_obj(i: &Installer) -> String {
    format!(
        "{{\"path\":{},\"size_bytes\":{},\"source\":{}}}",
        esc(&i.path),
        i.size_bytes,
        esc(&i.source)
    )
}

/// Serialize the dry-run report: `{dry_run:true,installers:[…],count:N,total_bytes:B}`.
pub fn to_json(installers: &[Installer]) -> String {
    let total: u64 = installers.iter().map(|i| i.size_bytes).sum();
    let items = installers
        .iter()
        .map(installer_obj)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"dry_run\":true,\"installers\":[{items}],\"count\":{},\"total_bytes\":{total}}}",
        installers.len()
    )
}

/// The result of a destructive installer cleanup — the same [`CleanOutcome`] `clean` reports
/// through, so the byte accounting, the `protected` bucket and the history logging are shared.
/// `removed[].label` is the installer's file name.
pub type InstallerOutcome = CleanOutcome;

/// Remove each installer file through the shared guarded remover
/// ([`crate::clean::execute::remove_guarded`]) — the same rails `clean` runs, because the oracle's
/// `mole_delete` validates every path before it deletes (`file_ops.sh:522`). Before that, the three
/// re-checks `bin/installer.sh:598-613` makes between planning and acting are ported verbatim:
/// the file must still exist, its identity must match the scan ([`FileIdentity`]), and its size
/// must match the scan — any drift is refused as `changed since scan`, because a file that changed
/// under the same name is not the file the user was shown. After the removal, the oracle's own
/// `still exists` post-check (`:625`) is what [`Freed::Unverified`] reports here: a remover that
/// exited zero while the file is still on disk is an error, and bills nothing (RULEBOOK §3m).
///
/// `permanent` selects the removal mode: `false` (the default) routes each file through the real
/// macOS Trash ([`crate::trash::move_to_trash`]); `true` removes it immediately via
/// `fs::remove_file` — irreversible. Errors (including a failed recoverable delete) are collected,
/// not fatal — a Trash failure on one file is never a reason to hard-delete it instead or to abort
/// the rest of the run.
pub fn execute(installers: &[Installer], permanent: bool) -> InstallerOutcome {
    execute_with_remover(installers, permanent, remove_one_reported)
}

pub fn execute_reviewed(
    installers: &[Installer],
    roots: &[String],
    permanent: bool,
) -> InstallerOutcome {
    execute_checked_with_remover(installers, permanent, remove_one_reported, |path| {
        reviewed_source(path, roots).is_some()
    })
}

/// The oracle's wording for a candidate that drifted between scan and apply (`installer.sh:604`).
const CHANGED_SINCE_SCAN: &str = "changed since scan";

/// [`execute`] with the per-file removal function injected — the seam that makes the
/// permanent/recoverable dispatch testable without a real Trash call. See
/// `crate::clean::execute`'s identically-shaped split for the full reasoning.
fn execute_with_remover(
    installers: &[Installer],
    permanent: bool,
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
) -> InstallerOutcome {
    execute_checked_with_remover(installers, permanent, remover, |_| true)
}

fn execute_checked_with_remover(
    installers: &[Installer],
    permanent: bool,
    remover: impl Fn(&Path, bool) -> Result<Removal, String>,
    allowed: impl Fn(&Path) -> bool,
) -> InstallerOutcome {
    let mut outcome = InstallerOutcome::default();
    for i in installers {
        let path = Path::new(&i.path);
        if !allowed(path) {
            outcome.protected.push(i.path.clone());
            continue;
        }
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // `installer.sh:597`: `[[ ! -e "$file_path" && ! -L "$file_path" ]]` → "missing". Unlike
        // clean/purge, a vanished installer IS recorded as a failure in the oracle.
        if !path.exists() && path.symlink_metadata().is_err() {
            outcome.errors.push(RemovalError {
                path: i.path.clone(),
                error: "missing".to_string(),
            });
            continue;
        }
        // `:602-606`: identity, then `:608-616`: size. On a platform with no identity the scan
        // recorded `None` and the check is skipped rather than failed.
        if i.identity.is_some() && file_identity(path) != i.identity {
            outcome.errors.push(RemovalError {
                path: i.path.clone(),
                error: CHANGED_SINCE_SCAN.to_string(),
            });
            continue;
        }
        match std::fs::metadata(path).map(|m| m.len()) {
            Ok(current) if current == i.size_bytes => {}
            Ok(_) => {
                outcome.errors.push(RemovalError {
                    path: i.path.clone(),
                    error: CHANGED_SINCE_SCAN.to_string(),
                });
                continue;
            }
            Err(_) => {
                outcome.errors.push(RemovalError {
                    path: i.path.clone(),
                    error: "size unavailable".to_string(),
                });
                continue;
            }
        }
        // `bin/installer.sh` never exports MOLE_UNINSTALL_MODE and `mole_delete` consults no
        // whitelist — so the cleanup regime, with no whitelist.
        match remove_guarded(
            &i.path,
            i.size_bytes,
            &[],
            permanent,
            ProtectionMode::Cleanup,
            &remover,
        ) {
            Guarded::Protected => outcome.protected.push(i.path.clone()),
            // Existence was checked above; a path that vanishes in between is the oracle's own
            // `missing` arm, reached one step later.
            Guarded::Missing => outcome.errors.push(RemovalError {
                path: i.path.clone(),
                error: "missing".to_string(),
            }),
            // `:625`: `record_installer_delete_failure "$file_path" "still exists"`.
            Guarded::Removed(Freed::Unverified) => outcome.errors.push(RemovalError {
                path: i.path.clone(),
                error: "still exists".to_string(),
            }),
            Guarded::Removed(freed) => outcome.record_removed(&i.path, &label, freed, permanent),
            Guarded::Failed(e) => outcome.errors.push(RemovalError {
                path: i.path.clone(),
                error: e,
            }),
        }
    }
    outcome
}

const RULE: &str = "======================================================================";

/// Human-readable report text for a completed (`--apply`) run, in `bin/installer.sh`'s
/// `show_summary` wording (`:758-807`): `Installers cleaned` / `Installer cleanup incomplete`,
/// `Removed N installers, freed X` / `No installers were removed`, `Failed to remove N installers`.
fn render_outcome_text(outcome: &InstallerOutcome) -> String {
    let mut out = String::new();
    out.push_str("Installer Cleanup\n\n");
    if !outcome.removed.is_empty() {
        out.push_str("➤ Installers\n");
        for r in &outcome.removed {
            out.push_str(&format!(
                "  ✓ {}, {}\n",
                r.path,
                crate::clean::format::bytes_to_human(r.bytes())
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
    if outcome.errors.is_empty() {
        out.push_str("Installers cleaned\n");
    } else {
        out.push_str("Installer cleanup incomplete\n");
    }
    // `installer.sh:776` says "freed"; that is true of its `rm`, not of this crate's default Trash
    // path, which frees nothing until the Trash is emptied — so the line names the destination.
    if outcome.removed.is_empty() {
        out.push_str("No installers were removed\n");
    } else if outcome.moved_to_trash_bytes > 0 {
        out.push_str(&format!(
            "Removed {} installers, moved {} to Trash\n",
            outcome.removed.len(),
            crate::clean::format::bytes_to_human(outcome.accounted_bytes())
        ));
    } else {
        out.push_str(&format!(
            "Removed {} installers, freed {}\n",
            outcome.removed.len(),
            crate::clean::format::bytes_to_human(outcome.freed_bytes)
        ));
    }
    if !outcome.errors.is_empty() {
        out.push_str(&format!(
            "Failed to remove {} installers\n",
            outcome.errors.len()
        ));
    }
    out.push_str(RULE);
    out
}

/// Serialize a destructive outcome:
/// `{dry_run:false,freed_bytes,moved_to_trash_bytes,removed:[{path,size_bytes,source}],errors:[{path,error}],protected:[…],text:S}`.
/// `removed[].size_bytes` is what this run can PROVE left that path, so it sums to
/// `freed_bytes + moved_to_trash_bytes` exactly (on the default path `freed_bytes` is 0 — a Trash
/// move frees no space); `source` is looked up from the scanned `installers` the outcome came
/// from. `moved_to_trash_bytes`, `protected` and `text` are additive over the shape's earliest form.
pub fn outcome_to_json(outcome: &InstallerOutcome, installers: &[Installer]) -> String {
    let removed = outcome
        .removed
        .iter()
        .map(|r| {
            let source = installers
                .iter()
                .find(|i| i.path == r.path)
                .map(|i| i.source.as_str())
                .unwrap_or("");
            format!(
                "{{\"path\":{},\"size_bytes\":{},\"source\":{}}}",
                esc(&r.path),
                r.bytes(),
                esc(source)
            )
        })
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
        let dir = std::env::temp_dir().join(format!("burrow_inst_{}_{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reviewed_plan_does_not_scan_for_later_installers() {
        let root = scratch("reviewed_exact");
        let reviewed = root.join("reviewed.dmg");
        let late = root.join("late.pkg");
        std::fs::write(&reviewed, "reviewed").unwrap();
        std::fs::write(&late, "later").unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let paths = vec![reviewed.to_string_lossy().into_owned()];
        let installers = from_reviewed_paths(&paths, &roots).unwrap();
        assert_eq!(installers.len(), 1);
        let remover_calls = std::cell::Cell::new(0);
        let outcome = execute_checked_with_remover(
            &installers,
            true,
            |path, _| {
                remover_calls.set(remover_calls.get() + 1);
                assert_eq!(path, reviewed);
                std::fs::remove_file(path).unwrap();
                Ok(Removal::Removed)
            },
            |path| reviewed_source(path, &roots).is_some(),
        );
        assert!(outcome.errors.is_empty());
        if crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            assert_eq!(outcome.removed.len(), 1);
            assert!(outcome.protected.is_empty());
            assert_eq!(remover_calls.get(), 1);
            assert!(!reviewed.exists());
        } else {
            // Reviewed-path selection works on Windows, but apply still refuses paths outside
            // the POSIX protection tables before reaching even an injected remover.
            assert!(outcome.removed.is_empty());
            assert_eq!(outcome.protected, paths);
            assert_eq!(remover_calls.get(), 0);
            assert!(reviewed.exists());
        }
        assert!(late.exists());
        let deep = root.join("a/b/deep.dmg");
        std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
        std::fs::write(&deep, "deep").unwrap();
        assert!(from_reviewed_paths(&[deep.to_string_lossy().into_owned()], &roots).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn reviewed_plan_rechecks_installer_parent_aliases_at_apply() {
        let root = scratch("reviewed_alias");
        let sub = root.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let path = sub.join("reviewed.dmg");
        std::fs::write(&path, "reviewed").unwrap();
        let roots = vec![root.to_string_lossy().into_owned()];
        let paths = vec![path.to_string_lossy().into_owned()];
        let installers = from_reviewed_paths(&paths, &roots).unwrap();
        std::fs::rename(&sub, root.join("original")).unwrap();
        std::os::unix::fs::symlink(root.join("original"), &sub).unwrap();
        assert!(from_reviewed_paths(&paths, &roots).is_err());
        let outcome = execute_checked_with_remover(
            &installers,
            true,
            |_, _| panic!("must not remove"),
            |path| reviewed_source(path, &roots).is_some(),
        );
        assert_eq!(outcome.protected, paths);
        assert!(root.join("original/reviewed.dmg").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn direct_installer_extensions_case_insensitive() {
        for n in ["App.dmg", "Tool.PKG", "img.iso", "x.mpkg", "y.xip"] {
            assert!(is_direct_installer(n), "{n} is an installer");
        }
        for n in ["notes.txt", "photo.png", "archive.tar", "data.zip"] {
            assert!(!is_direct_installer(n), "{n} is not a direct installer");
        }
    }

    #[test]
    fn zip_contents_classifier() {
        assert!(zip_entries_look_like_installer(
            "Foo.app/\nFoo.app/Contents/MacOS/Foo"
        ));
        assert!(zip_entries_look_like_installer("Installer.pkg"));
        assert!(zip_entries_look_like_installer("nested/dir/Thing.dmg"));
        // Not an installer: no .app/.pkg/.dmg/.xip entries.
        assert!(!zip_entries_look_like_installer(
            "readme.txt\nsrc/main.rs\ndata.json"
        ));
        // ".application" must NOT match ".app" (needs / or end after the ext).
        assert!(!zip_entries_look_like_installer("Foo.application/config"));
    }

    #[test]
    fn zip_classifier_caps_at_50_entries() {
        // The installer marker sits on line 51 → beyond the cap → not detected.
        let mut lines: Vec<String> = (0..50).map(|i| format!("file{i}.txt")).collect();
        lines.push("Sneaky.app/".to_string());
        assert!(!zip_entries_look_like_installer(&lines.join("\n")));
        // Same marker on line 50 (within the cap) → detected.
        let mut in_cap: Vec<String> = (0..49).map(|i| format!("file{i}.txt")).collect();
        in_cap.push("Sneaky.app/".to_string());
        assert!(zip_entries_look_like_installer(&in_cap.join("\n")));
    }

    #[test]
    fn scan_finds_installers_skips_others_and_respects_depth() {
        let root = scratch("scan");
        std::fs::write(root.join("Chrome.dmg"), vec![0u8; 100]).unwrap();
        std::fs::write(root.join("notes.txt"), "x").unwrap();
        // depth 2: still scanned.
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/Tool.pkg"), vec![0u8; 50]).unwrap();
        // depth 3: beyond SCAN_MAX_DEPTH → ignored.
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::fs::write(root.join("sub/deep/Hidden.dmg"), vec![0u8; 10]).unwrap();

        let found = scan(&[root.to_string_lossy().into_owned()]);
        let names: Vec<String> = found
            .iter()
            .map(|i| {
                Path::new(&i.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(names.contains(&"Chrome.dmg".to_string()));
        assert!(names.contains(&"Tool.pkg".to_string()));
        assert!(!names.contains(&"notes.txt".to_string()));
        assert!(
            !names.contains(&"Hidden.dmg".to_string()),
            "depth 3 not scanned"
        );
        assert_eq!(found.iter().map(|i| i.size_bytes).sum::<u64>(), 150);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A scanned installer for `path`, with the identity the real scan would record.
    fn scanned(path: &Path, source: &Path) -> Installer {
        Installer {
            path: path.to_string_lossy().into_owned(),
            size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            source: source.to_string_lossy().into_owned(),
            identity: file_identity(path),
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
    fn execute_removes_files_and_frees_bytes() {
        let root = scratch("exec");
        let dmg = root.join("App.dmg");
        std::fs::write(&dmg, vec![0u8; 200]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let out = execute(&insts, true);
        assert_eq!(out.removed.len(), 1, "{out:?}");
        assert_eq!(out.freed_bytes, 200);
        assert!(!dmg.exists(), "the installer file is gone");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn execute_reports_errors_for_missing() {
        // `installer.sh:597-599`: a planned file that is no longer there is recorded as `missing`.
        let out = execute(
            &[Installer {
                path: "/no/such/burrow_inst.dmg".into(),
                size_bytes: 9,
                ..Default::default()
            }],
            true,
        );
        assert!(out.removed.is_empty());
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].error, "missing");
        assert_eq!(out.freed_bytes, 0);
    }

    /// `bin/installer.sh:608-616`: the size is re-read before acting and a mismatch is refused as
    /// `changed since scan`. A download that finished (or a file overwritten) between the scan the
    /// user was shown and the removal is not the file they agreed to delete.
    #[test]
    fn a_candidate_whose_size_changed_between_scan_and_apply_is_refused() {
        let root = scratch("size_drift");
        let dmg = root.join("Grown.dmg");
        std::fs::write(&dmg, vec![0u8; 100]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        assert_eq!(insts[0].size_bytes, 100, "fixture sanity");
        // …and now it grows.
        std::fs::write(&dmg, vec![0u8; 250]).unwrap();
        let calls = std::cell::RefCell::new(0u32);
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            *calls.borrow_mut() += 1;
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&insts, true, remover);
        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(
            out.errors,
            vec![RemovalError {
                path: dmg.to_string_lossy().into_owned(),
                error: CHANGED_SINCE_SCAN.to_string()
            }]
        );
        assert_eq!(
            *calls.borrow(),
            0,
            "a refused candidate never reaches the remover"
        );
        assert_eq!(out.freed_bytes, 0);
        assert!(dmg.exists(), "the changed file is left alone");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `bin/installer.sh:602-606`: the identity (`mole_path_identity`, dev:ino) is re-read too, so
    /// a file REPLACED by one of the same size under the same name is refused as well.
    #[cfg(unix)]
    #[test]
    fn a_candidate_replaced_by_a_same_size_file_is_refused_on_identity() {
        let root = scratch("identity_drift");
        let dmg = root.join("Swapped.dmg");
        std::fs::write(&dmg, vec![0u8; 64]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        // Same name, same size, different inode. The replacement is created while the original
        // still exists so the two cannot share an inode, then renamed over it — a remove + write
        // may hand the freed inode straight back on some filesystems (Linux tmpfs does).
        let swap = root.join("Swapped.dmg.new");
        std::fs::write(&swap, vec![1u8; 64]).unwrap();
        std::fs::rename(&swap, &dmg).unwrap();
        let out = execute(&insts, true);
        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(out.errors[0].error, CHANGED_SINCE_SCAN);
        assert!(dmg.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The deletion rails `clean` runs are the ones `installer` runs too: the oracle deletes through
    /// `mole_delete`, which validates first (`file_ops.sh:522`). Before this, `installer --apply`
    /// re-checked nothing at all.
    #[cfg(unix)]
    #[test]
    fn apply_refuses_a_planted_protected_path() {
        let root = scratch("rails_protected");
        // `*/Library/Logs/mole/*` is on the stage-5 denylist (`protect.rs`).
        let dir = root.join("Library/Logs/mole");
        std::fs::create_dir_all(&dir).unwrap();
        let dmg = dir.join("Planted.dmg");
        std::fs::write(&dmg, vec![0u8; 10]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let out = execute(&insts, true);
        assert!(out.removed.is_empty(), "{out:?}");
        assert!(out.errors.is_empty(), "a refusal is not an error: {out:?}");
        assert_eq!(out.protected, vec![dmg.to_string_lossy().into_owned()]);
        assert_eq!(out.freed_bytes, 0);
        assert!(dmg.exists(), "the refused file is untouched");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn apply_refuses_a_path_that_fails_validation_and_never_calls_the_remover() {
        // A control character in the name is one of `validate_path_for_deletion`'s refusals.
        let root = scratch("rails_invalid");
        let dmg = root.join("Weird\nName.dmg");
        std::fs::write(&dmg, vec![0u8; 10]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let calls = std::cell::RefCell::new(0u32);
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            *calls.borrow_mut() += 1;
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&insts, true, remover);
        assert_eq!(
            out.protected,
            vec![dmg.to_string_lossy().into_owned()],
            "{out:?}"
        );
        assert!(out.removed.is_empty() && out.errors.is_empty(), "{out:?}");
        assert_eq!(*calls.borrow(), 0);
        assert!(dmg.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    // -- defect 2: permanent vs recoverable dispatch, via the injected remover (hermetic — see
    // clean::execute's identically-shaped tests for why the real Trash call isn't exercised here).

    #[cfg(unix)]
    #[test]
    fn permanent_false_is_the_default_and_reaches_the_remover_as_false() {
        let root = scratch("permanent_false");
        let dmg = root.join("App.dmg");
        std::fs::write(&dmg, b"x").unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let seen: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
        let remover = |p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(permanent);
            std::fs::remove_file(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&insts, false, remover);
        assert_eq!(out.removed.len(), 1, "{out:?}");
        assert_eq!(seen.into_inner(), vec![false]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn permanent_true_reaches_the_remover_as_true() {
        let root = scratch("permanent_true");
        let pkg = root.join("App.pkg");
        std::fs::write(&pkg, b"x").unwrap();
        let insts = vec![scanned(&pkg, &root)];
        let seen: std::cell::RefCell<Vec<bool>> = std::cell::RefCell::new(Vec::new());
        let remover = |_p: &Path, permanent: bool| -> Result<Removal, String> {
            seen.borrow_mut().push(permanent);
            Ok(Removal::Removed)
        };
        let _ = execute_with_remover(&insts, true, remover);
        assert_eq!(seen.into_inner(), vec![true]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_recoverable_delete_is_reported_as_an_error_never_a_fallback_hard_delete() {
        let root = scratch("recover_fail");
        let dmg = root.join("Still.dmg");
        std::fs::write(&dmg, vec![0u8; 10]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let remover = |_p: &Path, _permanent: bool| -> Result<Removal, String> {
            Err("trash unavailable".into())
        };
        let out = execute_with_remover(&insts, false, remover);
        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(out.errors.len(), 1);
        assert!(
            dmg.exists(),
            "a failed recoverable delete must not fall back to removing the file anyway"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `installer.sh:625`: a delete that "succeeded" while the file is still there is `still
    /// exists`, a failure — and bills nothing (RULEBOOK §3m).
    #[cfg(unix)]
    #[test]
    fn a_remover_that_reports_success_without_deleting_is_an_error_and_bills_nothing() {
        let root = scratch("still_exists");
        let dmg = root.join("Lying.dmg");
        std::fs::write(&dmg, vec![0u8; 4096]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let lying =
            |_p: &Path, _permanent: bool| -> Result<Removal, String> { Ok(Removal::Removed) };
        let out = execute_with_remover(&insts, true, lying);
        assert!(out.removed.is_empty(), "{out:?}");
        assert_eq!(out.freed_bytes, 0);
        assert_eq!(out.errors[0].error, "still exists");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// RULEBOOK §3m: a Trash move frees nothing, so the default path bills `moved_to_trash_bytes`
    /// and leaves `freed_bytes` at 0 — and the human line says where the file went.
    #[cfg(unix)]
    #[test]
    fn trash_mode_bills_moved_to_trash_bytes_never_freed_bytes() {
        let root = scratch("trash_billing");
        let dmg = root.join("App.dmg");
        std::fs::write(&dmg, vec![0u8; 300]).unwrap();
        let insts = vec![scanned(&dmg, &root)];
        let mover = |p: &Path, _permanent: bool| -> Result<Removal, String> {
            std::fs::remove_file(p).map_err(|e| e.to_string())?;
            Ok(Removal::Removed)
        };
        let out = execute_with_remover(&insts, false, mover);
        assert_eq!(out.freed_bytes, 0, "{out:?}");
        assert_eq!(out.moved_to_trash_bytes, 300, "{out:?}");
        let j = outcome_to_json(&out, &insts);
        assert!(j.contains("\"freed_bytes\":0"), "{j}");
        assert!(j.contains("\"moved_to_trash_bytes\":300"), "{j}");
        let text = render_outcome_text(&out);
        assert!(
            text.contains("Removed 1 installers, moved 300B to Trash"),
            "{text}"
        );
        assert!(!text.contains("freed"), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn json_shapes() {
        let insts = vec![Installer {
            path: "/d/App.dmg".into(),
            size_bytes: 100,
            source: "/d".into(),
            identity: None,
        }];
        let dry = to_json(&insts);
        assert!(dry.contains("\"dry_run\":true"));
        assert!(dry.contains("\"count\":1"));
        assert!(dry.contains("\"total_bytes\":100"));
        assert!(dry.contains("\"source\":\"/d\""));
        let out = InstallerOutcome {
            removed: vec![crate::clean::execute::RemovedItem {
                path: "/d/App.dmg".into(),
                label: "App.dmg".into(),
                freed: Freed::Bytes(100),
            }],
            freed_bytes: 100,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/d/bad.pkg".into(),
                error: "boom".into(),
            }],
            protected: vec!["/d/keep.pkg".into()],
        };
        let j = outcome_to_json(&out, &insts);
        assert!(j.contains("\"dry_run\":false"));
        assert!(j.contains("\"freed_bytes\":100"));
        assert!(j.contains("\"moved_to_trash_bytes\":0"), "{j}");
        assert!(
            j.contains(
                "\"removed\":[{\"path\":\"/d/App.dmg\",\"size_bytes\":100,\"source\":\"/d\"}]"
            ),
            "{j}"
        );
        assert!(j.contains("\"errors\":[{\"path\":\"/d/bad.pkg\",\"error\":\"boom\"}]"));
        assert!(j.contains("\"protected\":[\"/d/keep.pkg\"]"));
        let text = render_outcome_text(&out);
        assert!(text.contains("Installer cleanup incomplete"), "{text}");
        assert!(text.contains("Removed 1 installers, freed 100B"), "{text}");
        assert!(text.contains("Failed to remove 1 installers"), "{text}");
        assert!(j.contains("\"text\":\""), "{j}");
    }
    /// The zip probe through a fake runner: `zipinfo -1 <zip>` first, `unzip -Z -1 <zip>` when
    /// it fails, the listing classified as before — and a scan that finds an installer-shaped zip
    /// through the same seam, without a zipinfo on the box.
    #[test]
    fn zip_listing_falls_back_from_zipinfo_to_unzip_through_the_runner() {
        let root = scratch("zip_runner");
        let zip = root.join("Foo.zip");
        std::fs::write(&zip, b"PK").unwrap();
        let calls = std::cell::RefCell::new(Vec::new());
        let unzip_only = |p: &str, a: &[&str]| -> Option<String> {
            calls.borrow_mut().push(format!("{p} {}", a.join(" ")));
            (p == "unzip").then(|| "Foo.app/\nFoo.app/Contents/\n".to_string())
        };
        assert!(is_installer_zip_with(&zip, &unzip_only));
        let z = zip.to_string_lossy();
        assert_eq!(
            calls.borrow().as_slice(),
            [format!("zipinfo -1 {z}"), format!("unzip -Z -1 {z}")]
        );
        let none = |_: &str, _: &[&str]| -> Option<String> { None };
        assert!(!is_installer_zip_with(&zip, &none));
        let plain = |_: &str, _: &[&str]| -> Option<String> { Some("readme.txt\n".into()) };
        assert!(!is_installer_zip_with(&zip, &plain));

        let found = scan_with(&[root.to_string_lossy().to_string()], &unzip_only);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, z);
        assert!(scan_with(&[root.to_string_lossy().to_string()], &none).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
