//! Classify a directory as safe-to-delete-manually — ported verbatim from digger's
//! `cmd/analyze/cleanable.go`. A dir is "cleanable" when it's a CACHEDIR.TAG-marked cache tree or
//! a well-known regenerable project dependency/build dir (node_modules, target, DerivedData, …) —
//! but NOT when `mo clean` already handles it (Caches/Logs/Trash/…), to avoid double-counting.

use std::fs;
use std::io::Read;
use std::path::Path;

const CACHEDIR_TAG_FILENAME: &str = "CACHEDIR.TAG";
const CACHEDIR_TAG_SIGNATURE: &str = "Signature: 8a477f597d28d172789f06886806bc55";

/// Path fragments `mo clean` already sweeps — excluded so analyze doesn't double-count them as
/// "manually cleanable".
const MO_CLEAN_HANDLED_FRAGMENTS: &[&str] = &[
    "/Library/Caches/",
    "/Library/Logs/",
    "/Library/Saved Application State/",
    "/.Trash/",
    "/Library/DiagnosticReports/",
];

/// Regenerable project dependency + build-output directory basenames.
const PROJECT_DEPENDENCY_DIRS: &[&str] = &[
    // JavaScript/Node.
    "node_modules",
    "bower_components",
    ".yarn",
    ".pnpm-store",
    // Python.
    "venv",
    ".venv",
    "virtualenv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".eggs",
    "htmlcov",
    ".ipynb_checkpoints",
    // Ruby.
    "vendor",
    ".bundle",
    // Java/Kotlin/Scala.
    ".gradle",
    "out",
    // Build outputs.
    "build",
    "dist",
    "target",
    ".next",
    ".nuxt",
    ".output",
    ".parcel-cache",
    ".turbo",
    ".vite",
    ".nx",
    "coverage",
    ".coverage",
    ".nyc_output",
    // Frontend framework outputs.
    ".angular",
    ".svelte-kit",
    ".astro",
    ".docusaurus",
    // Apple dev.
    "DerivedData",
    "Pods",
    ".build",
    "Carthage",
    ".dart_tool",
    // Other tools.
    ".terraform",
];

/// Marks paths safe to delete manually (not handled by `mo clean`).
pub fn is_cleanable_dir(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if s.is_empty() {
        return false;
    }
    // Exclude paths mo clean already handles.
    if is_handled_by_mo_clean(&s) {
        return false;
    }
    // CACHEDIR.TAG marks the whole directory tree as regenerable cache.
    if has_valid_cache_dir_tag(path) {
        return true;
    }
    // Project dependencies and build outputs are safe.
    matches!(
        path.file_name().and_then(|b| b.to_str()),
        Some(base) if PROJECT_DEPENDENCY_DIRS.contains(&base)
    )
}

fn is_handled_by_mo_clean(path: &str) -> bool {
    MO_CLEAN_HANDLED_FRAGMENTS.iter().any(|f| path.contains(f))
}

/// True only when `<path>/CACHEDIR.TAG` is a REGULAR file (a symlink is rejected — lstat, no
/// follow) whose leading bytes are the standard cachedir signature.
pub fn has_valid_cache_dir_tag(path: &Path) -> bool {
    let tag = path.join(CACHEDIR_TAG_FILENAME);
    // lstat (symlink_metadata doesn't follow): the tag must be a regular file, not a symlink.
    match fs::symlink_metadata(&tag) {
        Ok(m) if m.file_type().is_file() => {}
        _ => return false,
    }
    let Ok(mut file) = fs::File::open(&tag) else {
        return false;
    };
    let mut buf = vec![0u8; CACHEDIR_TAG_SIGNATURE.len()];
    // A file shorter than the signature (short read) is not a valid tag.
    if file.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == CACHEDIR_TAG_SIGNATURE.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway unique temp dir (zero-dep — no tempfile crate). Caller removes it.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow_cleanable_{}_{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_tag(dir: &Path, content: &str) {
        fs::write(dir.join(CACHEDIR_TAG_FILENAME), content).unwrap();
    }

    #[test]
    fn accepts_valid_cachedir_tag() {
        let dir = scratch("valid");
        write_tag(
            &dir,
            &format!("{CACHEDIR_TAG_SIGNATURE}\n# https://bford.info/cachedir/"),
        );
        assert!(
            is_cleanable_dir(&dir),
            "a valid CACHEDIR.TAG dir is cleanable"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_invalid_cachedir_tag() {
        // Wrong signature and a one-byte-short file both stay non-cleanable.
        for (name, content) in [
            ("wrong", "Signature: invalid".to_string()),
            (
                "short",
                CACHEDIR_TAG_SIGNATURE[..CACHEDIR_TAG_SIGNATURE.len() - 1].to_string(),
            ),
        ] {
            let dir = scratch(name);
            write_tag(&dir, &content);
            assert!(
                !is_cleanable_dir(&dir),
                "invalid tag ({name}) must stay non-cleanable"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_cachedir_tag() {
        let dir = scratch("symlink");
        let real = dir.join("real-tag");
        fs::write(&real, CACHEDIR_TAG_SIGNATURE).unwrap();
        std::os::unix::fs::symlink(&real, dir.join(CACHEDIR_TAG_FILENAME)).unwrap();
        assert!(
            !is_cleanable_dir(&dir),
            "a symlinked CACHEDIR.TAG must stay non-cleanable"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_dependency_basenames_are_cleanable() {
        for base in [
            "node_modules",
            "target",
            "DerivedData",
            ".venv",
            "__pycache__",
        ] {
            let dir = scratch(&base.replace('.', "_"));
            let sub = dir.join(base);
            fs::create_dir_all(&sub).unwrap();
            assert!(is_cleanable_dir(&sub), "{base} should be cleanable");
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn mo_clean_handled_paths_are_excluded() {
        // A node_modules basename that nonetheless sits under a mo-clean path is NOT re-counted.
        assert!(!is_cleanable_dir(Path::new(
            "/Users/x/Library/Caches/node_modules"
        )));
        assert!(!is_cleanable_dir(Path::new("")));
    }
}
