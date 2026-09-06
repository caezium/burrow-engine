//! The disk scanner — the headless core of digger's `cmd/analyze`, reimplemented in Rust.
//!
//! Ported from `cmd/analyze/scanner.go`, but **sequential**: digger's concurrency (semaphores,
//! channels, waitgroups) and its `du`-subprocess / folded-dir / on-disk-cache shortcuts are
//! performance optimizations that don't change the RESULT — a native recursive walk is the ground
//! truth. They can be layered back later without touching this output. What IS preserved (because
//! it changes the numbers): actual-disk-usage sizing (`min(blocks*512, apparent)`, so sparse/cloned
//! files count what they occupy), hardlink dedup (a multiply-linked inode counts once per scan),
//! symlinks counted by their own size and never followed, the skip-dir tables, and the top-20
//! large-file selection that excludes source-code extensions.
//!
//! Unix-only metadata (block count, nlink, inode, atime) is cfg-gated so the crate still builds on
//! the non-unix CI runner; there sizing falls back to apparent length with no hardlink dedup. The
//! real target is macOS, matching digger's `//go:build darwin`.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const MAX_LARGE_FILES: usize = 20;
const LARGE_FILE_MIN_SIZE: i64 = 1 << 20; // 1 MiB

/// Directories never descended into, at any level — VM/container network mounts whose sizes are
/// misleading or whose traversal hangs. From digger's `defaultSkipDirs`.
const DEFAULT_SKIP_DIRS: &[&str] = &[
    "nfs",
    "PHD",
    "Permissions",
    "OrbStack",
    "Colima",
    "Parallels",
    "VMware Fusion",
    "VirtualBox VMs",
    "Rancher Desktop",
    ".lima",
    ".colima",
    ".orbstack",
];

/// Directories skipped ONLY at the filesystem root `/` — system trees a disk-usage view shouldn't
/// walk. From digger's `skipSystemDirs` (its `false` entries — opt, usr — are simply omitted here).
const SKIP_SYSTEM_DIRS: &[&str] = &[
    "dev",
    "tmp",
    "private",
    "cores",
    "net",
    "home",
    "System",
    "sbin",
    "bin",
    "etc",
    "var",
    "Volumes",
    "Network",
    ".vol",
    ".Spotlight-V100",
    ".fseventsd",
    ".DocumentRevisions-V100",
    ".TemporaryItems",
    ".MobileBackups",
];

/// Source-code / project-text extensions excluded from the "large files" list — a 5 MB checked-in
/// `.json` or `.sql` isn't junk to surface for deletion. From digger's `skipExtensions`.
const SKIP_LARGE_FILE_EXTS: &[&str] = &[
    "go", "js", "ts", "tsx", "jsx", "json", "md", "txt", "yml", "yaml", "xml", "html", "css",
    "scss", "sass", "less", "py", "rb", "java", "kt", "rs", "swift", "m", "mm", "c", "cpp", "h",
    "hpp", "cs", "sql", "db", "lock", "gradle", "mjs", "cjs", "coffee", "dart", "svelte", "vue",
    "nim", "hx",
];

/// One immediate child of the scanned directory. `last_access` is the atime (unix secs) for files
/// and symlinks, and `None` for directories — mirroring digger, where dir entries carry a zero time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub path: String,
    pub size: i64,
    pub is_dir: bool,
    pub last_access: Option<i64>,
}

/// One of the largest individual files found anywhere in the subtree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub size: i64,
}

/// A whole scan: immediate children (largest first), the top-N large files (largest first), and
/// subtree totals.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanResult {
    pub entries: Vec<DirEntry>,
    pub large_files: Vec<FileEntry>,
    pub total_size: i64,
    pub total_files: i64,
}

/// Actual disk usage: the smaller of allocated (blocks × 512) and apparent length, so sparse and
/// APFS-cloned files count what they physically occupy. Apparent length off unix.
fn actual_size(meta: &fs::Metadata) -> i64 {
    let apparent = meta.len() as i64;
    #[cfg(unix)]
    let sized = (meta.blocks() as i64 * 512).min(apparent);
    #[cfg(not(unix))]
    let sized = apparent;
    sized
}

/// atime in unix seconds for files/symlinks; `None` off unix.
fn atime(meta: &fs::Metadata) -> Option<i64> {
    #[cfg(unix)]
    {
        Some(meta.atime())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// A file's countable size, deduping hardlinks: a file with >1 link counts fully the first time its
/// inode is seen this scan and 0 thereafter (returns `true` for the dedup). Keyed on
/// (dev-truncated-to-u32, inode), matching digger. No dedup off unix.
fn countable_file_size(meta: &fs::Metadata, seen: &mut HashSet<(u64, u64)>) -> (i64, bool) {
    let size = actual_size(meta);
    #[cfg(unix)]
    {
        if meta.nlink() <= 1 {
            return (size, false);
        }
        let key = (meta.dev() as u32 as u64, meta.ino());
        if !seen.insert(key) {
            return (0, true);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = seen;
    }
    (size, false)
}

fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
}

fn is_source_ext(path: &Path) -> bool {
    matches!(ext_lower(path), Some(e) if SKIP_LARGE_FILE_EXTS.contains(&e.as_str()))
}

/// A large-file candidate: ≥ 1 MiB and not a source/text extension.
fn consider_large(path: &Path, name: &str, size: i64, large: &mut Vec<FileEntry>) {
    if size >= LARGE_FILE_MIN_SIZE && !is_source_ext(path) {
        large.push(FileEntry {
            name: name.to_string(),
            path: path.to_string_lossy().into_owned(),
            size,
        });
    }
}

/// A cumulative progress reading, handed to the `analyze --progress` stream each time a top-level
/// directory of the scan root has been sized. The counters are running totals over the whole scan
/// so far — the shape digger's `progressEvent` emits (`cmd/analyze/progress.go`) and the app's
/// `AnalyzeProgressEvent.parse` reads (`files`, `dirs`, `bytes`, `path`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    /// The directory that just finished.
    pub path: String,
    /// Files counted so far.
    pub files: i64,
    /// Directories entered so far (including the one that just finished).
    pub dirs: i64,
    /// Bytes accounted so far.
    pub bytes: i64,
}

/// Recursively size a subtree: sum countable file sizes (hardlink-deduped via the shared `seen`
/// set), skip `DEFAULT_SKIP_DIRS`, count symlinks by their own size without following, and feed
/// large-file candidates. Returns (bytes, file_count, dir_count) — `dir_count` includes `dir`
/// itself. Unreadable dirs contribute nothing.
fn size_subtree(
    dir: &Path,
    seen: &mut HashSet<(u64, u64)>,
    large: &mut Vec<FileEntry>,
) -> (i64, i64, i64) {
    let mut size = 0i64;
    let mut files = 0i64;
    let mut dirs = 1i64;
    let Ok(rd) = fs::read_dir(dir) else {
        return (0, 0, dirs);
    };
    for entry in rd.flatten() {
        let full = entry.path();
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        let ft = meta.file_type();
        if ft.is_symlink() {
            size += actual_size(&meta); // count the link, never follow
            continue;
        }
        if ft.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if DEFAULT_SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            let (s, f, d) = size_subtree(&full, seen, large);
            size += s;
            files += f;
            dirs += d;
            continue;
        }
        let (s, _) = countable_file_size(&meta, seen);
        size += s;
        files += 1;
        let name = entry.file_name().to_string_lossy().into_owned();
        consider_large(&full, &name, s, large);
    }
    (size, files, dirs)
}

/// Scan a directory's immediate children — each subdir sized recursively — plus the subtree's
/// top-20 large files and totals. Entries and large files come back largest-first.
pub fn scan(root: &Path) -> std::io::Result<ScanResult> {
    scan_with(root, |_| {})
}

/// [`scan`] with a progress hook: `progress` is called once per top-level directory of `root` as
/// its subtree finishes, with the running totals (see [`ScanProgress`]). The result is identical
/// to [`scan`]'s — the hook observes, it never changes what is counted.
pub fn scan_with(
    root: &Path,
    mut progress: impl FnMut(&ScanProgress),
) -> std::io::Result<ScanResult> {
    let is_root = root == Path::new("/");
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut entries: Vec<DirEntry> = Vec::new();
    let mut large: Vec<FileEntry> = Vec::new();
    let mut total: i64 = 0;
    let mut total_files: i64 = 0;
    let mut total_dirs: i64 = 0;

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let full = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        let ft = meta.file_type();
        let path_str = full.to_string_lossy().into_owned();

        if ft.is_symlink() {
            // Count the link's own size only; mark the name and reflect the target's kind, but
            // never follow it into the totals.
            let size = actual_size(&meta);
            total += size;
            let is_dir = fs::metadata(&full).map(|m| m.is_dir()).unwrap_or(false);
            entries.push(DirEntry {
                name: format!("{name} →"),
                path: path_str,
                size,
                is_dir,
                last_access: atime(&meta),
            });
            continue;
        }

        if ft.is_dir() {
            if DEFAULT_SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            if is_root && SKIP_SYSTEM_DIRS.contains(&name.as_str()) {
                continue;
            }
            let (size, files, dirs) = size_subtree(&full, &mut seen, &mut large);
            total += size;
            total_files += files;
            total_dirs += dirs;
            progress(&ScanProgress {
                path: path_str.clone(),
                files: total_files,
                dirs: total_dirs,
                bytes: total,
            });
            entries.push(DirEntry {
                name,
                path: path_str,
                size,
                is_dir: true,
                last_access: None,
            });
            continue;
        }

        // A regular file directly under root.
        let (size, _) = countable_file_size(&meta, &mut seen);
        total += size;
        total_files += 1;
        consider_large(&full, &name, size, &mut large);
        entries.push(DirEntry {
            name,
            path: path_str,
            size,
            is_dir: false,
            last_access: atime(&meta),
        });
    }

    // Largest first (stable, so ties keep readdir order — matching digger's stable sort).
    entries.sort_by_key(|e| std::cmp::Reverse(e.size));
    large.sort_by_key(|f| std::cmp::Reverse(f.size));
    large.truncate(MAX_LARGE_FILES);

    Ok(ScanResult {
        entries,
        large_files: large,
        total_size: total,
        total_files,
    })
}

/// Total actual-disk-usage of a whole subtree (the recursive size of `path` itself), with the same
/// sizing/dedup/skip semantics as [`scan`]. digger's `measureOverviewSize` — used to size the
/// insight entries. A fresh dedup set per call (each measurement is independent).
pub fn dir_size(path: &Path) -> i64 {
    let mut seen = HashSet::new();
    let mut large = Vec::new(); // discarded; dir_size only wants the byte total
    size_subtree(path, &mut seen, &mut large).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow_scan_{}_{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: usize) {
        fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn sizes_entries_and_sorts_largest_first() {
        let root = scratch("basic");
        write(&root.join("small.bin"), 100);
        let big = root.join("big");
        fs::create_dir_all(&big).unwrap();
        write(&big.join("a"), 5000);
        write(&big.join("b"), 3000);

        let r = scan(&root).unwrap();
        // Two immediate children: the "big" dir (8000) then "small.bin" (100), largest first.
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].name, "big");
        assert!(r.entries[0].is_dir);
        assert_eq!(r.entries[0].size, 8000);
        assert_eq!(r.entries[1].name, "small.bin");
        assert!(!r.entries[1].is_dir);
        assert_eq!(r.entries[1].size, 100);
        assert_eq!(r.total_size, 8100);
        assert_eq!(r.total_files, 3); // a, b, small.bin — dirs aren't files
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn large_files_pick_big_binaries_and_skip_source_and_small() {
        let root = scratch("large");
        write(&root.join("movie.bin"), 2 << 20); // 2 MiB binary -> large
        write(&root.join("data.json"), 3 << 20); // 3 MiB but source-ext -> excluded
        write(&root.join("note.bin"), 1024); // under 1 MiB -> excluded

        let r = scan(&root).unwrap();
        let names: Vec<&str> = r.large_files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["movie.bin"],
            "only the big non-source binary is 'large'"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn default_skip_dirs_are_not_descended() {
        let root = scratch("skip");
        let vm = root.join(".orbstack");
        fs::create_dir_all(&vm).unwrap();
        write(&vm.join("huge.bin"), 9_000_000);
        write(&root.join("keep.bin"), 200);

        let r = scan(&root).unwrap();
        // .orbstack is skipped entirely — not an entry, not in the total.
        assert!(r.entries.iter().all(|e| e.name != ".orbstack"));
        assert_eq!(r.total_size, 200);
        assert_eq!(r.total_files, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_marked_and_not_followed() {
        let root = scratch("symlink");
        let target = root.join("realdir");
        fs::create_dir_all(&target).unwrap();
        write(&target.join("payload.bin"), 4000);
        std::os::unix::fs::symlink(&target, root.join("link")).unwrap();

        let r = scan(&root).unwrap();
        let link = r
            .entries
            .iter()
            .find(|e| e.name.starts_with("link"))
            .unwrap();
        assert_eq!(
            link.name, "link →",
            "symlink entries are marked with an arrow"
        );
        assert!(
            link.size < 4000,
            "the link is counted by its own size, not its target's"
        );
        // The target dir is counted once (via realdir), NOT again through the link.
        assert_eq!(r.total_files, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn hardlinks_are_counted_once() {
        let root = scratch("hardlink");
        let a = root.join("a.bin");
        write(&a, 6000);
        fs::hard_link(&a, root.join("b.bin")).unwrap(); // same inode, 2 links

        let r = scan(&root).unwrap();
        // Both entries appear, but the shared inode's bytes are counted once in the total.
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.total_size, 6000, "hardlinked bytes count once");
        assert_eq!(r.total_files, 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_dir_scans_clean() {
        let root = scratch("empty");
        let r = scan(&root).unwrap();
        assert_eq!(r, ScanResult::default());
        let _ = fs::remove_dir_all(&root);
    }
}
