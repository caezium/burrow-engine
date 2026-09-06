//! Overview "hidden space" insights — paths that silently accumulate disk usage and deserve a peek
//! (iOS backups, old downloads, dev caches). Ported from digger's `cmd/analyze/insights.go`.
//!
//! Two halves: the KNOWN-hog table + existence filter (`create_insight_entries`), and measuring a
//! hog's size (`measure_insight_size`) — which reuses the ported scanner (`dir_size`) rather than
//! shelling out to `du`, except Old Downloads, which counts only entries older than 90 days. The
//! `insightIcon` helper in the Go file is TUI-only and not ported.

use super::scanner::dir_size;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const OLD_DOWNLOADS_DAYS: u64 = 90;

/// A hidden-space insight: a known accumulator directory that exists on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsightEntry {
    pub name: String,
    pub path: PathBuf,
}

/// The OrbStack data dir, found by matching `~/Library/Group Containers/*dev.orbstack/data` (a
/// zero-dep stand-in for digger's `filepath.Glob`). First match wins.
fn orbstack_data(home: &Path) -> Option<PathBuf> {
    let group_containers = home.join("Library/Group Containers");
    let rd = std::fs::read_dir(&group_containers).ok()?;
    for entry in rd.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .ends_with("dev.orbstack")
        {
            let data = entry.path().join("data");
            if data.is_dir() {
                return Some(data);
            }
        }
    }
    None
}

/// The full known-hog table (name, absolute path) in digger's display order, before existence
/// filtering: iOS backups and old downloads first, then the developer/cache set, then OrbStack.
fn known_insight_paths(home: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut v: Vec<(&'static str, PathBuf)> = vec![
        (
            "iOS Backups",
            home.join("Library/Application Support/MobileSync/Backup"),
        ),
        ("Old Downloads (90d+)", home.join("Downloads")),
        ("System Logs", home.join("Library/Logs")),
        ("Homebrew Cache", home.join("Library/Caches/Homebrew")),
        (
            "Xcode DerivedData",
            home.join("Library/Developer/Xcode/DerivedData"),
        ),
        (
            "Xcode Simulators",
            home.join("Library/Developer/CoreSimulator/Devices"),
        ),
        (
            "Xcode Archives",
            home.join("Library/Developer/Xcode/Archives"),
        ),
        (
            "Spotify Cache",
            home.join("Library/Application Support/Spotify/PersistentCache"),
        ),
        ("JetBrains Cache", home.join("Library/Caches/JetBrains")),
        (
            "Docker Data",
            home.join("Library/Containers/com.docker.docker/Data"),
        ),
        ("pip Cache", home.join("Library/Caches/pip")),
        ("Gradle Cache", home.join(".gradle/caches")),
        ("CocoaPods Cache", home.join("Library/Caches/CocoaPods")),
    ];
    if let Some(orbstack) = orbstack_data(home) {
        v.push(("OrbStack Data", orbstack));
    }
    v
}

/// The insight entries that actually exist (as directories) on this machine, in display order.
pub fn create_insight_entries(home: &Path) -> Vec<InsightEntry> {
    known_insight_paths(home)
        .into_iter()
        .filter(|(_, p)| p.is_dir())
        .map(|(name, path)| InsightEntry {
            name: name.to_string(),
            path,
        })
        .collect()
}

/// Measure a hog's size. Old Downloads is special: only entries not modified within the last 90
/// days count (that folder is legitimate user data, so only the stale part is "reclaimable").
/// Everything else is a full recursive subtree size via the ported scanner.
pub fn measure_insight_size(path: &Path, home: &Path) -> i64 {
    if path == home.join("Downloads") {
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(OLD_DOWNLOADS_DAYS * 86_400))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        return measure_old_entries(path, cutoff);
    }
    dir_size(path)
}

/// Sum the top-level entries of `dir` last modified before `cutoff`, skipping hidden dotfiles.
/// Directories are sized recursively; files count their apparent length (matching digger). Split
/// out with an explicit cutoff so it's testable without waiting 90 days.
fn measure_old_entries(dir: &Path, cutoff: SystemTime) -> i64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0i64;
    for entry in rd.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue; // skip hidden files
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified >= cutoff {
            continue; // recently touched — not "old"
        }
        if meta.is_dir() {
            total += dir_size(&entry.path());
        } else {
            total += meta.len() as i64;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("burrow_insights_{}_{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_existing_dirs_become_insights_in_order() {
        let home = scratch("home");
        // Create two known hogs (out of order relative to the table) + skip the rest.
        fs::create_dir_all(home.join("Library/Caches/Homebrew")).unwrap();
        fs::create_dir_all(home.join("Downloads")).unwrap();

        let insights = create_insight_entries(&home);
        let names: Vec<&str> = insights.iter().map(|i| i.name.as_str()).collect();
        // Table order is preserved: Old Downloads precedes Homebrew Cache.
        assert_eq!(names, vec!["Old Downloads (90d+)", "Homebrew Cache"]);
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn a_file_shadowing_a_hog_path_is_not_an_insight() {
        let home = scratch("file");
        // System Logs exists but as a FILE, not a dir → excluded.
        fs::create_dir_all(home.join("Library")).unwrap();
        fs::write(home.join("Library/Logs"), b"not a dir").unwrap();
        assert!(create_insight_entries(&home).is_empty());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn old_downloads_counts_only_stale_entries() {
        let home = scratch("dl");
        let downloads = home.join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        fs::write(downloads.join("fresh.bin"), vec![b'x'; 5000]).unwrap();
        fs::write(downloads.join("stale.bin"), vec![b'x'; 3000]).unwrap();
        fs::write(downloads.join(".hidden"), vec![b'x'; 9000]).unwrap(); // hidden → skipped

        // Cutoff in the FUTURE so "stale.bin" (mtime now) counts, "fresh.bin" we exclude by hand:
        // instead, set cutoff in the past and assert nothing counts (both are fresh).
        let future = SystemTime::now() + Duration::from_secs(3600);
        let past = SystemTime::now() - Duration::from_secs(3600);
        // Everything is newer than `past` → nothing is "old".
        assert_eq!(measure_old_entries(&downloads, past), 0);
        // Everything is older than `future` → both visible files count, hidden excluded.
        assert_eq!(measure_old_entries(&downloads, future), 8000);
        let _ = fs::remove_dir_all(&home);
    }
}
