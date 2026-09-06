//! App uninstall — find and remove the files an application leaves scattered across `~/Library`.
//! The engine reimplementation of digger's uninstall leftover discovery.
//!
//! Given a bundle id (e.g. `com.foo.Bar`), the standard macOS support locations are constructed and
//! filtered to those that actually exist. Discovery is pure path construction (testable), with
//! existence and sizing the only IO. Removal reuses the clean executor (whitelist re-checked per
//! item), gated behind an explicit `--apply` — the default is a non-destructive listing.
//!
//! [`list`] is the separate read-only half: `uninstall --list`, the app inventory the GUI's
//! Software tab reads. It enumerates and exits, and it is the one command that does NOT emit the
//! Burrow envelope — see that module's docs for why.
//!
//! [`resolve`] is the gate between the two: every argument is resolved against that same inventory
//! before anything is listed or removed, which is what the oracle does and what makes a multi-app
//! request act on every app rather than only the first.
//!
//! [`bundle`] is the OTHER half of a removal — the `.app` itself. It came late, and its module docs
//! explain the four things `lib/uninstall/batch.sh` does with `$app_path` that a from-scratch design
//! would not: the bundle goes first and the leftovers are gated on it succeeding, an already-absent
//! bundle counts as success, Trash-vs-permanent is one switch for both halves, and a Homebrew cask
//! is removed by `brew uninstall --cask --zap` or not at all.

pub mod apply;
pub mod bundle;
pub mod list;
pub mod resolve;

use crate::analyze::scanner::dir_size;
use crate::clean::plan::CleanCandidate;
use std::path::Path;

/// Whether `bundle_id` is reverse-DNS shaped — the port of `mole_is_reverse_dns_bundle_id`
/// (`lib/core/base.sh:513`): non-empty, not the `unknown` placeholder, and matching
/// `^[A-Za-z0-9][-A-Za-z0-9]*(\.[A-Za-z0-9][-A-Za-z0-9]*)+$` — at least two dot-separated labels
/// of ASCII letters, digits and hyphens, each starting with a letter or digit.
///
/// This is the gate in front of every path [`leftover_paths`] builds. An inventory row's bundle id
/// comes from the app's own `Info.plist`, which the engine does not control, and it is interpolated
/// straight into `~/Library/…/<id>`: an id of `..` or `a/../b` would point the sweep outside the
/// directory it names. The shape rule rejects `/`, `..`, whitespace and control characters as a
/// consequence of allowing only the four character classes — there is no denylist to keep current.
pub fn is_reverse_dns_bundle_id(bundle_id: &str) -> bool {
    if bundle_id.is_empty() || bundle_id == list::UNKNOWN_BUNDLE_ID {
        return false;
    }
    let mut labels = bundle_id.split('.');
    let label_ok = |l: &str| {
        let mut chars = l.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    let Some(first) = labels.next() else {
        return false;
    };
    if !label_ok(first) {
        return false;
    }
    let mut rest = 0;
    for l in labels {
        if !label_ok(l) {
            return false;
        }
        rest += 1;
    }
    rest >= 1
}

/// Why leftovers are NOT enumerated for `bundle_id`, or `None` when they may be. The reason is
/// worded for the `warnings` array a caller reads, and names the id so the refusal is attributable.
pub fn leftover_refusal(bundle_id: &str) -> Option<String> {
    if is_reverse_dns_bundle_id(bundle_id) {
        None
    } else {
        Some(format!(
            "bundle id {bundle_id:?} refused: not reverse-DNS shaped, so no ~/Library leftover \
             path is built from it"
        ))
    }
}

/// The standard per-app support locations for a bundle id, under `home`. Pure — no filesystem access.
/// Covers containers, application support, caches, preferences, logs, saved state, HTTP storage,
/// WebKit data, and cookies.
///
/// EMPTY for an id [`is_reverse_dns_bundle_id`] refuses: the id is interpolated into every path
/// below, and this is the one place that decides whether it may be. See [`leftover_refusal`] for
/// the reason a caller can report.
pub fn leftover_paths(home: &str, bundle_id: &str) -> Vec<String> {
    if !is_reverse_dns_bundle_id(bundle_id) {
        return Vec::new();
    }
    let b = bundle_id;
    vec![
        format!("{home}/Library/Containers/{b}"),
        format!("{home}/Library/Application Support/{b}"),
        format!("{home}/Library/Caches/{b}"),
        format!("{home}/Library/Preferences/{b}.plist"),
        format!("{home}/Library/Logs/{b}"),
        format!("{home}/Library/Saved Application State/{b}.savedState"),
        format!("{home}/Library/HTTPStorages/{b}"),
        format!("{home}/Library/WebKit/{b}"),
        format!("{home}/Library/Cookies/{b}.binarycookies"),
    ]
}

/// The leftover files that actually exist for a bundle id, each with its size. Purely reports —
/// deletes nothing (removal is a separate `--apply` step). Uses the label to describe each location.
pub fn find_leftovers(home: &str, bundle_id: &str) -> Vec<CleanCandidate> {
    leftover_paths(home, bundle_id)
        .into_iter()
        .filter_map(|path| {
            let p = Path::new(&path);
            if !p.exists() {
                return None;
            }
            let size = if p.is_dir() {
                dir_size(p) as u64
            } else {
                p.metadata().map(|m| m.len()).unwrap_or(0)
            };
            let label = label_for(&path);
            Some(CleanCandidate { path, label, size })
        })
        .collect()
}

/// A short human label for a leftover path based on which Library subdir it lives in.
fn label_for(path: &str) -> String {
    for (frag, label) in [
        ("/Library/Containers/", "Container"),
        ("/Library/Application Support/", "Application support"),
        ("/Library/Caches/", "Cache"),
        ("/Library/Preferences/", "Preferences"),
        ("/Library/Logs/", "Logs"),
        ("/Library/Saved Application State/", "Saved state"),
        ("/Library/HTTPStorages/", "HTTP storage"),
        ("/Library/WebKit/", "WebKit data"),
        ("/Library/Cookies/", "Cookies"),
    ] {
        if path.contains(frag) {
            return label.to_string();
        }
    }
    "File".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn leftover_paths_cover_the_standard_locations() {
        let paths = leftover_paths("/Users/me", "com.foo.Bar");
        assert!(paths.contains(&"/Users/me/Library/Containers/com.foo.Bar".to_string()));
        assert!(paths.contains(&"/Users/me/Library/Preferences/com.foo.Bar.plist".to_string()));
        assert!(paths.contains(
            &"/Users/me/Library/Saved Application State/com.foo.Bar.savedState".to_string()
        ));
        assert_eq!(paths.len(), 9);
    }

    /// `mole_is_reverse_dns_bundle_id` (`lib/core/base.sh:513`), both halves: the ids the oracle
    /// accepts and the ones it refuses — including every shape that would escape `~/Library/…`.
    #[test]
    fn bundle_ids_are_gated_on_the_oracles_reverse_dns_shape() {
        for ok in ["com.foo.Bar", "org.python.IDLE", "a.b", "io.x-y.z9", "1.2"] {
            assert!(is_reverse_dns_bundle_id(ok), "{ok:?} must be accepted");
            assert!(leftover_refusal(ok).is_none());
        }
        for bad in [
            "",
            "unknown",
            "/",
            "..",
            "a/../b",
            "../com.foo.Bar",
            "com.foo.Bar/..",
            "com foo.Bar",
            "com.foo.Bar\n",
            "com.foo.",
            ".com.foo",
            "com..foo",
            "nodots",
            "com.-foo.bar",
            "com.foo.bär",
        ] {
            assert!(!is_reverse_dns_bundle_id(bad), "{bad:?} must be refused");
            assert!(
                leftover_refusal(bad).is_some_and(|r| r.contains("refused")),
                "{bad:?}"
            );
        }
    }

    /// A refused id produces ZERO paths — never a path with the id spliced into it. This is the
    /// property that matters: the four ids below each named a real location outside
    /// `~/Library/<subdir>/` when interpolated unvalidated.
    #[test]
    fn a_refused_bundle_id_yields_no_leftover_paths_at_all() {
        for bad in ["..", "a/../b", "", "/"] {
            let paths = leftover_paths("/Users/me", bad);
            assert!(paths.is_empty(), "{bad:?} produced {paths:?}");
            assert!(find_leftovers("/Users/me", bad).is_empty(), "{bad:?}");
        }
        // …and an accepted id still yields the full set, with no `..` component anywhere in it.
        let ok = leftover_paths("/Users/me", "com.foo.Bar");
        assert_eq!(ok.len(), 9);
        assert!(ok.iter().all(|p| !p.split('/').any(|c| c == "..")));
    }

    #[test]
    fn label_reflects_the_library_subdir() {
        assert_eq!(label_for("/x/Library/Caches/com.foo.Bar"), "Cache");
        assert_eq!(
            label_for("/x/Library/Preferences/com.foo.Bar.plist"),
            "Preferences"
        );
        assert_eq!(label_for("/x/Library/Containers/com.foo.Bar"), "Container");
    }

    #[test]
    fn find_leftovers_reports_only_existing_paths_with_sizes() {
        let home = std::env::temp_dir().join(format!("burrow_uninstall_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let bundle = "com.foo.Bar";
        // Create two of the nine standard locations.
        let cache = home.join("Library/Caches").join(bundle);
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("blob"), vec![b'x'; 2048]).unwrap();
        fs::create_dir_all(home.join("Library/Preferences")).unwrap();
        fs::write(
            home.join("Library/Preferences")
                .join(format!("{bundle}.plist")),
            b"prefs",
        )
        .unwrap();

        let found = find_leftovers(home.to_str().unwrap(), bundle);
        assert_eq!(found.len(), 2, "only the two existing locations are found");
        assert!(found.iter().any(|c| c.label == "Cache" && c.size >= 2048));
        assert!(found.iter().any(|c| c.label == "Preferences"));
        let _ = fs::remove_dir_all(&home);
    }
}
