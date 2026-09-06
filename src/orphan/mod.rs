//! Orphan / leftover scanner — the engine port of burrow-cli's macOS `orphans` command.
//!
//! Flags files in a caller-given directory that belong to NO installed app. There is no default
//! scan root: the CLI layer must be handed an explicit directory (matching the oracle, which
//! refuses the no-arg form outright — see `cli.rs::orphans`). The matching logic (synthesized
//! clean-room from the app-eraser landscape) is pure and tested; only `enumerate_installed_apps`
//! and the directory walk in `scan` touch the filesystem. Read-only by design: the command lists
//! candidates and never removes anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How strongly a candidate file relates to an installed app. Higher = more related.
///
/// `relatedness` grades a candidate against the inventory with `None`/`Medium`/`Strong`/`Exact`;
/// an UNMATCHED hit is then graded on its own shape (`hit_confidence`) as `Weak` or `Medium` —
/// the two words the `orphans` JSON has always carried (`exact`/`strong` are reserved for
/// inventory-matched relationships, `none` never reaches a hit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    None,
    Weak,
    Medium,
    Strong,
    Exact,
}

impl Confidence {
    /// The word the JSON carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Weak => "weak",
            Confidence::Medium => "medium",
            Confidence::Strong => "strong",
            Confidence::Exact => "exact",
        }
    }

    /// The inverse of [`Confidence::as_str`].
    pub fn parse(word: &str) -> Option<Self> {
        [
            Confidence::None,
            Confidence::Weak,
            Confidence::Medium,
            Confidence::Strong,
            Confidence::Exact,
        ]
        .into_iter()
        .find(|c| c.as_str() == word)
    }
}

/// Collapse a string to its alphanumeric, lowercased identity (the installed-app id form).
pub fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Normalize a candidate filename, dropping volatile tokens first (duplicate counters,
/// long digit runs like dates/versions, and hex runs like UUIDs/hashes) so they don't
/// dilute the match — the app-eraser insight.
pub fn clean_name(raw: &str) -> String {
    let no_counters = remove_paren_counters(raw);
    let lower = no_counters.to_lowercase();
    let mut out = String::new();
    for tok in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.is_empty() {
            continue;
        }
        let all_digits = tok.bytes().all(|b| b.is_ascii_digit());
        let all_hex = tok.bytes().all(|b| b.is_ascii_hexdigit());
        if all_digits {
            continue; // counters / dates / versions are noise for identity matching
        }
        if all_hex && tok.len() >= 12 {
            continue; // UUID chunk / content hash
        }
        out.push_str(tok);
    }
    out
}

fn remove_paren_counters(s: &str) -> String {
    // drop "(<digits>)" runs, e.g. "Slack (2)" -> "Slack "
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > i + 1 && j < bytes.len() && bytes[j] == b')' {
                i = j + 1; // skip "(123)"
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn longest_common_substring_len(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut best = 0;
    for i in 1..=a.len() {
        let mut curr = vec![0usize; b.len() + 1];
        for j in 1..=b.len() {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
                best = best.max(curr[j]);
            }
        }
        prev = curr;
    }
    best
}

/// Fraction of the candidate explained by the best contiguous overlap with `id`.
pub fn coverage_ratio(cand: &str, id: &str) -> f64 {
    let denom = cand.chars().count();
    if denom == 0 {
        return 0.0;
    }
    longest_common_substring_len(cand, id) as f64 / denom as f64
}

/// Best relatedness of a candidate (raw filename) to any installed identifier
/// (pre-normalized via `normalize`).
pub fn relatedness(candidate_raw: &str, installed: &[String]) -> Confidence {
    let cand = clean_name(candidate_raw);
    if cand.len() < 3 {
        return Confidence::None;
    }
    let mut best = Confidence::None;
    for id in installed {
        if id.len() < 3 {
            continue;
        }
        let c = if cand == *id {
            Confidence::Exact
        } else if id.len() >= 5 && cand.contains(id.as_str()) {
            Confidence::Strong
        } else if coverage_ratio(&cand, id) > 0.4 {
            Confidence::Medium
        } else {
            Confidence::None
        };
        best = best.max(c);
        if best == Confidence::Exact {
            break;
        }
    }
    best
}

/// Apple/system files that must never be flagged as orphans.
pub fn is_safelisted(name: &str) -> bool {
    let l = name.to_lowercase();
    l.starts_with("com.apple.")
        || l.starts_with("is.workflow.")
        || l == ".ds_store"
        || l.ends_with(".globalpreferences.plist")
}

/// Whether the name looks like an app-specific artifact (bundle-id-ish: >=3 dot components,
/// after stripping group/systemgroup prefixes). Prevents flagging arbitrary user files.
pub fn looks_like_app_artifact(name: &str) -> bool {
    let base = name
        .strip_prefix("group.")
        .or_else(|| name.strip_prefix("systemgroup."))
        .unwrap_or(name);
    base.split('.').filter(|p| !p.is_empty()).count() >= 3
}

/// A candidate is an orphan iff it looks like an app artifact, is not safelisted, and relates
/// to no installed app.
pub fn is_orphan(candidate_raw: &str, installed: &[String]) -> bool {
    if is_safelisted(candidate_raw) || !looks_like_app_artifact(candidate_raw) {
        return false;
    }
    relatedness(candidate_raw, installed) == Confidence::None
}

/// One orphan candidate: a leftover file with no owning installed app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanHit {
    pub name: String,
    pub path: String,
    pub confidence: Confidence,
    pub evidence: Vec<&'static str>,
    /// Always `false` — burrow-cli's scanner never preselects a hit; carried so a future acting
    /// pane inherits the CLI's judgement instead of inventing its own (OrphansModel.swift's own
    /// doc comment on `OrphanHit.defaultSelected`).
    pub default_selected: bool,
}

/// The confidence grade for an unmatched hit: reverse-domain (bundle-id-shaped) names carry a
/// vendor signature -> "medium"; looser names are only "weak" evidence of an app leftover.
/// (exact/strong are reserved for inventory-matched relationships.)
fn hit_confidence(name: &str) -> Confidence {
    let stem = name.strip_suffix(".savedState").unwrap_or(name);
    if stem.split('.').filter(|t| !t.is_empty()).count() >= 3 {
        Confidence::Medium
    } else {
        Confidence::Weak
    }
}

/// Volatile-roots policy: orphans must NEVER flag anything under Preferences, Keychains, Mail,
/// or Containers — deleting there loses settings, credentials, mail, or sandboxed app data even
/// when the owning app looks gone. Component-wise, so `PreferencesBackup` is not protected.
const PROTECTED_ROOTS: [&str; 4] = ["Preferences", "Keychains", "Mail", "Containers"];

pub fn is_protected_location(path: &Path) -> bool {
    path.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|s| PROTECTED_ROOTS.contains(&s))
    })
}

/// Resolve `root` to a canonical (absolute, symlink-resolved) path before it is used for
/// anything security-relevant. `is_protected_location` only ever inspects the literal path
/// components it is given, so a RELATIVE path (`orphans .` run from inside
/// `~/Library/Preferences`) or a SYMLINK whose target is a protected root would otherwise defeat
/// it silently — the component "Preferences" is only visible once the path is resolved.
/// AUTHORIZED DEVIATION (RULEBOOK §4): the shipping oracle has this same gap (it never
/// canonicalizes either), but the pre-fix engine ignored its scan-root argument entirely and only
/// ever swept hardcoded absolute paths, so the gap was unreachable; honoring the argument is what
/// makes it reachable, and presenting live preference files as medium-confidence abandoned
/// leftovers is a data-loss vector worth diverging from the oracle for. Falls back to the given
/// root unchanged when canonicalization fails (e.g. it doesn't exist), so a missing directory
/// still degrades to an empty scan rather than turning into an error.
pub fn canonical_root(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// Scan a single directory (non-recursive) for orphan candidates given the installed-app
/// identifier inventory. Every hit's reported `path` stays rooted at `root` EXACTLY as given —
/// parity with the oracle, which never canonicalizes either, and load-bearing: the CLI echoes
/// `root` back verbatim as `roots`, and a canonicalized echo would falsely read as "the engine
/// scanned somewhere else" on any machine where the given path crosses a symlink (e.g. macOS's
/// `/tmp` -> `/private/tmp`) even though it scanned the exact right location.
///
/// The protected-roots safety decision below is the one exception: it is evaluated against the
/// CANONICAL (absolute, symlink-resolved) form of each hit, specifically so that form is never
/// leaked into a reported path — only used to decide whether a hit survives at all.
pub fn scan(root: &Path, installed: &[String]) -> Vec<OrphanHit> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let canonical = canonical_root(root);
    let mut hits = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if is_orphan(&name, installed) {
            let confidence = hit_confidence(&name);
            hits.push(OrphanHit {
                name,
                path: e.path().to_string_lossy().into_owned(),
                confidence,
                evidence: vec!["app-artifact-shaped", "not-matched-to-installed-inventory"],
                default_selected: false,
            });
        }
    }
    // One chokepoint for the volatile-roots policy: whatever the scan found, nothing under a
    // protected root leaves — checked against `canonical.join(name)`, so a relative root
    // (`orphans .` run from inside `~/Library/Preferences`) or a symlink into a protected root
    // cannot defeat this by hiding the component from view. The reported `path` above is
    // untouched by this — only whether a hit survives depends on the canonical form.
    hits.retain(|h| !is_protected_location(&canonical.join(&h.name)));
    hits.sort_by(|a, b| a.name.cmp(&b.name));
    hits
}

/// One installed-app record from the inventory. Mirrors burrow-cli's
/// `InstalledApp::synthetic` for the macOS `applications_dir` source — the CSV/Windows-registry
/// sources in burrow-cli's fuller cross-platform `orphan.rs` are out of scope for this port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    /// Inventory provenance label, e.g. `"applications_dir"` — golden's `inventory_sources`
    /// groups by this.
    pub source: &'static str,
    pub display_name: String,
    /// `normalize(display_name)`, guaranteed >=3 chars (shorter names are filtered out before
    /// construction, matching `InstalledApp::synthetic`'s guard).
    pub id: String,
}

/// Enumerate `.app` bundles directly under each of `roots`, reduced to `InstalledApp` records.
/// Sorted and deduped BY DISPLAY NAME (not by normalized id) — this is what the original counts
/// as "installed apps", so two differently-named bundles that happen to normalize to the same id
/// still count as two. Split out from `enumerate_installed_apps` so the enumeration/dedup logic
/// is testable against a fixture directory instead of the real `/Applications`.
pub fn enumerate_installed_apps_at(roots: &[PathBuf]) -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    for root in roots {
        if let Ok(entries) = std::fs::read_dir(root) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if let Some(app) = n.strip_suffix(".app") {
                    let display_name = app.trim().to_string();
                    let id = normalize(&display_name);
                    if id.len() >= 3 {
                        apps.push(InstalledApp {
                            source: "applications_dir",
                            display_name,
                            id,
                        });
                    }
                }
            }
        }
    }
    apps.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    apps.dedup_by(|a, b| a.display_name == b.display_name);
    apps
}

/// Build an installed-app inventory from a CLI-supplied CSV of names — the `--installed`
/// override (`burrow-cli/src/main.rs:348-353` -> `orphan::installed_from_cli_csv`,
/// `orphan.rs:746-754`). Each token becomes a synthetic `InstalledApp` with `source: "cli"`.
///
/// Deliberately dedups BY ID here, not by display name — the ONE place this port's simplified
/// `InstalledApp` needs two different dedup keys for two different callers, matching the
/// original exactly: `enumerate_installed_apps` dedups `apps.sort_by(display_name)` +
/// `dedup_by(display_name)`, but `installed_from_cli_csv` dedups `dedup_by(identifiers)` — and
/// for a CLI-synthetic entry (no publisher/install_location) `identifiers` is always the
/// single-element `[id]`, so "dedup by identifiers" collapses to "dedup by id" once simplified to
/// this port's scalar `id` field. An empty CSV (`--installed ""`) legitimately produces an empty
/// Vec — the caller explicitly said "treat nothing as installed", which is different from, and
/// must not be confused with, `enumerate_installed_apps_checked` failing to enumerate at all.
pub fn installed_from_cli_csv(csv: &str) -> Vec<InstalledApp> {
    let mut apps: Vec<InstalledApp> = csv
        .split(',')
        .filter_map(|s| {
            let display_name = s.trim().to_string();
            let id = normalize(&display_name);
            if id.len() >= 3 {
                Some(InstalledApp {
                    source: "cli",
                    display_name,
                    id,
                })
            } else {
                None
            }
        })
        .collect();
    apps.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    apps.dedup_by(|a, b| a.id == b.id);
    apps
}

/// Enumerate installed apps from `primary` (a HARD requirement — see below) plus `extra_roots`
/// (each read best-effort, matching `enumerate_installed_apps_at`: a missing/unreadable extra
/// root just contributes zero apps). Split out from `enumerate_installed_apps` so the failure
/// path is testable without depending on the real `/Applications`.
///
/// AUTHORIZED DEVIATION (RULEBOOK §4): a failed read of `primary` is an ERROR, not an empty
/// inventory. Silently treating an unreadable `primary` as "zero apps" — which is what
/// `enumerate_installed_apps_at` does, correctly, for the OPTIONAL extra roots — would make
/// `is_orphan` treat every app-shaped file as unmatched, including apps that are genuinely
/// installed and running, and there is no way for a caller to tell "nothing is installed" apart
/// from "the probe is broken" once both collapse to the same empty Vec. An inventory that is
/// empty because the CALLER said so (`--installed ""`) is a different, legitimate case — that
/// goes through `installed_from_cli_csv`, never through here.
pub fn enumerate_installed_apps_checked(
    primary: &Path,
    extra_roots: &[PathBuf],
) -> Result<Vec<InstalledApp>, String> {
    if let Err(e) = std::fs::read_dir(primary) {
        return Err(format!("cannot read {}: {e}", primary.display()));
    }
    let mut roots = vec![primary.to_path_buf()];
    roots.extend_from_slice(extra_roots);
    Ok(enumerate_installed_apps_at(&roots))
}

/// Enumerate installed apps from the default macOS inventory roots (`/Applications` is the hard
/// requirement, `~/Applications` is optional — see `enumerate_installed_apps_checked`). Errors
/// off macOS: this port carries no Windows registry source, so there is no way to answer "what
/// apps are installed" there at all, and that is an error, not zero apps (see
/// `enumerate_installed_apps_checked`'s doc comment for why the distinction matters).
pub fn enumerate_installed_apps() -> Result<Vec<InstalledApp>, String> {
    if !cfg!(target_os = "macos") {
        return Err(
            "orphans needs macOS (no installed-app inventory source on this platform)".to_string(),
        );
    }
    // Degrades: `/Applications` is scanned either way, so an unknown home costs the per-user
    // half of the inventory rather than producing a fabricated root.
    let extra = crate::platform::home_dir()
        .map(|home| vec![PathBuf::from(home).join("Applications")])
        .unwrap_or_default();
    enumerate_installed_apps_checked(Path::new("/Applications"), &extra)
}

/// The matching identifiers `scan`/`is_orphan` compare candidates against: every installed
/// app's normalized id, sorted and deduped — a SECOND, coarser dedup pass than
/// `enumerate_installed_apps`'s (by id, not display name), matching burrow-cli's
/// `installed_identifiers`. Two apps with different display names that normalize to the same id
/// still count as two installed apps but contribute one matching identifier.
pub fn installed_identifiers(apps: &[InstalledApp]) -> Vec<String> {
    let mut ids: Vec<String> = apps.iter().map(|a| a.id.clone()).collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Count installed apps by inventory source — the golden's `inventory_sources`
/// (`{"applications_dir": 109}`). `OrphansModel`'s header comment says this field may drift
/// upstream without breaking the GUI, but it costs nothing to keep accurate.
pub fn inventory_source_counts(apps: &[InstalledApp]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for app in apps {
        *counts.entry(app.source.to_string()).or_insert(0) += 1;
    }
    counts
}

/// Serialize a full orphans report to JSON (zero-dep):
/// `{count,installed_count,inventory_sources:{…},orphans:[{confidence,default_selected,evidence:[…],name,path}],roots:[…]}`.
/// `installed_count` is the denominator that makes "orphan" meaningful, so it is always the real
/// `enumerate_installed_apps().len()` — never a placeholder or the length of `orphans`/`roots`.
pub fn to_json(
    hits: &[OrphanHit],
    roots: &[String],
    installed_count: usize,
    inventory_sources: &BTreeMap<String, usize>,
) -> String {
    use crate::json::escape as esc;
    let items = hits
        .iter()
        .map(|h| {
            let ev = h
                .evidence
                .iter()
                .map(|e| esc(e))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"confidence\":{},\"default_selected\":{},\"evidence\":[{}],\"name\":{},\"path\":{}}}",
                esc(h.confidence.as_str()),
                h.default_selected,
                ev,
                esc(&h.name),
                esc(&h.path)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let roots_json = roots.iter().map(|r| esc(r)).collect::<Vec<_>>().join(",");
    // BTreeMap iterates in key order, so this is stable across runs.
    let inv_json = inventory_sources
        .iter()
        .map(|(k, v)| format!("{}:{}", esc(k), v))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"count\":{},\"installed_count\":{},\"inventory_sources\":{{{}}},\"orphans\":[{}],\"roots\":[{}]}}",
        hits.len(),
        installed_count,
        inv_json,
        items,
        roots_json
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| normalize(s)).collect()
    }

    #[test]
    fn normalize_strips_punctuation() {
        assert_eq!(normalize("Com.Google.Chrome!"), "comgooglechrome");
    }

    #[test]
    fn clean_name_drops_counters_dates_uuids() {
        assert_eq!(clean_name("Slack (2)"), "slack");
        assert_eq!(clean_name("com.foo.bar-2024-01-01"), "comfoobar");
        assert_eq!(
            clean_name("cache-0123456789abcdef0123456789abcdef"),
            "cache"
        );
    }

    #[test]
    fn exact_and_strong_matches_are_related() {
        let installed = ids(&["com.google.Chrome"]);
        assert_eq!(
            relatedness("com.google.Chrome.savedState", &installed),
            Confidence::Strong
        );
        assert_eq!(
            relatedness("com.google.Chrome", &installed),
            Confidence::Exact
        );
    }

    #[test]
    fn coverage_ratio_partial() {
        // "comslack" shares "slack" (5) with "slack" -> 5/8
        assert!((coverage_ratio("comslack", "slack") - 0.625).abs() < 1e-9);
    }

    #[test]
    fn unrelated_bundle_is_orphan() {
        let installed = ids(&["com.google.Chrome"]);
        assert!(is_orphan("com.deadvendor.oldapp.savedState", &installed));
    }

    #[test]
    fn apple_files_never_orphan() {
        let installed = ids(&["com.google.Chrome"]);
        assert!(!is_orphan("com.apple.Safari.savedState", &installed));
        assert!(!is_orphan(".DS_Store", &installed));
    }

    #[test]
    fn non_bundle_files_never_orphan() {
        let installed = ids(&["com.google.Chrome"]);
        assert!(!is_orphan("my-notes.txt", &installed));
        assert!(!is_orphan("Screenshot.png", &installed));
    }

    #[test]
    fn installed_app_files_not_orphan() {
        let installed = ids(&["com.google.Chrome", "com.tinyspeck.slackmacgap"]);
        assert!(!is_orphan("com.tinyspeck.slackmacgap.helper", &installed));
    }

    #[test]
    fn hit_confidence_grades_bundle_id_shape() {
        assert_eq!(
            hit_confidence("com.deadvendor.oldapp.savedState"),
            Confidence::Medium
        );
        assert_eq!(hit_confidence("org.foo.bar"), Confidence::Medium);
        assert_eq!(hit_confidence("OldAppLeftovers"), Confidence::Weak);
        assert_eq!(hit_confidence("cache.db"), Confidence::Weak);
    }

    #[test]
    fn protected_locations_match_by_whole_component() {
        for p in [
            "/Users/x/Library/Preferences/com.foo.plist",
            "/Users/x/Library/Keychains/login.keychain-db",
            "/Users/x/Library/Mail/V10/whatever",
            "/Users/x/Library/Containers/com.foo.app",
        ] {
            assert!(is_protected_location(Path::new(p)), "{p} must be protected");
        }
        for p in [
            "/Users/x/Library/Caches/com.foo",
            "/Users/x/Library/PreferencesBackup/f",
            "/Users/x/Library/Saved Application State/com.foo.savedState",
        ] {
            assert!(
                !is_protected_location(Path::new(p)),
                "{p} must NOT be protected"
            );
        }
    }

    #[test]
    fn scan_flags_unmatched_bundle_and_skips_matched() {
        let dir = std::env::temp_dir().join(format!("burrow_orph_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("com.deadvendor.oldapp.savedState"), "x").unwrap();
        std::fs::write(dir.join("com.google.Chrome.savedState"), "x").unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        let hits = scan(&dir, &ids(&["com.google.Chrome"]));
        assert_eq!(hits.len(), 1, "only the dead vendor is an orphan: {hits:?}");
        assert_eq!(hits[0].name, "com.deadvendor.oldapp.savedState");
        assert_eq!(hits[0].confidence, Confidence::Medium);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_never_flags_inside_protected_roots() {
        let dir = std::env::temp_dir().join(format!("burrow_prot_{}", std::process::id()));
        let prefs = dir.join("Preferences");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&prefs).unwrap();
        std::fs::write(prefs.join("com.deadvendor.oldapp.plist"), "x").unwrap();
        let hits = scan(&prefs, &[]);
        assert!(
            hits.is_empty(),
            "Preferences must never be flagged: {hits:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Leak an owned `String` to `&'static str` — legitimate in test-only code that runs once:
    /// lets a test build `OrphanHit`s (whose `confidence`/`evidence` are `&'static str`, matching
    /// the rest of the module) from values read at run time, instead of hardcoding the known set
    /// of confidence/evidence tags the way an earlier version of this test did.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    #[test]
    fn to_json_shape_is_well_typed_for_synthetic_input() {
        // Edge cases the pinned fixture doesn't exercise (a single hand-built hit, and the empty
        // case). Checked via the engine's own JSON reader (`crate::json::Json`) and typed
        // accessors — never a hand-typed JSON string literal (RULEBOOK §6).
        let mut inv = BTreeMap::new();
        inv.insert("applications_dir".to_string(), 5usize);
        let hits = vec![OrphanHit {
            name: "com.foo.bar".into(),
            path: "/tmp/com.foo.bar".into(),
            confidence: Confidence::Medium,
            evidence: vec!["app-artifact-shaped"],
            default_selected: false,
        }];
        let out = to_json(&hits, &["/tmp/scan".to_string()], 5, &inv);
        let parsed = crate::json::Json::parse(&out).expect("to_json must emit valid JSON");

        assert_eq!(parsed.get("count").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            parsed.get("installed_count").and_then(|v| v.as_u64()),
            Some(5)
        );
        assert_eq!(
            parsed
                .get("inventory_sources")
                .and_then(|v| v.get("applications_dir"))
                .and_then(|v| v.as_u64()),
            Some(5)
        );
        assert_eq!(
            parsed
                .get("roots")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );
        assert_eq!(
            parsed
                .get("roots")
                .and_then(|v| v.at(0))
                .and_then(|v| v.as_str()),
            Some("/tmp/scan")
        );
        let hit0 = parsed
            .get("orphans")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .expect("one hit");
        assert_eq!(
            hit0.get("name").and_then(|v| v.as_str()),
            Some("com.foo.bar")
        );
        assert_eq!(
            hit0.get("path").and_then(|v| v.as_str()),
            Some("/tmp/com.foo.bar")
        );
        assert_eq!(
            hit0.get("confidence").and_then(|v| v.as_str()),
            Some("medium")
        );
        assert_eq!(
            hit0.get("default_selected").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            hit0.get("evidence")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );

        // Zero hits must still be a well-formed, empty (not omitted) `orphans` array.
        let empty_out = to_json(&[], &[], 0, &BTreeMap::new());
        let empty = crate::json::Json::parse(&empty_out).expect("to_json must emit valid JSON");
        assert_eq!(
            empty
                .get("orphans")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(0)
        );
        assert_eq!(empty.get("count").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            empty
                .get("roots")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(0)
        );
    }

    /// The contract fixture bundled for standalone CI. `scripts/check_fixtures.py` verifies
    /// the approved public copy; `FIXTURE_PROVENANCE.md` records its captured authority.
    ///
    /// This test LOADS that file at run time and derives every input to `to_json` from it — it
    /// does not transcribe values. A prior version of this test (`to_json_matches_the_golden_…`)
    /// asserted `count: 0, orphans: []` transcribed from the FIRST capture (an empty fixture) and
    /// could not go red when the golden was re-captured with three real rows; it had to be
    /// hand-edited. Loading the file is the fix (RULEBOOK §3e / check_tests.py).
    #[test]
    fn to_json_round_trips_the_golden_loaded_from_disk() {
        let golden_text = include_str!("orphans.golden.json");
        let golden =
            crate::json::Json::parse(golden_text).expect("vendored golden must be valid JSON");

        let roots: Vec<String> = golden
            .get("roots")
            .and_then(|v| v.as_array())
            .expect("golden.roots must be an array")
            .iter()
            .map(|v| v.as_str().expect("roots[*] must be a string").to_string())
            .collect();
        let installed_count = golden
            .get("installed_count")
            .and_then(|v| v.as_u64())
            .expect("golden.installed_count must be a number")
            as usize;
        let inventory_sources: BTreeMap<String, usize> = match golden.get("inventory_sources") {
            Some(crate::json::Json::Object(m)) => m
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_u64()
                            .unwrap_or_else(|| panic!("inventory_sources.{k} must be a number"))
                            as usize,
                    )
                })
                .collect(),
            _ => panic!("golden.inventory_sources must be an object"),
        };
        let hits: Vec<OrphanHit> = golden
            .get("orphans")
            .and_then(|v| v.as_array())
            .expect("golden.orphans must be an array")
            .iter()
            .map(|h| OrphanHit {
                name: h
                    .get("name")
                    .and_then(|v| v.as_str())
                    .expect("hit.name")
                    .to_string(),
                path: h
                    .get("path")
                    .and_then(|v| v.as_str())
                    .expect("hit.path")
                    .to_string(),
                confidence: Confidence::parse(
                    h.get("confidence")
                        .and_then(|v| v.as_str())
                        .expect("hit.confidence"),
                )
                .expect("hit.confidence is a known grade"),
                evidence: h
                    .get("evidence")
                    .and_then(|v| v.as_array())
                    .expect("hit.evidence")
                    .iter()
                    .map(|e| {
                        leak(
                            e.as_str()
                                .expect("evidence entry must be a string")
                                .to_string(),
                        )
                    })
                    .collect(),
                default_selected: h
                    .get("default_selected")
                    .and_then(|v| v.as_bool())
                    .expect("hit.default_selected"),
            })
            .collect();

        // Golden has real rows (not the blind empty-fixture capture) — otherwise this test would
        // pass even if `to_json` emitted nothing, same failure mode the empty golden had.
        assert!(
            !hits.is_empty(),
            "golden.orphans is empty — this test can no longer prove anything; re-capture with a \
             fixture that has real hits before trusting this comparison"
        );

        let engine_out = to_json(&hits, &roots, installed_count, &inventory_sources);
        let engine_parsed =
            crate::json::Json::parse(&engine_out).expect("to_json must produce valid JSON");

        assert_eq!(
            engine_parsed, golden,
            "to_json's output must be structurally identical to the golden it was built from \
             (engine: {engine_out}, golden: {golden_text})"
        );
    }

    fn fake_app(root: &Path, display_name: &str) {
        std::fs::create_dir_all(root.join(format!("{display_name}.app"))).unwrap();
    }

    #[test]
    fn enumerate_installed_apps_dedups_by_display_name_not_by_normalized_id() {
        // Mirrors burrow-cli's InstalledApp inventory-count semantics: the dedup key for
        // COUNTING installed apps is the display name, not the coarser normalized id. Two apps
        // with different display names that happen to normalize to the same id ("My-App" and
        // "MyApp" both -> "myapp") must both survive as separate installed apps; only an exact
        // display-name duplicate across roots (e.g. the same app under /Applications and
        // ~/Applications) collapses.
        let base = std::env::temp_dir().join(format!("burrow_orph_inv_{}", std::process::id()));
        let root_a = base.join("Applications");
        let root_b = base.join("HomeApplications");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        fake_app(&root_a, "My-App");
        fake_app(&root_a, "Dup");
        fake_app(&root_b, "MyApp");
        fake_app(&root_b, "Dup");

        let apps = enumerate_installed_apps_at(&[root_a, root_b]);
        let mut names: Vec<&str> = apps.iter().map(|a| a.display_name.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            vec!["Dup", "My-App", "MyApp"],
            "exact-name duplicate (Dup) collapses to one; same-id different-name apps (My-App/MyApp) both survive: {names:?}"
        );
        assert_eq!(apps.len(), 3, "installed_count must be 3, not 2: {apps:?}");
        assert!(apps.iter().all(|a| a.source == "applications_dir"));

        // The matching-identifier list is deduped a second time, coarser, BY id — so My-App and
        // MyApp (same normalized id) collapse to one matcher even though they counted as two
        // installed apps above.
        let ids = installed_identifiers(&apps);
        assert_eq!(
            ids,
            vec!["dup".to_string(), "myapp".to_string()],
            "identifiers must dedup by id even though the app count does not: {ids:?}"
        );

        let inv = inventory_source_counts(&apps);
        assert_eq!(inv.get("applications_dir"), Some(&3));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn enumerate_installed_apps_at_filters_short_ids() {
        let dir = std::env::temp_dir().join(format!("burrow_orph_short_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        fake_app(&dir, "AB"); // normalizes to "ab", 2 chars -> filtered out
        fake_app(&dir, "ABC"); // normalizes to "abc", 3 chars -> kept
        let apps = enumerate_installed_apps_at(std::slice::from_ref(&dir));
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].display_name, "ABC");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- `--installed` CSV override (burrow-cli's `installed_from_cli_csv`) ----

    #[test]
    fn installed_from_cli_csv_builds_a_cli_sourced_inventory() {
        let apps = installed_from_cli_csv("Ghostapp,Acme");
        assert_eq!(apps.len(), 2, "{apps:?}");
        assert!(apps.iter().all(|a| a.source == "cli"), "{apps:?}");
        let mut names: Vec<&str> = apps.iter().map(|a| a.display_name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Acme", "Ghostapp"]);

        let inv = inventory_source_counts(&apps);
        assert_eq!(inv.get("cli"), Some(&2));
        assert_eq!(
            inv.len(),
            1,
            "must not also carry an applications_dir entry: {inv:?}"
        );
    }

    #[test]
    fn installed_from_cli_csv_trims_whitespace_and_drops_short_tokens() {
        let apps = installed_from_cli_csv(" Foo , ab , Bar ");
        // "ab" normalizes to "ab" (2 chars) -> filtered out, matching InstalledApp::synthetic.
        let mut names: Vec<&str> = apps.iter().map(|a| a.display_name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["Bar", "Foo"], "{apps:?}");
    }

    #[test]
    fn installed_from_cli_csv_empty_string_is_a_legitimate_empty_inventory() {
        // "--installed ''" is the caller explicitly saying "treat nothing as installed" — the
        // oracle honours it, so this must return an empty Vec cleanly, not panic or error.
        let apps = installed_from_cli_csv("");
        assert!(apps.is_empty(), "{apps:?}");
    }

    #[test]
    fn installed_from_cli_csv_dedups_by_id_not_display_name() {
        // Distinct from enumerate_installed_apps_at's dedup key (display name) — this mirrors
        // burrow-cli's installed_from_cli_csv, which dedups by `identifiers` (here: `id`).
        // "My-App" and "MyApp" both normalize to "myapp" and must collapse to ONE entry, unlike
        // the applications_dir path where they'd both survive.
        let apps = installed_from_cli_csv("My-App,MyApp");
        assert_eq!(apps.len(), 1, "{apps:?}");
    }

    #[test]
    fn installed_csv_inventory_changes_which_files_are_orphans() {
        // End-to-end proof that the CSV inventory actually drives matching (not just that the
        // struct gets built): "Ghostapp" is strong-tier related to "com.example.ghostapp" (its
        // normalized id, 8 chars, is a literal substring of the cleaned candidate), so that file
        // stops being an orphan once "Ghostapp" is in the inventory; a file unrelated to anything
        // in the CSV remains an orphan.
        let dir = std::env::temp_dir().join(format!("burrow_orph_csv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("com.example.ghostapp"), "x").unwrap();
        std::fs::write(dir.join("org.nonexistent.vendor.tool"), "x").unwrap();

        let apps = installed_from_cli_csv("Ghostapp,Acme");
        let installed = installed_identifiers(&apps);
        let hits = scan(&dir, &installed);

        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].name, "org.nonexistent.vendor.tool");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- `enumerate_installed_apps_checked` (distinguishing "caller said empty" from "the
    // inventory probe failed") ----

    #[test]
    fn enumerate_installed_apps_checked_errors_when_the_primary_root_is_unreadable() {
        let missing = std::env::temp_dir().join(format!(
            "burrow_orph_primary_missing_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        let result = enumerate_installed_apps_checked(&missing, &[]);
        assert!(
            result.is_err(),
            "an unreadable PRIMARY root must be an error, not a silent empty inventory: {result:?}"
        );
    }

    #[test]
    fn enumerate_installed_apps_checked_tolerates_a_missing_extra_root() {
        // ~/Applications is optional and commonly absent — only the primary root is load-bearing.
        let primary =
            std::env::temp_dir().join(format!("burrow_orph_primary_ok_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&primary);
        std::fs::create_dir_all(&primary).unwrap();
        fake_app(&primary, "RealApp");
        let missing_extra =
            std::env::temp_dir().join(format!("burrow_orph_extra_missing_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing_extra);

        let apps = enumerate_installed_apps_checked(&primary, &[missing_extra])
            .expect("a missing EXTRA root must not error");
        assert_eq!(apps.len(), 1, "{apps:?}");
        assert_eq!(apps[0].display_name, "RealApp");

        let _ = std::fs::remove_dir_all(&primary);
    }

    // ---- canonicalization defeats the protected-root bypass (AUTHORIZED DEVIATION) ----

    #[test]
    fn scan_canonicalizes_a_relative_root_before_checking_protected_status() {
        // `orphans .` run from inside a directory whose OWN name is a protected component
        // ("Preferences") must not leak: is_protected_location only sees literal components, so
        // a relative "." must be resolved to an absolute path before the check can see
        // "Preferences" in it at all.
        let base = std::env::temp_dir().join(format!("burrow_orph_relroot_{}", std::process::id()));
        let prefs = base.join("Preferences");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&prefs).unwrap();
        std::fs::write(prefs.join("com.deadvendor.oldapp.plist"), "x").unwrap();

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&prefs).unwrap();
        let hits = scan(Path::new("."), &[]);
        std::env::set_current_dir(&cwd).unwrap();

        assert!(
            hits.is_empty(),
            "a relative root resolving into Preferences must still be protected: {hits:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[cfg(unix)]
    fn scan_canonicalizes_a_symlink_before_checking_protected_status() {
        // A symlink whose TARGET is a protected root must not defeat the guard either — same
        // failure mode as the relative-path case, different disguise.
        let base = std::env::temp_dir().join(format!("burrow_orph_symroot_{}", std::process::id()));
        let real_prefs = base.join("real").join("Preferences");
        let link = base.join("sneaky_link");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&real_prefs).unwrap();
        std::fs::write(real_prefs.join("com.deadvendor.oldapp.plist"), "x").unwrap();
        std::os::unix::fs::symlink(&real_prefs, &link).unwrap();

        let hits = scan(&link, &[]);
        assert!(
            hits.is_empty(),
            "a symlink resolving into Preferences must still be protected: {hits:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn canonical_root_falls_back_to_the_given_path_when_it_does_not_exist() {
        // A missing directory must still degrade to an empty scan (existing behavior), not start
        // erroring just because canonicalization was added.
        let missing = std::env::temp_dir().join(format!("burrow_orph_nope_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert_eq!(canonical_root(&missing), missing);
        assert!(scan(&missing, &[]).is_empty());
    }
}
