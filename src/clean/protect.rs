//! `should_protect_path` — the unconditional protection rail, ported from the oracle's
//! `lib/core/app_protection.sh:227-420`.
//!
//! # Why this module exists
//!
//! `bin/clean.sh`'s `safe_clean` is not a thin wrapper around `rm`. Before it touches anything it
//! runs every candidate path through TWO filters, in this order (`bin/clean.sh:600-612`):
//!
//! ```text
//! if should_protect_path "$path"; then  … log_operation "clean" "SKIPPED" "$path" "protected"
//! if is_path_whitelisted "$path"; then  … log_operation "clean" "SKIPPED" "$path" "whitelist"
//! ```
//!
//! The first port transcribed the ARGUMENTS of ~240 `safe_clean` calls without porting `safe_clean`
//! itself, so it inherited neither filter. Measured live on a real machine, that made the engine's
//! delete-list a strict SUPERSET of the shipping program's by 130 paths — Safari's cache, the
//! Spotlight index, HomeKit, `containermanagerd`, Photoshop, tailscale, and (with a particular kind
//! of irony) `~/Library/Logs/mole`, which the oracle protects with the comment *"Protect Mole's own
//! runtime logs so cleanup cannot delete its active log targets"* and which is the data the GUI's
//! History view reads. A target-by-target patch cannot fix that class: the coarse sweeps
//! (`~/Library/Caches/*` expands to 132 children here, 116 of them protected) have no fixed member
//! list to patch. So this is one filter, applied to every candidate, exactly where bash applies it.
//!
//! # The seven stages
//!
//! Ported in the oracle's order, because the order is observable: stage 3 can set a flag that
//! stages 6 and 7 read, and an early `return 0` means later stages never run.
//!
//! 1. Keyword match for system components (`*[Ss]ystem[Ss]ettings*`, `*com.apple.[Nn]otes*`, …).
//! 2. Caches critical to system-UI rendering, sandboxed Settings/ControlCenter containers, OrbStack
//!    group containers, Settings shared file lists.
//! 3. Extract a bundle ID from a `…/Library/Containers/<id>/…` or `…/Library/Group Containers/<id>/…`
//!    path. A `…/Data/Library/Caches/…` or `…/Data/tmp/…` path inside a container is regenerable by
//!    definition, so instead of protecting it this sets a flag that SUPPRESSES stages 6 and 7 (the
//!    oracle's comment: "safe_clean calls explicitly target these; let them through instead of
//!    blocking on the blanket `com.apple.*` match in should_protect_data"). Any other container path
//!    is protected when [`should_protect_data`] claims its bundle ID.
//! 4. Hardcoded `com.apple.{Settings,SystemSettings,controlcenter,finder,dock}` substrings.
//! 5. A long hardcoded denylist of preference files, user data, and cache-shaped paths that hold
//!    licence/account/plugin/MDM state — Mole's own logs, Codex's session index, iCloud Drive,
//!    Keychains, Mail, audio plug-ins, `ms-playwright`, Adobe, HomeKit, CoreAudio.
//! 6. The whole path against every [`SYSTEM_CRITICAL_BUNDLES`] and [`DATA_PROTECTED_BUNDLES`]
//!    pattern (only entries beginning with `*` can match a path here — that is a property of the
//!    matcher, not a filtering of the data).
//! 7. The path's BASENAME through [`should_protect_data`]. This is the stage that does the heavy
//!    lifting on a real machine: `~/Library/Caches/com.apple.Safari` has basename
//!    `com.apple.Safari`, which hits `should_protect_data`'s very first `case` arm, `com.apple.*`.
//!
//! # The two modes
//!
//! Stages 3, 6 and 7 each branch on `MOLE_UNINSTALL_MODE=1`, which `lib/uninstall/batch.sh:667`
//! exports for the whole uninstall run and `batch.sh:1308` unsets afterwards. An earlier revision of
//! this module left those branches out on the theory that `clean` never sets the flag, so they were
//! unreachable — true then, and false the moment [`super::execute::execute_clean`] (which `uninstall`
//! shares) started calling this function. With the flag omitted, `uninstall com.jetbrains.goland
//! --apply` removed 0 of its 7 leftovers and reported success, and the same held for every bundle ID
//! matching `should_protect_data` or the 351-entry `DATA_PROTECTED_BUNDLES` table — JetBrains,
//! Microsoft, Adobe, Docker, 1Password, Tencent, Slack, Dropbox, Firefox. Protecting an app's data
//! from the command whose entire job is deleting that app's data is not fail-safe; it is a silent
//! no-op.
//!
//! So the mode is ported, as an explicit [`ProtectionMode`] ARGUMENT rather than a global or an
//! env-var read: the two callers state their intent at the call site, and a third caller added later
//! has to choose rather than inherit. What it changes:
//!
//! * **Stage 3** (`app_protection.sh:284`) — the container bundle-ID data check is skipped entirely,
//!   so `~/Library/Containers/com.jetbrains.goland/…` is no longer protected by its own ID.
//! * **Stage 6** (`:387-407`) — [`APPLE_UNINSTALLABLE_APPS`] is consulted FIRST and a match returns
//!   "not protected" immediately; otherwise only [`SYSTEM_CRITICAL_BUNDLES`] applies.
//!   [`DATA_PROTECTED_BUNDLES`] is not consulted at all.
//! * **Stage 7** (`:411`) — skipped entirely; the oracle's comment is "user explicitly chose to
//!   remove this app".
//!
//! Stages 1, 2, 4 and 5 are unconditional in both modes, so System Settings, Control Center,
//! Keychains, iCloud Drive, Mole's own logs and the audio-plugin denylist stay protected even under
//! an uninstall.

use super::protect_data::{
    APPLE_UNINSTALLABLE_APPS, DATA_PROTECTED_BUNDLES, SYSTEM_CRITICAL_BUNDLES,
};
use super::whitelist::glob_match;

/// Which of the oracle's two protection regimes to apply — the ported `MOLE_UNINSTALL_MODE`.
/// Deliberately an argument with no `Default`: every call site has to say which program it is
/// standing in for, because the two answers differ for hundreds of real bundle IDs and picking the
/// wrong one is silent in both directions (a cleanup that deletes an app's licence state, or an
/// uninstall that removes nothing and reports success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionMode {
    /// `bin/clean.sh` with the flag unset — the cleanup regime. Protects data-protected apps.
    Cleanup,
    /// `lib/uninstall/batch.sh` with `MOLE_UNINSTALL_MODE=1` exported — the user has explicitly
    /// asked for this app's files to go, so only system-critical components are still protected.
    Uninstall,
}

fn any_match(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| glob_match(p, text))
}

/// Stage 1 — keyword-based matching for system components. The oracle writes these case-insensitive
/// only where it wrote a bracket class, so `SYSTEMSETTINGS` does NOT match and `systemSettings`
/// does; transcribed exactly rather than "sensibly" widened to a lowercase compare.
const STAGE1_SYSTEM_KEYWORDS: &[&str] = &[
    "*[Ss]ystem[Ss]ettings*",
    "*[Ss]ystem[Pp]references*",
    "*[Cc]ontrol[Cc]enter*",
    "*com.apple.[Ss]ettings*",
    "*com.apple.[Ss]ETTINGS*",
    "*com.apple.[Nn]otes*",
    "*com.apple.[Nn]OTES*",
];

/// Stage 2 — caches essential to modern macOS system-UI rendering (the oracle's comment flags the
/// Settings/ControlCenter ones as preventing a blank-panel bug), plus OrbStack group containers,
/// which hold live container filesystem images rather than anything cache-like.
const STAGE2_UI_CRITICAL: &[&str] = &[
    "*com.apple.systempreferences.cache*",
    "*com.apple.Settings.cache*",
    "*com.apple.controlcenter.cache*",
    "*com.apple.finder.cache*",
    "*com.apple.dock.cache*",
    "*/Library/Containers/com.apple.Settings*",
    "*/Library/Containers/com.apple.SystemSettings*",
    "*/Library/Containers/com.apple.controlcenter*",
    "*/Library/Group Containers/com.apple.systempreferences*",
    "*/Library/Group Containers/com.apple.Settings*",
    "*/Library/Group Containers/*dev.orbstack",
    "*/Library/Group Containers/*dev.orbstack/*",
    "*/.orbstack",
    "*/.orbstack/*",
    "*/com.apple.sharedfilelist/*com.apple.Settings*",
    "*/com.apple.sharedfilelist/*com.apple.SystemSettings*",
    "*/com.apple.sharedfilelist/*systempreferences*",
];

/// Stage 4 — specific hardcoded critical patterns, re-checked after the container extraction.
const STAGE4_CRITICAL: &[&str] = &[
    "*com.apple.Settings*",
    "*com.apple.SystemSettings*",
    "*com.apple.controlcenter*",
    "*com.apple.finder*",
    "*com.apple.dock*",
];

/// Stage 5 — the high-risk cleanup denylist. The oracle's own framing: "these cache/preferences
/// paths are known to contain license, account, plugin, MDM, or system-service state despite
/// cache-like names. Keep this as a protection overlay only; it is not a cleanup allowlist."
///
/// Order within this list is irrelevant (any hit protects), so the oracle's `case`-arm grouping is
/// preserved as comments rather than as structure.
const STAGE5_DENYLIST: &[&str] = &[
    // Dock/Finder preference files.
    "*/Library/Preferences/com.apple.dock.plist",
    "*/Library/Preferences/com.apple.finder.plist",
    // "Protect Mole's own runtime logs so cleanup cannot delete its active log targets."
    "*/Library/Logs/mole",
    "*/Library/Logs/mole/",
    "*/Library/Logs/mole/*",
    // Codex Desktop and CLI keep conversation indexes and app state in cache-shaped paths.
    "*/Library/Application Support/Codex",
    "*/Library/Application Support/Codex/*",
    "*/Library/Logs/com.openai.codex",
    "*/Library/Logs/com.openai.codex/*",
    "*/.codex/sessions",
    "*/.codex/sessions/*",
    "*/.codex/auth.json",
    "*/.codex/history.jsonl",
    "*/.codex/state_*.sqlite",
    "*/.codex/logs_*.sqlite",
    "*/.codex/session_index.jsonl",
    "*/.codex/cache/session_index.jsonl",
    "*/.codex/cache/codex_app_directory",
    "*/.codex/cache/codex_app_directory/*",
    // Bluetooth and WiFi configurations.
    "*/ByHost/com.apple.bluetooth.*",
    "*/ByHost/com.apple.wifi.*",
    // NetworkExtension stores VPN tunnel state and provider preferences.
    "*/Library/Preferences/com.apple.networkextension*.plist",
    // iCloud Drive — the user's cloud-synced data.
    "*/Library/Mobile Documents*",
    "*/Mobile Documents*",
    // Account/credential/mail/calendar/contact stores.
    "*/Library/Accounts",
    "*/Library/Accounts/*",
    "*/Library/Keychains",
    "*/Library/Keychains/*",
    "*/Library/Mail",
    "*/Library/Mail/*",
    "*/Library/Calendars",
    "*/Library/Contacts",
    "*/Library/Contacts/*",
    // Audio plug-ins and their licence state.
    "/Library/Audio/Plug-Ins/Components",
    "/Library/Audio/Plug-Ins/Components/*",
    "/Library/Audio/Plug-Ins/VST",
    "/Library/Audio/Plug-Ins/VST/*",
    "/Library/Audio/Plug-Ins/VST3",
    "/Library/Audio/Plug-Ins/VST3/*",
    "/Library/Application Support/iZotope",
    "/Library/Application Support/iZotope/*",
    "*/Library/Application Support/iZotope",
    "*/Library/Application Support/iZotope/*",
    "/Library/Application Support/LaserSoft Imaging",
    "/Library/Application Support/LaserSoft Imaging/*",
    "*/Library/Preferences/com.native-instruments*",
    "*/Library/Preferences/com.avid.mediacomposer*.plist",
    "*/Library/Preferences/com.fabfilter.*.[0-9].plist",
    "*/Library/Preferences/com.fabfilter.*.[0-9][0-9].plist",
    "*/Library/Preferences/com.paceap.*.plist",
    "/private/var/folders/*/C/com.native-instruments*",
    "/private/var/folders/*/C/com.avid.mediacomposer*",
    "/private/var/folders/*/C/com.paceap.eden.iLokLicenseManager*",
    // Cache-shaped paths that are not disposable.
    "*/Library/Caches/ms-playwright",
    "*/Library/Caches/ms-playwright/*",
    "*/Library/Caches/app.cotypist.Cotypist",
    "*/Library/Caches/app.cotypist.Cotypist/*",
    "*/Library/Caches/com.displaylink.DisplayLinkUserAgent",
    "*/Library/Caches/com.displaylink.DisplayLinkUserAgent/*",
    "*/Library/Caches/com.lasersoft-imaging.SilverFast9",
    "*/Library/Caches/com.lasersoft-imaging.SilverFast9/*",
    "*/Library/Caches/com.lasersoft-imaging.SilverFast-9-Installer",
    "*/Library/Caches/com.lasersoft-imaging.SilverFast-9-Installer/*",
    "*/Library/Caches/Adobe *",
    "*/Library/Caches/* Adobe*",
    "*/Library/Caches/com.apple.containermanagerd",
    "*/Library/Caches/com.apple.containermanagerd/*",
    "*/Library/Caches/com.apple.homed",
    "*/Library/Caches/com.apple.homed/*",
    "*/Library/Caches/com.apple.ap.adprivacyd",
    "*/Library/Caches/com.apple.ap.adprivacyd/*",
    "*/Library/Caches/FamilyCircle",
    "*/Library/Caches/FamilyCircle/*",
    "*/Library/Caches/com.apple.HomeKit",
    "*/Library/Caches/com.apple.HomeKit/*",
    "*/Library/Caches/com.apple.WorkflowKit.BackgroundShortcutRunner.ShortcutsSandboxCache",
    "*/Library/Caches/com.apple.WorkflowKit.BackgroundShortcutRunner.ShortcutsSandboxCache/*",
    "*/Library/Caches/com.apple.siriactionsd.ShortcutsSandboxCache",
    "*/Library/Caches/com.apple.siriactionsd.ShortcutsSandboxCache/*",
    // CoreAudio and audio subsystem caches (oracle issue #553): cleaning these can cause audio
    // output loss on Intel Macs.
    "*com.apple.coreaudio*",
    "*com.apple.audio.*",
    "*coreaudiod*",
];

/// Every `case` arm of the oracle's `should_protect_data` that returns immediately, in order. The
/// arms are checked in sequence and any hit protects, so — unlike a bash `case`, where order decides
/// WHICH arm runs — flattening them into one list is behaviour-preserving. The one arm that is NOT
/// here is the `com.tencent.*|com.sogou.*|com.baidu.*|com.googlecode.*|im.rime.*` arm, which does
/// something different (see [`should_protect_data`]).
const DATA_CASE_ARMS: &[&str] = &[
    // Apple + the classic short names.
    "com.apple.*",
    "loginwindow",
    "dock",
    "systempreferences",
    "finder",
    "safari",
    // CUPS: an OS subsystem with no user-facing app, so its prefs plist looks orphaned (oracle #731).
    "org.cups.*",
    "backgroundtaskmanagement*",
    "keychain*",
    "security*",
    "bluetooth*",
    "wifi*",
    "network*",
    "tcc",
    "notification*",
    "accessibility*",
    "universalaccess*",
    "HIToolbox*",
    "*inputmethod*",
    "*InputMethod*",
    "*IME",
    "textinput*",
    "TextInput*",
    "keyboard*",
    "Keyboard*",
    "inputsource*",
    "InputSource*",
    "keylayout*",
    "KeyLayout*",
    "GlobalPreferences",
    ".GlobalPreferences",
    "org.pqrs.Karabiner*",
    // Password managers.
    "com.1password.*",
    "com.agilebits.*",
    "com.lastpass.*",
    "com.dashlane.*",
    "com.bitwarden.*",
    // IDEs.
    "com.jetbrains.*",
    "JetBrains*",
    "com.microsoft.*",
    "com.visualstudio.*",
    "com.sublimetext.*",
    "com.sublimehq.*",
    "Cursor",
    "Claude",
    "ChatGPT",
    "com.openai.codex",
    "Codex",
    "codex-runtimes",
    "Ollama",
    // Proxy/VPN clients.
    "com.clash.app",
    "com.nssurge.*",
    "com.v2ray.*",
    "com.clash.*",
    "ClashX*",
    "Surge*",
    "Shadowrocket*",
    "Quantumult*",
    "clash-*",
    "Clash-*",
    "*-clash",
    "*-Clash",
    "clash.*",
    "Clash.*",
    "clash_*",
    "*clash-verge*",
    "*Clash-Verge*",
    "clashverge*",
    "ClashVerge*",
    // Dev tooling.
    "com.docker.*",
    "com.getpostman.*",
    "com.insomnia.*",
];

/// The one `case` arm of `should_protect_data` that is not a plain "matched ⇒ protected": these five
/// vendor prefixes cover both protected input methods and plenty of unrelated apps, so the oracle
/// narrows them to the detailed list and RETURNS — it never falls through to the final catch-all
/// loop. Getting that wrong in either direction is a real behaviour change (falling through would
/// protect more; skipping the inner loop would protect less), so it is modelled explicitly.
const DATA_NARROWED_VENDORS: &[&str] = &[
    "com.tencent.*",
    "com.sogou.*",
    "com.baidu.*",
    "com.googlecode.*",
    "im.rime.*",
];

/// Should this app's DATA be protected during cleanup? Ported from `app_protection.sh:147-215`.
/// Called with a container's bundle ID (stage 3) and with a candidate path's basename (stage 7).
pub(crate) fn should_protect_data(bundle_id: &str) -> bool {
    if any_match(bundle_id, DATA_CASE_ARMS) {
        return true;
    }
    if any_match(bundle_id, DATA_NARROWED_VENDORS) {
        // Narrowed arm: consult the detailed list and return that answer — no fallthrough.
        return any_match(bundle_id, DATA_PROTECTED_BUNDLES);
    }
    any_match(bundle_id, DATA_PROTECTED_BUNDLES)
}

/// The bundle ID a container path names, or `None`. Mirrors the oracle's two unanchored regexes,
/// `/Library/Containers/([^/]+)` then `/Library/Group\ Containers/([^/]+)`, including the leftmost-
/// match semantics: a `…/Library/Containers//weird` path fails the first regex at that position but
/// a later occurrence could still match, so every occurrence is tried before giving up.
fn container_bundle(path: &str) -> Option<&str> {
    for marker in ["/Library/Containers/", "/Library/Group Containers/"] {
        let mut from = 0;
        while let Some(rel) = path[from..].find(marker) {
            let start = from + rel + marker.len();
            let seg = path[start..].split('/').next().unwrap_or("");
            if !seg.is_empty() {
                return Some(seg);
            }
            from = start;
        }
    }
    None
}

/// `should_protect_from_uninstall` (`app_protection.sh:94-107`) — the APP-LEVEL gate, a different
/// question from [`should_protect_path`]: not "may this file be deleted" but "may this application
/// be uninstalled at all". `bin/uninstall.sh:438` calls it from
/// `uninstall_app_is_currently_eligible`, so a protected app is never even offered as a candidate.
///
/// Ported because [`ProtectionMode::Uninstall`] turns `uninstall --apply` from a silent no-op into a
/// working delete, and without this gate the engine would remove Finder's, Dock's and Safari's
/// leftovers — which the oracle refuses outright. Trading a silent no-op for a silent over-delete
/// would be the worse of the two bugs.
///
/// The oracle matches with a REGEX built by `build_regex_var` (`:61-81`) rather than a glob: each
/// pattern gets `.` → `\.`, `*` → `.*`, and `^…$` anchors. For these two tables that is exactly
/// [`glob_match`], because neither contains a `?` or a `[` — the only constructs where the two
/// notations would part company. `tables_contain_no_glob_only_metacharacters` pins that precondition
/// so a future entry with a `?` in it fails a test instead of silently changing the semantics.
pub fn should_protect_from_uninstall(bundle_id: &str) -> bool {
    if any_match(bundle_id, APPLE_UNINSTALLABLE_APPS) {
        return false;
    }
    any_match(bundle_id, SYSTEM_CRITICAL_BUNDLES)
}

/// True when the oracle would refuse to delete this path — i.e. when `safe_clean` would log
/// `SKIPPED … protected` instead of removing it. `mode` is the ported `MOLE_UNINSTALL_MODE`; see the
/// module docs for the stage-by-stage port and for exactly what the two modes differ on.
pub fn should_protect_path(path: &str, mode: ProtectionMode) -> bool {
    if path.is_empty() {
        return false;
    }
    let uninstalling = mode == ProtectionMode::Uninstall;

    // 1 + 2. Unconditional in both modes.
    if any_match(path, STAGE1_SYSTEM_KEYWORDS) || any_match(path, STAGE2_UI_CRITICAL) {
        return true;
    }

    // 3. Container bundle ID. Cache/tmp inside a container is regenerable, and the oracle lets those
    // through the blanket `com.apple.*` rule by suppressing stages 6 and 7 for them. The bundle-ID
    // data check is the `elif` of `[[ "${MOLE_UNINSTALL_MODE:-0}" != "1" ]] && should_protect_data …`
    // (`app_protection.sh:284`), so under `Uninstall` it never runs — but the cache/tmp flag in the
    // `if` above it still does, exactly as in bash.
    let mut container_cache_path = false;
    if let Some(bundle_id) = container_bundle(path) {
        if glob_match("*/Data/Library/Caches/*", path) || glob_match("*/Data/tmp/*", path) {
            container_cache_path = true;
        } else if !uninstalling && should_protect_data(bundle_id) {
            return true;
        }
    }

    // 4 + 5. Unconditional in both modes.
    if any_match(path, STAGE4_CRITICAL) || any_match(path, STAGE5_DENYLIST) {
        return true;
    }

    if container_cache_path {
        return false;
    }

    // 6. The whole path against the bundle tables — which tables depends on the mode
    // (`app_protection.sh:387-407`).
    if uninstalling {
        // An App Store / developer.apple.com Apple app returns "not protected" IMMEDIATELY, before
        // the system-critical loop that `com.apple.*` entries would otherwise catch. The early
        // `return 1` also skips stage 7 — which this mode skips anyway, so the two agree.
        if any_match(path, APPLE_UNINSTALLABLE_APPS) {
            return false;
        }
        return any_match(path, SYSTEM_CRITICAL_BUNDLES);
    }
    if any_match(path, SYSTEM_CRITICAL_BUNDLES) || any_match(path, DATA_PROTECTED_BUNDLES) {
        return true;
    }

    // 7. The BASENAME through should_protect_data — `${path##*/}`, so a trailing slash yields "".
    // Skipped entirely under `Uninstall` (the `return` above), per `app_protection.sh:411`.
    let filename = path.rsplit('/').next().unwrap_or("");
    should_protect_data(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    /// The oracle-captured fixture: 1968 concrete paths and, for each, what the REAL bash program's
    /// `should_protect_path` (and `is_path_whitelisted` seeded with the built-in defaults — used by
    /// [`super::super::whitelist`]'s tests) said about it, all in CLEANUP mode
    /// (`MOLE_UNINSTALL_MODE` unset). The public copy replaces private path identifiers without
    /// changing verdicts. `scripts/check_fixtures.py` verifies the approved copy; see
    /// `FIXTURE_PROVENANCE.md` for the capture authority and preserved invariants.
    const ORACLE_VERDICTS: &str = include_str!("protection.golden.json");

    /// The second oracle capture, which asks the SAME function under both `MOLE_UNINSTALL_MODE`
    /// settings — the column `protection.golden.json` structurally cannot have. Captured by
    /// `capture_deletion_rails_golden.py`; see `FIXTURE_PROVENANCE.md`.
    const RAILS: &str = include_str!("deletion_rails.golden.json");

    /// `(path, protect_clean, protect_uninstall)` from the deletion-rails fixture.
    fn mode_rows() -> Vec<(String, bool, bool)> {
        let doc = Json::parse(RAILS).expect("fixture parses");
        doc.get("paths")
            .and_then(|p| p.as_array())
            .expect("fixture has a paths array")
            .iter()
            .map(|r| {
                let flag = |k: &str| {
                    r.get(k)
                        .and_then(|v| v.as_bool())
                        .unwrap_or_else(|| panic!("row is missing {k}"))
                };
                (
                    r.get("path")
                        .and_then(|v| v.as_str())
                        .expect("row has a path")
                        .to_string(),
                    flag("protect_clean"),
                    flag("protect_uninstall"),
                )
            })
            .collect()
    }

    fn oracle_rows() -> Vec<(String, bool)> {
        let doc = Json::parse(ORACLE_VERDICTS).expect("fixture parses");
        doc.get("paths")
            .and_then(|p| p.as_array())
            .expect("fixture has a paths array")
            .iter()
            .map(|row| {
                (
                    row.get("path")
                        .and_then(|v| v.as_str())
                        .expect("row has a path")
                        .to_string(),
                    row.get("protected")
                        .and_then(|v| v.as_bool())
                        .expect("row has a verdict"),
                )
            })
            .collect()
    }

    /// The `$HOME` the fixture was captured under. The tests below name a few specific paths, and
    /// reading the prefix from the fixture rather than hardcoding one developer's home means a
    /// re-capture on another machine keeps them meaningful instead of quietly failing to find rows.
    fn oracle_home() -> String {
        Json::parse(ORACLE_VERDICTS)
            .expect("fixture parses")
            .get("home")
            .and_then(|v| v.as_str())
            .expect("fixture records the capture home")
            .to_string()
    }

    fn verdict_for(rows: &[(String, bool)], path: &str) -> Option<bool> {
        rows.iter().find(|(p, _)| p == path).map(|(_, v)| *v)
    }

    #[test]
    fn agrees_with_the_oracles_own_should_protect_path_on_every_captured_path() {
        let rows = oracle_rows();
        assert!(
            rows.len() > 1500,
            "the fixture should cover the whole live plan, the real ~/Library children and one \
             instantiation of every oracle pattern; got only {}",
            rows.len()
        );
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(path, expected)| {
                should_protect_path(path, ProtectionMode::Cleanup) != *expected
            })
            .map(|(path, expected)| {
                format!("  {path}\n    oracle: {expected}, engine: {}", !expected)
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} captured paths disagree with the oracle:\n{}",
            wrong.len(),
            rows.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn the_captured_fixture_has_both_verdicts_in_it() {
        // A fixture that were all-`false` would pass the test above against a `should_protect_path`
        // that always returns `false` — the empty-spine failure RULEBOOK §3b describes. Pin that
        // both answers are represented, and by a wide margin, so the conformance test has something
        // to fail on in either direction.
        let rows = oracle_rows();
        let protected = rows.iter().filter(|(_, p)| *p).count();
        let free = rows.len() - protected;
        assert!(
            protected > 500 && free > 500,
            "fixture spine is too thin to prove anything: {protected} protected / {free} not"
        );
    }

    #[test]
    fn mole_protects_its_own_log_directory_but_not_a_lookalike() {
        // The single most consequential entry in stage 5: without it the engine deletes its own
        // audit trail mid-run, which is also what the GUI's History view reads. The lookalike is not
        // hypothetical — `~/Library/Logs` on the capture machine really does contain directories
        // named `mole\n[` (some tool mkdir -p'd an unescaped JSON fragment), and the oracle does NOT
        // protect those, so a prefix match here would over-protect. Both verdicts are read from the
        // fixture; nothing about the expected answer is typed into this test.
        let rows = oracle_rows();
        let home = oracle_home();
        let log = format!("{home}/Library/Logs/mole");
        let lookalike = format!("{home}/Library/Logs/mole-lookalike");
        assert_eq!(
            verdict_for(&rows, &log),
            Some(true),
            "fixture must cover {log}"
        );
        assert_eq!(verdict_for(&rows, &lookalike), Some(false));
        assert!(should_protect_path(&log, ProtectionMode::Cleanup));
        assert!(!should_protect_path(&lookalike, ProtectionMode::Cleanup));
    }

    #[test]
    fn container_cache_paths_are_let_through_but_container_data_is_not() {
        // Stage 3's flag is the subtlest part of the port: the SAME container bundle ID yields
        // opposite answers depending on whether the path sits under Data/Library/Caches. Both
        // verdicts are the oracle's, loaded from the fixture; the engine's answers follow.
        let rows = oracle_rows();
        let home = oracle_home();
        let cache =
            format!("{home}/Library/Containers/com.apple.mediaanalysisd/Data/Library/Caches/x");
        let data = format!("{home}/Library/Containers/com.apple.mediaanalysisd/Data/Documents/x");
        assert_eq!(verdict_for(&rows, &cache), Some(false));
        assert_eq!(verdict_for(&rows, &data), Some(true));
        assert!(!should_protect_path(&cache, ProtectionMode::Cleanup));
        assert!(should_protect_path(&data, ProtectionMode::Cleanup));
    }

    #[test]
    fn empty_path_is_not_protected() {
        // `[[ -z "$path" ]] && return 1` — the oracle's very first line.
        assert!(!should_protect_path("", ProtectionMode::Cleanup));
        assert!(!should_protect_path("", ProtectionMode::Uninstall));
    }

    // -- MOLE_UNINSTALL_MODE. Omitting it was fail-safe only while `clean` was the sole caller;
    // once `uninstall` started sharing the executor it became a silent total failure of that
    // command. Every verdict below is the real bash's, in both modes, read from the fixture.

    #[test]
    fn agrees_with_the_oracle_in_uninstall_mode_on_every_captured_path() {
        let rows = mode_rows();
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(path, _, uninstall)| {
                should_protect_path(path, ProtectionMode::Uninstall) != *uninstall
            })
            .map(|(path, _, uninstall)| {
                format!(
                    "  {path:?}\n    oracle: {uninstall}, engine: {}",
                    !uninstall
                )
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "{} of {} captured paths disagree with the oracle under MOLE_UNINSTALL_MODE=1:\n{}",
            wrong.len(),
            rows.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn agrees_with_the_oracle_in_cleanup_mode_on_the_deletion_rails_corpus_too() {
        // The second fixture's corpus is a superset of the first's, so running the cleanup mode
        // against it as well covers the added policy/uninstall/symlink probes — and proves the two
        // captures agree with each other rather than each with its own private idea of the oracle.
        let rows = mode_rows();
        let wrong: Vec<String> = rows
            .iter()
            .filter(|(path, clean, _)| should_protect_path(path, ProtectionMode::Cleanup) != *clean)
            .map(|(path, clean, _)| format!("  {path:?}\n    oracle: {clean}"))
            .collect();
        assert!(
            wrong.is_empty(),
            "{} disagree:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn the_two_modes_really_do_disagree_and_only_ever_in_the_weaker_direction() {
        // Two properties at once. (1) The fixture distinguishes the modes at all — without this a
        // port that ignored `mode` would sail through the conformance tests above. (2) Every
        // disagreement goes ONE way: uninstall mode may drop protection, never add it. That is the
        // shape of all three bash branches (`:284`, `:387-407`, `:411`), and a port that got one
        // inverted would still "differ" without this check.
        let rows = mode_rows();
        let differs: Vec<&(String, bool, bool)> = rows.iter().filter(|(_, c, u)| c != u).collect();
        assert!(
            differs.len() > 50,
            "only {} rows distinguish the modes — the fixture cannot detect a port that ignores it",
            differs.len()
        );
        let wrong_way: Vec<&str> = differs
            .iter()
            .filter(|(_, c, u)| !*c && *u)
            .map(|(p, _, _)| p.as_str())
            .collect();
        assert!(
            wrong_way.is_empty(),
            "uninstall mode must never protect MORE than cleanup mode, but the oracle says it does \
             for: {wrong_way:?}"
        );
    }

    #[test]
    fn stage_six_only_ever_bites_on_a_bundle_id_shaped_argument() {
        // Worth pinning because it is counter-intuitive and it is what makes the two Xcode/Safari
        // rows below meaningful: stage 6 matches its tables against the WHOLE `$path`
        // (`bundle_matches_pattern "$path" "$pattern"`), and NO entry in SYSTEM_CRITICAL_BUNDLES
        // begins with `*`. So on a real absolute path stage 6 can never match, and uninstall mode —
        // which has only stage 6 after the unconditional stages — reduces to stages 1/2/4/5.
        assert!(
            SYSTEM_CRITICAL_BUNDLES.iter().all(|p| !p.starts_with('*')),
            "a `*`-leading entry would change what stage 6 can match on a path; the tests below \
             and protect_data.rs's doc comment both assume there is none"
        );
    }

    #[test]
    fn an_apple_uninstallable_app_is_releasable_where_a_system_critical_one_is_not() {
        // Both tables are matched against the whole argument, so the bundle-ID FORM is the only one
        // that reaches them — hence the fixture carries bare bundle IDs alongside the leftover
        // paths. Xcode is in APPLE_UNINSTALLABLE_APPS, Safari in SYSTEM_CRITICAL_BUNDLES; the
        // oracle's answers for both are read from the fixture.
        let rows = mode_rows();
        let find = |id: &str| {
            rows.iter()
                .find(|(p, _, _)| p == id)
                .unwrap_or_else(|| panic!("fixture must cover the bare bundle id {id}"))
        };
        let (xcode, xc_clean, xc_uninstall) = find("com.apple.dt.Xcode");
        assert!(*xc_clean, "cleanup protects it");
        assert!(!*xc_uninstall, "an explicit uninstall releases it");
        assert!(should_protect_path(xcode, ProtectionMode::Cleanup));
        assert!(!should_protect_path(xcode, ProtectionMode::Uninstall));

        let (safari, sf_clean, sf_uninstall) = find("com.apple.Safari");
        assert!(
            *sf_clean && *sf_uninstall,
            "Safari is critical in both modes"
        );
        assert!(should_protect_path(safari, ProtectionMode::Cleanup));
        assert!(should_protect_path(safari, ProtectionMode::Uninstall));
    }

    #[test]
    fn the_app_level_uninstall_gate_matches_the_oracles_two_tables() {
        // `should_protect_from_uninstall` is the gate `bin/uninstall.sh:438` applies before an app
        // is even eligible. It is where APPLE_UNINSTALLABLE_APPS actually earns its keep: Xcode and
        // GarageBand may be uninstalled, Finder/Dock/Safari may not.
        for id in [
            "com.apple.dt.Xcode",
            "com.apple.garageband10",
            "com.apple.iWork.Pages",
            "com.jetbrains.goland",
            "com.nothing.Matches",
        ] {
            assert!(!should_protect_from_uninstall(id), "{id} is uninstallable");
        }
        for id in ["com.apple.finder", "com.apple.dock", "com.apple.Safari"] {
            assert!(should_protect_from_uninstall(id), "{id} must be refused");
        }
    }

    #[test]
    fn tables_contain_no_glob_only_metacharacters() {
        // The oracle matches these two tables with a REGEX (`build_regex_var`: `.`→`\.`, `*`→`.*`,
        // anchored) while this port matches them with `glob_match`. The two agree only while no
        // entry uses `?` or `[`, which have meaning in globs and different meaning in regexes. If
        // someone adds one upstream, fail here rather than diverge silently.
        for table in [APPLE_UNINSTALLABLE_APPS, SYSTEM_CRITICAL_BUNDLES] {
            for p in table {
                assert!(
                    !p.contains('?') && !p.contains('['),
                    "{p:?} uses a metacharacter where glob and build_regex_var disagree"
                );
            }
        }
    }

    #[test]
    fn a_data_protected_bundles_leftover_is_releasable_by_uninstall_but_not_by_clean() {
        // The exact defect: `uninstall com.jetbrains.goland --apply` removed 0 of its leftovers and
        // reported success. Every leftover location must be RELEASED by uninstall mode, and all but
        // one must be PROTECTED by cleanup mode — the exception being the container's
        // `Data/Library/Caches` path, which stage 3's regenerable-cache flag already lets through in
        // both modes. The fixture is what says which is which; asserting "all protected in cleanup"
        // is what an earlier version of this test did, and the fixture correctly refused it.
        let rows = mode_rows();
        let bundle = "com.jetbrains.goland";
        let hits: Vec<&(String, bool, bool)> =
            rows.iter().filter(|(p, _, _)| p.contains(bundle)).collect();
        assert!(
            hits.len() >= 10,
            "fixture must carry the leftover locations for {bundle}; got {}",
            hits.len()
        );
        for (path, clean, uninstall) in &hits {
            assert!(!*uninstall, "uninstall must release {path}");
            assert_eq!(
                should_protect_path(path, ProtectionMode::Cleanup),
                *clean,
                "cleanup verdict for {path}"
            );
            assert!(!should_protect_path(path, ProtectionMode::Uninstall));
        }
        let protected_by_cleanup = hits.iter().filter(|(_, c, _)| *c).count();
        assert!(
            protected_by_cleanup >= 9,
            "cleanup mode must protect nearly all of them — that is the whole reason the shared \
             executor broke uninstall; only {protected_by_cleanup} of {} are protected",
            hits.len()
        );
    }

    #[test]
    fn stages_one_to_five_stay_unconditional_even_under_uninstall() {
        // Only stages 3, 6 and 7 branch on the flag. Mole's own logs, Keychains and iCloud Drive are
        // stage-5 entries and must survive an uninstall too — a port that gated the whole function
        // on the mode would pass every "uninstall releases X" test above and quietly hand an
        // uninstall the keys to the keychain.
        let rows = mode_rows();
        for needle in ["/Library/Logs/mole", "/Library/Keychains/x"] {
            let row = rows
                .iter()
                .find(|(p, _, _)| p.ends_with(needle))
                .unwrap_or_else(|| panic!("fixture must cover a path ending {needle}"));
            assert!(row.1 && row.2, "{} must be protected in BOTH modes", row.0);
            assert!(should_protect_path(&row.0, ProtectionMode::Cleanup));
            assert!(should_protect_path(&row.0, ProtectionMode::Uninstall));
        }
    }
}
