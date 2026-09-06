//! `validate_path_for_deletion` — the THIRD rail, ported from `lib/core/file_ops.sh:66-210`.
//!
//! # Why this module exists
//!
//! Both this crate's earlier module docs and the migration's own rulebook modelled `safe_clean` as
//! "two filters, then remove". That is wrong, and the mistake is one function call deep:
//! `safe_clean`'s removal call is `safe_remove "$path" true "$size"` (`bin/clean.sh:800` and `:845`),
//! and `safe_remove`'s very first act is
//!
//! ```text
//! if [[ "$silent" == "true" ]]; then
//!     validate_path_for_deletion "$path" 2> /dev/null || return 1
//! ```
//!
//! (`file_ops.sh:224-226`). So EVERY delete the oracle performs — cleanup and uninstall alike, since
//! `mole_delete` calls the same function at `file_ops.sh:522` — passes a third, independent gate that
//! the engine had no counterpart for at all: `remove_one` went straight to `fs::remove_dir_all` /
//! `move_to_trash`.
//!
//! Two live divergences, both measured rather than theorised:
//!
//! * Feeding the engine's own 321-path plan through the REAL bash `validate_path_for_deletion`
//!   returned 4 refusals, all of them paths the engine would delete: the `~/Library/Logs/mole\n{…}`
//!   directories whose names embed a newline (some tool `mkdir -p`'d an unescaped JSON fragment).
//!   The oracle cannot delete them; the engine could.
//! * `plan.rs` targets `/Library/Apple/usr/share/rosetta/rosetta_update_bundle`, transcribed from
//!   `lib/clean/user.sh:2109`. That `safe_clean` call is DEAD CODE in the oracle —
//!   `_mole_is_critical_deletion_path` matches `/Library/Apple/*` and refuses every single time. The
//!   engine actually removes it on any Mac that has Rosetta 2 and enough privilege.
//!
//! # The order is observable, so it is preserved exactly
//!
//! 1. Empty ⇒ refuse.
//! 2. Not absolute ⇒ refuse.
//! 3. `..` as a whole path COMPONENT ⇒ refuse. The oracle's own comment explains the narrowness: a
//!    directory merely CONTAINING `..`, like Firefox's `name..files`, is fine.
//! 4. Any control character ⇒ refuse.
//! 5. Normalize: `//` collapsed, one trailing `/` stripped.
//! 6. If the path is a symlink, resolve its target and refuse when THAT is a critical system path.
//! 7. Two ALLOWLISTS that return OK EARLY — the coresymbolicationd cache and the safe paths under
//!    `/private` — which is why `/private/var/db/diagnostics` is deletable even though
//!    `/private/var/db/*` is critical, and why neither of the two steps below can see those paths.
//! 8. Critical system path ⇒ refuse.
//! 9. [`should_protect_path`] AGAIN, on the NORMALIZED path.
//!
//! Step 9 is not redundant with `safe_clean`'s own first filter: `safe_clean` tests the RAW argument
//! and this tests the `//`-collapsed, trailing-slash-stripped one, so `~/Library//Keychains/x` is
//! protected by the oracle through this call and by nothing else. Both are reproduced.

use super::protect::{should_protect_path, ProtectionMode};
use super::whitelist::glob_match;
use std::path::Path;

/// Resolve the directories the kernel traverses without following the final entry. Removing a
/// symlink removes that link; removing a child beneath it acts on the link's destination.
pub(crate) fn physical_deletion_path(path: &str) -> Option<String> {
    let p = Path::new(path);
    let parent = p.parent()?.canonicalize().ok()?;
    Some(parent.join(p.file_name()?).to_str()?.to_string())
}

/// Recheck whitelist patterns against the physical namespace as well as their displayed spelling.
/// Resolve only the literal prefix of a glob so a wildcard never becomes a filesystem lookup.
pub(crate) fn deletion_is_whitelisted(path: &str, patterns: &[&str]) -> bool {
    use super::whitelist::{has_glob, is_path_whitelisted};
    if is_path_whitelisted(path, patterns) {
        return true;
    }
    let physical = physical_deletion_path(path).unwrap_or_else(|| path.to_string());
    if is_path_whitelisted(&physical, patterns) {
        return true;
    }
    patterns.iter().any(|pattern| {
        let mut prefix = std::path::PathBuf::new();
        let mut suffix = std::path::PathBuf::new();
        let mut wildcard = false;
        for component in Path::new(pattern).components() {
            wildcard |= has_glob(&component.as_os_str().to_string_lossy());
            if wildcard {
                suffix.push(component.as_os_str());
            } else {
                prefix.push(component.as_os_str());
            }
        }
        // A protected descendant can be absent; resolve its nearest existing ancestor too.
        while !prefix.exists() {
            let Some(name) = prefix.file_name() else {
                return false;
            };
            suffix = Path::new(name).join(suffix);
            if !prefix.pop() {
                return false;
            }
        }
        prefix
            .canonicalize()
            .ok()
            .and_then(|p| p.join(suffix).to_str().map(str::to_string))
            .is_some_and(|p| is_path_whitelisted(&physical, &[p.as_str()]))
    })
}

fn any_match(text: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| glob_match(p, text))
}

/// `_mole_is_critical_deletion_path` (`file_ops.sh:80-110`), transcribed arm for arm. Deletion
/// policy ONLY — app/data protection is [`should_protect_path`]'s job, and the oracle keeps the two
/// in different files for that reason.
///
/// Read the near-misses as carefully as the hits: `/usr/local` is NOT here (only `/usr` itself and
/// `bin`/`sbin`/`lib` under it), `/Users/Shared` is critical but `/Users/Shared/*` is not, and
/// `/private` alone is critical while `/private/tmp` is not.
const CRITICAL_DELETION_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/bin/*",
    "/sbin",
    "/sbin/*",
    "/usr",
    "/usr/bin",
    "/usr/bin/*",
    "/usr/sbin",
    "/usr/sbin/*",
    "/usr/lib",
    "/usr/lib/*",
    "/System",
    "/System/*",
    "/Library/Apple",
    "/Library/Apple/*",
    "/Library/Extensions",
    "/Library/Extensions/*",
    "/Library/Keychains",
    "/Library/Keychains/*",
    "/Applications/Finder.app",
    "/Applications/Finder.app/*",
    "/Applications/Safari.app",
    "/Applications/Safari.app/*",
    "/Users",
    "/Users/Shared",
    "/Users/Guest",
    "/Users/Guest/*",
    "/private",
    "/etc",
    "/etc/*",
    "/private/etc",
    "/private/etc/*",
    "/var",
    "/var/db",
    "/var/db/*",
    "/var/audit",
    "/var/audit/*",
    "/private/var",
    "/private/var/db",
    "/private/var/db/*",
    "/private/var/audit",
    "/private/var/audit/*",
];

/// `file_ops.sh:172-176` — the coresymbolicationd cache is a rebuildable system cache, allowed even
/// though `/System/*` is critical. Checked BEFORE the critical list, and it returns OK immediately,
/// so it also skips the `should_protect_path` re-check below it.
const ALLOWED_CORESYMBOLICATION: &[&str] = &[
    "/System/Library/Caches/com.apple.coresymbolicationd/data",
    "/System/Library/Caches/com.apple.coresymbolicationd/data/*",
];

/// `file_ops.sh:179-191` — the known-safe paths under `/private`. Same early-return: these are the
/// reason `/private/var/db/diagnostics` is deletable while `/private/var/db/*` is critical.
const ALLOWED_PRIVATE: &[&str] = &[
    "/private/tmp",
    "/private/tmp/*",
    "/private/var/tmp",
    "/private/var/tmp/*",
    "/private/var/log",
    "/private/var/log/*",
    "/private/var/folders",
    "/private/var/folders/*",
    "/private/var/db/diagnostics",
    "/private/var/db/diagnostics/*",
    "/private/var/db/DiagnosticPipeline",
    "/private/var/db/DiagnosticPipeline/*",
    "/private/var/db/powerlog",
    "/private/var/db/powerlog/*",
    "/private/var/db/reportmemoryexception",
    "/private/var/db/reportmemoryexception/*",
    "/private/var/db/receipts/*.bom",
    "/private/var/db/receipts/*.plist",
];

/// `_mole_normalize_deletion_policy_path` (`file_ops.sh:66-77`): collapse every run of `//` to `/`,
/// then strip ONE trailing `/` — unless that empties the string, in which case the collapsed form is
/// kept (so `///` normalizes to `/`, not to `""`).
pub(crate) fn normalize_deletion_policy_path(path: &str) -> String {
    let mut p = path.to_string();
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    match p.strip_suffix('/') {
        Some(trimmed) if !trimmed.is_empty() => trimmed.to_string(),
        _ => p,
    }
}

/// True when this path is one the oracle refuses to delete on deletion-policy grounds alone.
pub(crate) fn is_critical_deletion_path(path: &str) -> bool {
    any_match(path, CRITICAL_DELETION_PATHS)
}

/// `${p##*/}` / `${p%/*}` the way bash's `basename`/`dirname` behave for the shapes reachable here.
fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn dirname(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => ".",
    }
}

/// Join `rel` onto `base` the way bash's LOGICAL `cd` does — `.` dropped, `..` popping the previous
/// component TEXTUALLY (never above `/`), symlinks in the path left unresolved. Deliberately not
/// [`std::fs::canonicalize`]: the oracle uses plain `cd`/`pwd`, which are `-L`, and resolving
/// symlinks here would answer a different question than the one bash asks.
fn logical_join<'a>(base: &'a str, rel: &'a str) -> String {
    let mut out: Vec<&'a str> = Vec::new();
    let feed = |s: &'a str, out: &mut Vec<&'a str>| {
        for part in s.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    out.pop();
                }
                other => out.push(other),
            }
        }
    };
    if rel.starts_with('/') {
        feed(rel, &mut out);
    } else {
        feed(base, &mut out);
        feed(rel, &mut out);
    }
    format!("/{}", out.join("/"))
}

/// Reproduce `file_ops.sh:154-159` for a RELATIVE symlink target:
///
/// ```text
/// resolved_target=$(cd "$link_dir" 2>/dev/null && cd "$(dirname "$link_target")" 2>/dev/null && pwd)/$(basename "$link_target")
/// ```
///
/// The `|| resolved_target=""` on the next line never fires (the assignment's exit status comes from
/// the trailing `$(basename …)`, which always succeeds), so when EITHER `cd` fails the command
/// substitution is empty and the result is the string `/<basename>`. That is not a hypothetical: a
/// symlink to `nowhere/System` therefore "resolves" to `/System` and is REFUSED. Verified against
/// the real bash before this was written, and pinned by the differential fixture.
fn resolve_relative_symlink(link_path: &str, target: &str) -> String {
    let base = basename(target);
    let link_dir = dirname(link_path);
    if !Path::new(link_dir).is_dir() {
        return format!("/{base}");
    }
    let joined = logical_join(link_dir, dirname(target));
    if !Path::new(&joined).is_dir() {
        return format!("/{base}");
    }
    format!("{joined}/{base}")
}

/// Whether THIS platform's absolute paths are the ones the protection tables below are written in.
/// False anywhere but unix, and [`validate_path_for_deletion`] refuses outright when it is false —
/// see the long comment at that guard for why the refusal has to be explicit rather than left to
/// fall out of the POSIX absoluteness check.
pub(crate) const RAILS_SPEAK_THIS_PLATFORMS_PATHS: bool = cfg!(unix);

/// `Ok(())` when the oracle's `validate_path_for_deletion` would return 0 for this path, `Err(why)`
/// when it would refuse. The reason strings mirror the oracle's own `log_error` wording so a refusal
/// in the engine's output is greppable against the bash it came from.
///
/// `mode` threads through to the step-9 [`should_protect_path`] re-check, because the oracle's is an
/// ambient `MOLE_UNINSTALL_MODE` read: during an uninstall run the flag IS exported, so `mole_delete`
/// → `validate_path_for_deletion` → `should_protect_path` all see the weaker regime.
pub fn validate_path_for_deletion(path: &str, mode: ProtectionMode) -> Result<(), String> {
    validate_path(path, mode, true)
}

fn validate_path(path: &str, mode: ProtectionMode, check_parent: bool) -> Result<(), String> {
    if path.is_empty() {
        return Err("path validation failed: empty path".into());
    }

    // EVERY RAIL BELOW THIS LINE SPEAKS POSIX, SO NOTHING IS DELETED ON A PLATFORM THAT DOES NOT.
    //
    // This is a deliberate killswitch, not a missing feature, and it is here rather than left to
    // fall out of the absoluteness check below because the accidental version was a trap. Read on
    // before removing it.
    //
    // Every protection rail this function is the gate for is written in `/`-separated, macOS-shaped
    // path vocabulary, and every one of them answers "not protected" for a `C:\...` path:
    //
    // * `CRITICAL_DELETION_PATHS` is `/System`, `/usr/bin`, `/etc`, … — there is no `C:\Windows`
    //   entry, so `is_critical_deletion_path(r"C:\Windows\System32")` is FALSE.
    // * `should_protect_path` matches its stage tables with `/`-separated globs and takes its
    //   step-7 basename with `rsplit('/')`, so on a backslash path the basename is the whole tail
    //   (`com.example.foo\data`) and every table misses. It returns FALSE.
    // * The `..` traversal check below splits on `/`, so `C:\Users\me\..\..\Windows` contains no
    //   `..` COMPONENT as far as it can see, and passes.
    //
    // So the POSIX absoluteness check immediately below is, on Windows, the only thing standing
    // between a planner-supplied path and an unguarded `remove_dir_all`. That makes "fix the
    // absoluteness check to use `Path::is_absolute()`" — which looks like a plain correctness
    // improvement, and is the obvious response to a wall of `path must be absolute: C:\...` test
    // failures — the single most dangerous edit available in this file: it would convert refusing
    // everything into protecting nothing.
    //
    // Making a Windows `clean`/`uninstall --apply` actually work means porting the protection
    // tables to Windows path vocabulary, and there is no oracle to port them against — the bash
    // this crate transcribes is macOS-only, and the captured fixtures are macOS paths. Until that
    // exists, refusing is the honest answer, and it costs nothing real: `clean`'s target table is
    // entirely `~/Library/...`, so a Windows run has no candidates to lose.
    //
    // See `the_deletion_rails_refuse_outright_on_a_platform_they_were_not_written_for`, which pins
    // both halves of this: that the refusal happens, and that the rails underneath it would not
    // catch anything if it did not.
    //
    // `cfg!` rather than `#[cfg]` deliberately: the ported body below stays COMPILED and
    // warning-clean on every platform, so a Windows `cargo clippy -D warnings` keeps type-checking
    // the rails instead of dead-coding them out of the build and out of review.
    if !RAILS_SPEAK_THIS_PLATFORMS_PATHS {
        return Err(format!(
            "path validation failed: deletion rails are POSIX-only and this platform is not: {path}"
        ));
    }

    if !path.starts_with('/') {
        return Err(format!(
            "path validation failed: path must be absolute: {path}"
        ));
    }
    // `[[ "$path" =~ (^|/)\.\.(\/|$) ]]` — `..` as a COMPLETE component only, so a directory named
    // `name..files` is fine. Splitting on `/` is exactly that regex.
    if path.split('/').any(|c| c == ".." || c == ".") {
        return Err(format!(
            "path validation failed: path traversal not allowed: {path}"
        ));
    }
    // `[[ "$path" =~ [[:cntrl:]] ]] || [[ "$path" =~ $'\n' ]]`. Measured against the real bash in
    // this repo's own locale (LANG/LC_ALL/LC_CTYPE all unset, i.e. C): `[[:cntrl:]]` matches ASCII
    // 0x00-0x1F and 0x7F and NOTHING else — U+0085, U+00A0 and U+200B all fail to match — so a
    // codepoint test over `chars()` is equivalent to bash's byte test.
    if path.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(format!(
            "path validation failed: contains control characters: {path}"
        ));
    }

    let policy_path = normalize_deletion_policy_path(path);
    if check_parent {
        if let Some(physical) = physical_deletion_path(path) {
            if physical != policy_path {
                if should_protect_path(&physical, mode) {
                    return Err(format!(
                        "path resolves beneath protected data: {path} -> {physical}"
                    ));
                }
                validate_path(&physical, mode, false)?;
            }
        }
    }

    // Symlink target check, BEFORE the allowlists — a symlink sitting at an allowlisted location and
    // pointing at a critical one is still refused.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let Ok(target) = std::fs::read_link(path) else {
                return Err(format!("cannot read symlink: {path}"));
            };
            let target = target.to_string_lossy().into_owned();
            let resolved = if target.starts_with('/') {
                target
            } else {
                resolve_relative_symlink(path, &target)
            };
            if !resolved.is_empty() {
                let resolved = normalize_deletion_policy_path(&resolved);
                if is_critical_deletion_path(&resolved) {
                    return Err(format!(
                        "symlink points to protected system path: {path} -> {resolved}"
                    ));
                }
            }
        }
    }

    // The two allowlists — both return OK immediately, skipping the critical check AND the
    // should_protect_path re-check below.
    if any_match(&policy_path, ALLOWED_CORESYMBOLICATION)
        || any_match(&policy_path, ALLOWED_PRIVATE)
    {
        return Ok(());
    }

    if is_critical_deletion_path(&policy_path) {
        return Err(format!(
            "path validation failed: critical system path: {path}"
        ));
    }

    if should_protect_path(&policy_path, mode) {
        return Err(format!(
            "path validation: protected path skipped: {policy_path}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    /// The oracle-captured differential fixture: concrete paths and, for each, what the REAL bash
    /// `validate_path_for_deletion` said about it under BOTH `MOLE_UNINSTALL_MODE` settings, plus
    /// `should_protect_path`'s own answer in both modes. The public copy anonymizes private path
    /// identifiers while retaining every verdict. `scripts/check_fixtures.py` verifies its
    /// approved contents; see `FIXTURE_PROVENANCE.md` for the capture authority.
    const RAILS: &str = include_str!("deletion_rails.golden.json");

    /// One fixture row: the path and the four verdicts the oracle gave for it.
    struct Row {
        path: String,
        validate_clean: bool,
        validate_uninstall: bool,
        protect_clean: bool,
        protect_uninstall: bool,
    }

    fn rows() -> Vec<Row> {
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
                Row {
                    path: r
                        .get("path")
                        .and_then(|v| v.as_str())
                        .expect("row has a path")
                        .to_string(),
                    validate_clean: flag("validate_clean"),
                    validate_uninstall: flag("validate_uninstall"),
                    protect_clean: flag("protect_clean"),
                    protect_uninstall: flag("protect_uninstall"),
                }
            })
            .collect()
    }

    /// The `$HOME` and scratch root the fixture was captured under. The symlink rows only mean
    /// anything relative to the tree the capture built, so tests read the prefix instead of
    /// hardcoding one machine's layout.
    fn fixture_str(key: &str) -> String {
        Json::parse(RAILS)
            .expect("fixture parses")
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("fixture records {key}"))
            .to_string()
    }

    /// Rows whose verdict depends on the filesystem (symlink targets, `-d` probes) are only
    /// meaningful while the scratch tree the capture built still exists. Skip those rather than
    /// fail when it has been cleaned up, and count them so the test can insist it saw some.
    #[cfg(unix)]
    fn scratch_alive() -> bool {
        Path::new(&fixture_str("scratch")).is_dir()
    }

    #[cfg(unix)]
    #[test]
    fn agrees_with_the_oracles_own_validate_path_for_deletion_in_cleanup_mode() {
        let scratch = fixture_str("scratch");
        let live = scratch_alive();
        let all = rows();
        let mut checked = 0usize;
        let wrong: Vec<String> = all
            .iter()
            .filter(|r| live || !r.path.starts_with(&scratch))
            .inspect(|_| checked += 1)
            .filter(|r| {
                validate_path_for_deletion(&r.path, ProtectionMode::Cleanup).is_ok()
                    != r.validate_clean
            })
            .map(|r| {
                format!(
                    "  {:?}\n    oracle allows: {}, engine allows: {}",
                    r.path, r.validate_clean, !r.validate_clean
                )
            })
            .collect();
        assert!(
            checked > 1500,
            "fixture too thin to prove anything: {checked} rows checked"
        );
        assert!(
            wrong.is_empty(),
            "{} of {checked} captured paths disagree with the oracle:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    #[cfg(unix)]
    #[test]
    fn agrees_with_the_oracles_own_validate_path_for_deletion_in_uninstall_mode() {
        let scratch = fixture_str("scratch");
        let live = scratch_alive();
        let wrong: Vec<String> = rows()
            .into_iter()
            .filter(|r| live || !r.path.starts_with(&scratch))
            .filter(|r| {
                validate_path_for_deletion(&r.path, ProtectionMode::Uninstall).is_ok()
                    != r.validate_uninstall
            })
            .map(|r| {
                format!(
                    "  {:?}\n    oracle allows: {}",
                    r.path, r.validate_uninstall
                )
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "{} captured paths disagree with the oracle under MOLE_UNINSTALL_MODE=1:\n{}",
            wrong.len(),
            wrong.join("\n")
        );
    }

    #[test]
    fn the_fixture_covers_both_verdicts_and_the_two_modes_actually_differ() {
        // Guards the empty-spine failure RULEBOOK §3b describes, in three directions at once: a
        // fixture that were all-allow would pass the conformance tests above against a validator
        // that always returns Ok, and a fixture where the two modes never disagree would pass them
        // against a port that ignores `mode` entirely — which is exactly the defect being fixed.
        let all = rows();
        let refused = all.iter().filter(|r| !r.validate_clean).count();
        let allowed = all.len() - refused;
        assert!(
            refused > 100 && allowed > 100,
            "fixture spine too thin: {refused} refused / {allowed} allowed"
        );
        let mode_differs = all
            .iter()
            .filter(|r| r.validate_clean != r.validate_uninstall)
            .count();
        assert!(
            mode_differs > 50,
            "only {mode_differs} rows distinguish cleanup mode from uninstall mode — the fixture \
             cannot detect a port that ignores the mode"
        );
        let protect_differs = all
            .iter()
            .filter(|r| r.protect_clean != r.protect_uninstall)
            .count();
        assert!(
            protect_differs > 50,
            "only {protect_differs} rows distinguish should_protect_path's two modes"
        );
    }

    #[test]
    fn a_newline_in_a_path_is_refused_exactly_as_the_oracle_refuses_it() {
        // The live instance: `~/Library/Logs` on the capture machine really does contain
        // directories whose names embed a newline and a JSON fragment, all four of them in the
        // engine's own delete-list, and the oracle cannot delete any of them. Verdicts come from
        // the fixture, not from this test's own opinion.
        let newline_rows: Vec<Row> = rows()
            .into_iter()
            .filter(|r| r.path.contains('\n'))
            .collect();
        assert!(
            !newline_rows.is_empty(),
            "the fixture must carry at least one control-character path"
        );
        for r in &newline_rows {
            assert!(
                !r.validate_clean,
                "the oracle refuses {:?} and the fixture must say so",
                r.path
            );
            assert!(validate_path_for_deletion(&r.path, ProtectionMode::Cleanup).is_err());
        }
    }

    #[test]
    fn the_rosetta_target_the_planner_still_carries_is_dead_code_in_the_oracle() {
        // `plan.rs` transcribes `lib/clean/user.sh:2109`, whose `safe_clean` call can never delete
        // anything: `/Library/Apple/*` is critical, so the oracle refuses it every time. Pinned
        // here so the engine's behaviour tracks the oracle's rather than the target list's.
        let path = "/Library/Apple/usr/share/rosetta/rosetta_update_bundle";
        let row = rows().into_iter().find(|r| r.path == path);
        let row = row.unwrap_or_else(|| panic!("fixture must cover {path}"));
        assert!(!row.validate_clean, "the oracle refuses it");
        assert!(!row.validate_uninstall, "in both modes");
        assert!(validate_path_for_deletion(path, ProtectionMode::Cleanup).is_err());
        assert!(validate_path_for_deletion(path, ProtectionMode::Uninstall).is_err());
    }

    #[test]
    fn the_normalized_should_protect_path_recheck_is_what_catches_a_doubled_slash() {
        // `safe_clean` checks the RAW argument; this rail checks the `//`-collapsed one. Without
        // the second check `~/Library//Keychains/x` passes both of `safe_clean`'s filters and is
        // deleted. The oracle's answer is read from the fixture.
        let home = fixture_str("home");
        let doubled = format!("{home}/Library//Keychains/x");
        let row = rows().into_iter().find(|r| r.path == doubled);
        let row = row.unwrap_or_else(|| panic!("fixture must cover {doubled}"));
        assert!(!row.validate_clean, "the oracle refuses it");
        assert!(validate_path_for_deletion(&doubled, ProtectionMode::Cleanup).is_err());
        // …and the raw-string rail alone does NOT catch it, which is the whole point.
        assert!(!should_protect_path(&doubled, ProtectionMode::Cleanup));
    }

    #[cfg(unix)]
    #[test]
    fn an_allowlisted_private_path_survives_the_critical_check_above_it() {
        // `/private/var/db/*` is critical, but `/private/var/db/diagnostics` is explicitly allowed
        // first — an ordering the oracle depends on and a port can easily invert. Fixture-sourced.
        let all = rows();
        let allowed = all
            .iter()
            .find(|r| r.path == "/private/var/db/diagnostics")
            .expect("fixture must cover /private/var/db/diagnostics");
        let critical = all
            .iter()
            .find(|r| r.path == "/private/var/db")
            .expect("fixture must cover /private/var/db");
        assert!(
            allowed.validate_clean,
            "the oracle allows the diagnostics db"
        );
        assert!(!critical.validate_clean, "but refuses its parent");
        assert!(validate_path_for_deletion(&allowed.path, ProtectionMode::Cleanup).is_ok());
        assert!(validate_path_for_deletion(&critical.path, ProtectionMode::Cleanup).is_err());
    }

    #[test]
    fn normalization_matches_the_oracles_own_edge_cases() {
        // `_mole_normalize_deletion_policy_path`: `///` must collapse to `/`, not to the empty
        // string — the oracle's `[[ -n "$trimmed" ]] && … || …` fallback exists for exactly that.
        assert_eq!(normalize_deletion_policy_path("///"), "/");
        assert_eq!(normalize_deletion_policy_path("/a//b///c/"), "/a/b/c");
        assert_eq!(normalize_deletion_policy_path("/"), "/");
        assert_eq!(normalize_deletion_policy_path("/a/"), "/a");
    }

    /// The deletion rails are POSIX-shaped, and this pins BOTH halves of what that means, because
    /// the dangerous half is the one a future reader will not think to check.
    ///
    /// Half one: on a platform whose absolute paths are not `/`-rooted, the rails refuse outright,
    /// so nothing is ever removed there.
    ///
    /// Half two — the reason half one may not simply be deleted — is that every rail the guard
    /// sits in front of would let a Windows path through. Those rails are pure string predicates,
    /// so feeding them a `C:\...` path HERE, on unix, produces exactly the answers they produce on
    /// Windows; this is a real measurement of the Windows behaviour, not an analogy for it. If
    /// someone teaches the tables Windows vocabulary, these assertions fail and point at the guard
    /// — which is the intended way to find out that the guard is now the thing holding you back.
    #[test]
    fn the_deletion_rails_refuse_outright_on_a_platform_they_were_not_written_for() {
        let system32 = r"C:\Windows\System32";
        let traversal = r"C:\Users\me\..\..\Windows";
        let cache = r"C:\Users\me\AppData\Local\Temp\x\Library/Caches/com.example.foo";

        // Half two, measured first: NONE of the rails under the guard would stop these.
        for p in [system32, traversal, cache] {
            let norm = normalize_deletion_policy_path(p);
            assert!(
                !is_critical_deletion_path(&norm),
                "CRITICAL_DELETION_PATHS is POSIX-only, so it cannot be what protects {p}"
            );
            assert!(
                !should_protect_path(&norm, ProtectionMode::Cleanup),
                "should_protect_path's tables and its rsplit('/') basename both miss on {p}"
            );
            assert!(
                !should_protect_path(&norm, ProtectionMode::Uninstall),
                "…and the uninstall regime is strictly weaker still, on {p}"
            );
        }
        // The `..` rail splits on '/', so a backslash traversal is invisible to it.
        assert!(
            !traversal.split('/').any(|c| c == ".."),
            "the traversal rail cannot see a backslash-separated `..`, which is why the guard \
             above it has to refuse before this rail is ever consulted"
        );

        // Half one: the guard, and the fact that it is what does the refusing. Off unix the guard
        // fires FIRST and says so, so a caller reading the reason learns the platform is
        // unsupported rather than that its own absolute path was somehow relative. On unix the
        // same paths are refused by the ported absoluteness step instead, exactly as the oracle
        // refuses any relative argument — the guard is not what fires there.
        let expected_reason = if RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            "path must be absolute"
        } else {
            "deletion rails are POSIX-only"
        };
        for p in [system32, traversal, cache] {
            for mode in [ProtectionMode::Cleanup, ProtectionMode::Uninstall] {
                let why = validate_path_for_deletion(p, mode)
                    .expect_err("every rail-less platform path must be refused, in both modes");
                assert!(
                    why.contains(expected_reason),
                    "{p} must be refused with {expected_reason:?}, got {why:?}"
                );
            }
        }
    }
}
