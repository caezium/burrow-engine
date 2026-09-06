//! `sentinel` — which `.app` bundles are sitting in the Trash right now, as uninstall-leftover
//! candidates. The engine port of burrow-cli's `sentinel` (its `src/sentinel.rs` + the
//! `run_sentinel` arm at `src/main.rs:524-579`).
//!
//! This is a CONDUCTOR-NATIVE command: burrow-cli's `engine_for` (`src/main.rs:968-977`) returns
//! `"native"` for it, so it never reached the bash engine and the whole of it is those two files.
//! It is also the smallest possible read: one `read_dir`, a suffix test, a sort. Nothing here
//! deletes, moves, or even opens a file.
//!
//! ## What is deliberately NOT ported: `--watch`
//!
//! The oracle also has a poll-based daemon mode (`--watch [--interval-ms N] [--max-ticks N]`,
//! `main.rs:540-575`) that streams one NDJSON `trashed_app` event per newly-arrived bundle and
//! loops forever by default. It is refused here rather than half-implemented, listed in
//! `REFUSED_ON_PURPOSE` in `cli.rs` with the same reasoning the engine already applies to
//! `status --watch`: a flag that changes the output contract must not be accepted and ignored.
//! Nothing in the app sends it — `MCP.swift:1283-1288` builds `sentinel [trashdir]` and nothing
//! else — and burrow-cli's own consumer of watch mode is a launchd template that runs the
//! conductor, not this binary.

use std::path::Path;

/// The `feature` a refusal of the INFERRED trash carries.
///
/// It names the inference, not the command, because only the inference is macOS-specific:
/// `sentinel <dir>` scans exactly the directory it was handed, on every platform, and must keep
/// doing so. A `feature` of `"sentinel"` would tell a caller the whole command is gone here, and
/// the caller would be right to believe it and stop asking.
pub const DEFAULT_TRASH_FEATURE: &str = "sentinel default trash";

/// `Some(detail)` when `<home>/.Trash` is not where `os` keeps deleted files, `None` when it is.
///
/// The oracle infers that path unconditionally (`burrow-cli/src/main.rs:526-530`,
/// `.unwrap_or_else(|| format!("{}/.Trash", platform::home_dir_string()))`), and off macOS that
/// is a directory nobody has: [`scan_trash`] swallows the failed `read_dir` by design, so the
/// command answers `ok:true, count:0` — "your Trash holds no leftover apps", about a Recycle Bin
/// it never opened. An empty successful scan has to keep meaning "I looked and found nothing", or
/// it means nothing at all.
///
/// Refused on every non-macOS platform rather than on Windows alone, which is where the oracle
/// drew the line. Its own guard (`run_sentinel`, `main.rs:270`, `platform::is_windows() &&
/// args.iter().all(|a| a.starts_with("--"))`) is Windows-scoped because burrow-cli targets two
/// platforms and Linux is not one of them — this engine builds on three, and freedesktop keeps
/// its trash at `~/.local/share/Trash/files`, so `~/.Trash` is exactly as fictional on Linux as
/// it is on Windows. Extending the guard costs a Linux caller nothing it had: there was no
/// answer there to lose, only a `count:0` that was never measured.
///
/// Note what is NOT refused. The oracle's guard fires only when there is no positional
/// (`args.iter().all(…starts_with("--"))`) and this mirrors that distinction exactly: an explicit
/// directory is scanned wherever it is, because a directory of `.app`-suffixed entries is a
/// perfectly answerable question on any filesystem, and burrow-cli's own docs record
/// `sentinel --watch <dir>` as working on Windows for the same reason.
pub fn default_trash_refusal(os: &str) -> Option<&'static str> {
    if os == "macos" {
        return None;
    }
    Some(
        "the inferred Trash is macOS's <home>/.Trash; no Recycle Bin or freedesktop trash \
         reader is implemented, so an empty scan here would not mean an empty trash. Pass the \
         directory explicitly — `sentinel <dir>` is served on every platform.",
    )
}

/// A `.app` bundle found in the Trash. `name` is the bundle name with `.app` stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashedApp {
    pub name: String,
    pub path: String,
}

/// List the `.app` entries directly inside a Trash directory, sorted by name.
///
/// Three behaviours here are load-bearing and were transcribed rather than reasoned about, because
/// each has an obvious-looking "improvement" that would diverge:
///
/// - **No `is_dir` check.** The oracle tests the NAME only, so a plain file called `Zeta.app` is
///   reported. Filtering to directories looks more correct and would silently drop rows.
/// - **Non-recursive.** `read_dir`, not a walk: only entries directly in the Trash.
/// - **An unreadable directory is not an error.** `read_dir` failing yields an empty list and a
///   SUCCESS response — measured against the oracle: `sentinel /tmp/definitely_absent_trash` and
///   `sentinel <a regular file>` both answer `ok:true, count:0, exit 0`. This is the opposite of
///   `rules`, which fails on a directory it cannot read; the two commands genuinely differ.
pub fn scan_trash(dir: &Path) -> Vec<TrashedApp> {
    let mut apps = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if let Some(app) = n.strip_suffix(".app") {
                apps.push(TrashedApp {
                    name: app.to_string(),
                    path: e.path().to_string_lossy().into_owned(),
                });
            }
        }
    }
    apps.sort_by(|a, b| a.name.cmp(&b.name));
    apps
}

use crate::json::escape as esc;

/// The `sentinel` payload: `{count, trash, trashed_apps:[{name,path}]}`.
///
/// `trash` echoes the directory that was scanned, exactly as the caller spelled it — it is not
/// canonicalised, because the oracle does not canonicalise it either and an echo that does not
/// match the argument is how `orphans` came to report a scan of a path it was never handed
/// (RULEBOOK §4).
pub fn report_json(dir: &str, apps: &[TrashedApp]) -> String {
    let rows = apps
        .iter()
        .map(|a| format!("{{\"name\":{},\"path\":{}}}", esc(&a.name), esc(&a.path)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"count\":{},\"trash\":{},\"trashed_apps\":[{}]}}",
        apps.len(),
        esc(dir),
        rows
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    /// The contract fixture bundled for standalone CI. `scripts/check_fixtures.py` verifies
    /// its approved public contents; see `FIXTURE_PROVENANCE.md` for the captured authority.
    const GOLDEN: &str = include_str!("sentinel.golden.json");

    fn golden() -> Json {
        Json::parse(GOLDEN).expect("vendored golden must be valid JSON")
    }

    /// Rebuild the golden's own fixture in a scratch directory: every `trashed_apps` entry becomes
    /// a real filesystem entry, plus the two negatives the golden proves are excluded by NOT
    /// listing them. `Zeta.app` is created as a FILE because that is what it is in the fixture
    /// (`make_fixtures.sh`) and that is the case a directory filter would break.
    fn rebuild_fixture(dir: &Path, apps: &[(String, String)]) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        for (name, path) in apps {
            let leaf = Path::new(path).file_name().unwrap();
            let target = dir.join(leaf);
            // Mirror the fixture: "Zeta.app" is a regular file, everything else a bundle dir.
            if name == "Zeta" {
                std::fs::write(&target, b"not a bundle, but the name ends in .app\n").unwrap();
            } else {
                std::fs::create_dir_all(&target).unwrap();
            }
        }
        std::fs::create_dir_all(dir.join("NotAnApp")).unwrap();
        std::fs::write(dir.join("notes.txt"), b"plain file\n").unwrap();
    }

    fn golden_apps() -> Vec<(String, String)> {
        golden()
            .get("trashed_apps")
            .and_then(Json::as_array)
            .expect("golden.trashed_apps must be an array")
            .iter()
            .map(|a| {
                (
                    a.get("name")
                        .and_then(Json::as_str)
                        .expect("name")
                        .to_string(),
                    a.get("path")
                        .and_then(Json::as_str)
                        .expect("path")
                        .to_string(),
                )
            })
            .collect()
    }

    /// RUN the real scanner over a rebuild of the golden's own fixture and require the result to
    /// reproduce the golden's rows — names, order, and count. Every expected value is read out of
    /// `sentinel.golden.json` at run time (RULEBOOK §3e); nothing below is transcribed, so
    /// re-capturing the golden moves this test with it.
    ///
    /// The scratch directory differs from `/tmp/sentinel_fixture`, so `path` cannot be compared
    /// verbatim — the golden's LEAF names are compared instead, which is the part of the path the
    /// scanner actually produces. `report_json_matches_the_golden` below covers the full path
    /// strings by feeding the golden's own values back through the serializer.
    #[test]
    fn scanning_the_goldens_fixture_reproduces_the_goldens_rows() {
        let expected = golden_apps();
        assert!(
            !expected.is_empty(),
            "golden.trashed_apps is empty — this test can no longer prove anything (RULEBOOK §3b)"
        );
        let dir = std::env::temp_dir().join(format!("burrow_sentinel_{}", std::process::id()));
        rebuild_fixture(&dir, &expected);

        let found = scan_trash(&dir);
        let names: Vec<&str> = found.iter().map(|a| a.name.as_str()).collect();
        let want: Vec<&str> = expected.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, want, "names and SORT ORDER must match the golden");
        assert_eq!(
            found.len(),
            golden().get("count").and_then(Json::as_u64).expect("count") as usize,
            "count must match the golden's"
        );
        // The negatives: the fixture also contains NotAnApp/ and notes.txt, and the golden proves
        // they are excluded by not listing them.
        for a in &found {
            assert!(a.path.ends_with(".app"), "non-.app entry leaked in: {a:?}");
        }
        // Every reported path must be the scanned directory's own child, spelled as passed.
        for a in &found {
            assert!(
                a.path.starts_with(&dir.to_string_lossy().into_owned()),
                "path must be rooted at the directory handed in: {a:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The serialization contract, anchored to the golden: feed the golden's OWN rows back through
    /// `report_json` and require every key the golden has to come out equal. This is the half that
    /// pins the full path strings and the `trash` echo, which the fixture-rebuild test cannot.
    #[test]
    fn report_json_matches_the_golden() {
        let golden = golden();
        let dir = golden
            .get("trash")
            .and_then(Json::as_str)
            .expect("golden.trash");
        let apps: Vec<TrashedApp> = golden_apps()
            .into_iter()
            .map(|(name, path)| TrashedApp { name, path })
            .collect();

        let engine = Json::parse(&report_json(dir, &apps)).expect("report_json must emit JSON");
        let Json::Object(top) = &golden else {
            panic!("golden root must be a JSON object");
        };
        for key in top.keys() {
            assert_eq!(
                engine.get(key.as_str()),
                golden.get(key.as_str()),
                "engine's {key} must match the golden's {key} verbatim"
            );
        }
    }

    /// An unreadable directory is a SUCCESSFUL empty scan, not a failure — measured against the
    /// oracle, which answers `ok:true, count:0, exit 0` for both a missing path and a regular file.
    /// `rules` behaves the opposite way on the same input, so this is the kind of asymmetry a port
    /// "tidies up" by accident.
    //
    // check_tests: no-golden — a golden captures ONE fixture's answer; this pins the behaviour on
    // inputs a fixture cannot be (a path that does not exist). The oracle measurements are
    // recorded in sentinel.golden.provenance.txt.
    #[test]
    fn an_unreadable_directory_is_an_empty_scan_not_an_error() {
        let missing =
            std::env::temp_dir().join(format!("burrow_sentinel_absent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        assert!(scan_trash(&missing).is_empty());
        assert!(report_json(&missing.to_string_lossy(), &[]).contains("\"count\":0"));

        let file =
            std::env::temp_dir().join(format!("burrow_sentinel_file_{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        assert!(
            scan_trash(&file).is_empty(),
            "a regular file scans as empty"
        );
        let _ = std::fs::remove_file(&file);
    }

    /// Names are escaped, not concatenated: a bundle whose name contains a quote or a backslash
    /// must still produce parseable JSON. `scan_trash` reads whatever the filesystem holds, so the
    /// serializer is the only thing standing between an odd filename and a corrupt envelope.
    //
    // check_tests: no-golden — an escaping test needs a name no real fixture should contain.
    #[test]
    fn odd_names_stay_valid_json() {
        let apps = vec![TrashedApp {
            name: "Quote\"And\\Slash".into(),
            path: "/t/Quote\"And\\Slash.app".into(),
        }];
        let out = report_json("/t", &apps);
        let parsed = Json::parse(&out).expect("must stay parseable");
        assert_eq!(
            parsed
                .get("trashed_apps")
                .and_then(|a| a.at(0))
                .and_then(|a| a.get("name"))
                .and_then(Json::as_str),
            Some("Quote\"And\\Slash")
        );
    }

    /// The INFERENCE is refused off macOS; the SCAN never is. Both halves, because refusing too
    /// much is the failure mode a platform guard reaches for by default and it would cost Windows
    /// and Linux a command that genuinely works there.
    ///
    /// Runs the same decision for every OS on every host — [`default_trash_refusal`] takes the OS
    /// as an argument rather than reading `cfg!` — so the Windows answer is exercised on a Mac and
    /// the macOS answer on Windows CI, instead of each platform testing only its own branch.
    //
    // check_tests: no-golden — a golden records what the oracle ANSWERED on macOS; this pins what
    // must not be answered elsewhere, which no capture can contain. The oracle's own guard is
    // quoted in `default_trash_refusal`'s doc comment.
    #[test]
    fn the_inferred_trash_is_refused_off_macos_and_the_scan_itself_never_is() {
        assert_eq!(
            default_trash_refusal("macos"),
            None,
            "macOS is where <home>/.Trash is real — refusing there would delete the command"
        );
        for os in ["windows", "linux", "freebsd"] {
            let detail = default_trash_refusal(os)
                .unwrap_or_else(|| panic!("{os} has no <home>/.Trash, so the inference must fail"));
            assert!(
                detail.contains("<home>/.Trash"),
                "{os}: the refusal must name the path it declined to invent, got {detail:?}"
            );
            assert!(
                detail.contains("sentinel <dir>"),
                "{os}: the refusal must point at the form that DOES work here, got {detail:?}"
            );
        }
        assert_eq!(
            DEFAULT_TRASH_FEATURE, "sentinel default trash",
            "the feature names the inference; naming it `sentinel` would tell a caller the whole \
             command is unavailable, which is the over-refusal this test exists to prevent"
        );

        // The other half, measured rather than argued: the scanner has no platform vocabulary at
        // all. Given a directory it reproduces the golden's rows wherever it runs, which is why
        // only the inference could ever be the thing refused.
        let expected = golden_apps();
        assert!(
            !expected.is_empty(),
            "golden.trashed_apps is empty — this half proves nothing (RULEBOOK §3b)"
        );
        let dir =
            std::env::temp_dir().join(format!("burrow_sentinel_any_os_{}", std::process::id()));
        rebuild_fixture(&dir, &expected);
        let found = scan_trash(&dir);
        assert_eq!(
            found.len(),
            golden().get("count").and_then(Json::as_u64).expect("count") as usize,
            "the scan is platform-free: the golden's count must come back on any host"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
