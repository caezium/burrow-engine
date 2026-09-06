//! Cloud-file dehydration — the engine port of burrow-cli's macOS `evict` command.
//!
//! Evict the local copy of a cloud-backed file, freeing disk while keeping the cloud item
//! available on demand. macOS wraps `brctl evict`. Dry-run by default (reports each path's
//! existence, mutates nothing); `--apply` runs the eviction. The eviction is reversible — the
//! cloud provider re-downloads the file on next access — but it's still gated behind `--apply`.
//! The apply step takes an injectable runner so it's unit-testable without spawning `brctl`.

use std::path::PathBuf;

/// The paths to evict: every non-flag argument. Errors when no path is given. Whether to act is
/// the caller's `wants_apply` (the one `--apply` reader, `cli.rs`), not read here.
pub fn parse(args: &[String]) -> Result<Vec<String>, String> {
    let paths: Vec<String> = args
        .iter()
        .filter(|a| !a.starts_with("--"))
        .cloned()
        .collect();
    if paths.is_empty() {
        return Err("evict: needs at least one path".into());
    }
    Ok(paths)
}

use crate::json::escape as esc;

/// The `feature` a platform refusal of this command carries.
pub const EVICT_FEATURE: &str = "evict";

/// `Some(detail)` when this engine has no way to dehydrate a cloud file on `os`, `None` on macOS.
///
/// This is asked of BOTH halves of the command, and that is the whole point of it existing.
/// `--apply` already refused off macOS ([`execute_apply_json`]'s `cfg(not(target_os = "macos"))`
/// arm), but the dry run answered `ok:true` with a `would_evict` array whose every item carried
/// `supported:false` — honest per item, false at the top. A caller branches on `ok` BEFORE it
/// decodes anything (that is what the flag is for; `BurrowConductor` and every MCP tool read it
/// first), so a refusal shaped like a successful preview reads as a successful preview, and the
/// per-item honesty is never reached. burrow-cli's post-dedupe conductor had to paper over this
/// from outside — `engine::windows_refusal` refuses `evict` before dispatch and its own comment
/// calls it "an engine-side defect ... the right home for the fix is the engine's own platform
/// guards". This is that home; the interim refusal there can come out.
///
/// Refused off macOS rather than off Windows: `brctl` is a macOS binary, there is no Linux iCloud
/// provider either, and burrow-cli's provider-aware OneDrive path (`attrib +U -P`, deleted with
/// `src/evict.rs` in `3633c19`) was never ported here.
pub fn platform_refusal(os: &str) -> Option<&'static str> {
    if os == "macos" {
        return None;
    }
    Some(
        "cloud-file dehydration needs macOS brctl and this engine has no provider for any other \
         platform, so neither the preview nor --apply can answer here",
    )
}

/// Preview: report each path and whether it currently exists locally. Mutates nothing.
/// `{applied:false,would_evict:[{path,exists,supported}]}`. `supported` is true only on macOS.
///
/// The CLI arm no longer reaches this off macOS — [`platform_refusal`] turns that argv into a
/// failure envelope first — so in practice `supported` is now always `true` in emitted output.
/// The per-item flag is computed anyway rather than hardcoded: it is in the captured contract
/// (`evict.golden.json`), and a library caller invoking this serializer directly still deserves
/// the truthful value rather than one that is only correct because of a check made somewhere else.
pub fn dry_run_json(paths: &[String]) -> String {
    let supported = cfg!(target_os = "macos");
    let items = paths
        .iter()
        .map(|p| {
            format!(
                "{{\"path\":{},\"exists\":{},\"supported\":{}}}",
                esc(p),
                std::path::Path::new(p).exists(),
                supported
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"applied\":false,\"would_evict\":[{items}]}}")
}

/// One path's eviction result: whether `brctl evict` succeeded and any stderr it emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictResult {
    pub path: String,
    pub ok: bool,
    pub stderr: String,
}

/// Locate `brctl` (the macOS iCloud tool): `$BURROW_BRCTL` override, the fixed `/usr/bin/brctl`,
/// then a `PATH` scan. Errors if none is runnable.
///
/// All three positions ask [`crate::platform`] the one question that matters — "is there something
/// here I can SPAWN?" — rather than `.exists()`, which answers a different one: a directory named
/// `brctl` on `PATH` satisfies existence (and on unix even carries execute bits, since that is what
/// `x` means on a directory) and then fails inside `Command::new` with an error about permissions
/// that names nothing useful. Tightening the predicate cannot cost a working setup, because the
/// paths it now rejects are exactly the ones `Command::spawn` was going to refuse anyway.
///
/// The `PATH` half also used to join the BARE name, which resolves nothing on Windows. `brctl` is
/// macOS-only so that half is theory here — `execute_apply_json` is `cfg(target_os = "macos")` and
/// every other platform gets a classified `unsupported`, which is the intended contract and stays
/// exactly as it is. It is fixed anyway because a resolver that is correct only on the platform its
/// author was sitting on is the thing this pair of functions kept getting wrong.
///
/// Under elevation the override and `PATH` are not trusted — see
/// [`crate::platform::resolve_helper`]; the fixed `/usr/bin/brctl` still is.
pub fn resolve_brctl() -> Result<PathBuf, String> {
    crate::platform::resolve_helper("brctl", Some("BURROW_BRCTL"), &["/usr/bin/brctl"])
        .ok_or_else(|| "brctl not found (macOS iCloud tool); set BURROW_BRCTL".to_string())
}

/// Evict each path, delegating the actual command to `run` (real: `brctl evict <path>`).
/// The runner returns `(ok, stderr)` per path; injectable so this is testable without brctl.
pub fn apply<F>(paths: &[String], mut run: F) -> Vec<EvictResult>
where
    F: FnMut(&str) -> (bool, String),
{
    paths
        .iter()
        .map(|p| {
            let (ok, stderr) = run(p);
            EvictResult {
                path: p.clone(),
                ok,
                stderr,
            }
        })
        .collect()
}

/// The real macOS runner: `brctl evict <path>`, returning (success, trimmed stderr).
#[cfg(target_os = "macos")]
fn run_brctl_evict(brctl: &std::path::Path, path: &str) -> (bool, String) {
    match std::process::Command::new(brctl)
        .args(["evict", path])
        .output()
    {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ),
        Err(e) => (false, format!("failed to run brctl evict {path}: {e}")),
    }
}

/// Run the eviction on macOS and serialize the results. Off macOS, or if brctl is missing,
/// returns an Err with a diagnostic (the caller wraps it as an error envelope).
pub fn execute_apply_json(paths: &[String]) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let brctl = resolve_brctl()?;
        let results = apply(paths, |p| run_brctl_evict(&brctl, p));
        Ok(apply_to_json(&results))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = paths;
        Err("evict --apply is macOS-only (needs brctl)".into())
    }
}

/// Serialize eviction results: `{applied:true,evicted:[{path,ok,stderr}]}`.
pub fn apply_to_json(results: &[EvictResult]) -> String {
    let items = results
        .iter()
        .map(|r| {
            format!(
                "{{\"path\":{},\"ok\":{},\"stderr\":{}}}",
                esc(&r.path),
                r.ok,
                esc(&r.stderr)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"applied\":true,\"evicted\":[{items}]}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract fixture bundled for standalone CI. `scripts/check_fixtures.py` verifies
    /// its approved public contents; see `FIXTURE_PROVENANCE.md` for the captured authority.
    const GOLDEN: &str = include_str!("evict.golden.json");

    fn golden() -> crate::json::Json {
        crate::json::Json::parse(GOLDEN).expect("vendored golden must be valid JSON")
    }

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parse_keeps_paths_and_drops_flags() {
        let paths = parse(&v(&["a", "--apply", "b"])).unwrap();
        assert_eq!(paths, v(&["a", "b"]), "--apply is not a path");
        let paths = parse(&v(&["only"])).unwrap();
        assert_eq!(paths, v(&["only"]));
    }

    #[test]
    fn parse_requires_path() {
        assert!(parse(&v(&["--apply"])).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn dry_run_reports_existence_and_never_applies() {
        let dir = std::env::temp_dir().join(format!("burrow_evict_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let here = dir.join("real.bin");
        std::fs::write(&here, "x").unwrap();
        let gone = dir.join("missing.bin");
        let j = dry_run_json(&v(&[here.to_str().unwrap(), gone.to_str().unwrap()]));
        assert!(j.contains("\"applied\":false"));
        assert!(j.contains("\"exists\":true"));
        assert!(j.contains("\"exists\":false"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_delegates_to_runner_per_path() {
        // Fake runner: "bad" paths fail with a stderr; everything else succeeds.
        let results = apply(&v(&["ok.bin", "bad.bin"]), |p| {
            if p.contains("bad") {
                (false, "brctl: no such file".into())
            } else {
                (true, String::new())
            }
        });
        assert_eq!(results.len(), 2);
        assert!(results[0].ok);
        assert!(!results[1].ok);
        assert_eq!(results[1].stderr, "brctl: no such file");
    }

    #[test]
    // check_tests: no-golden — apply_to_json's applied/evicted{path,ok,stderr} shape has no
    // oracle to anchor to, and none can exist: evict.golden.json (see its provenance file)
    // intentionally covers ONLY the dry-run path, because "a golden must never be captured by
    // doing something destructive," and a real `brctl evict` is exactly that. There is also no
    // Swift decoder to fall back on for this shape — evict does not appear in MoActions.swift's
    // argv table, and MCP.swift documents it as a mutating sibling deliberately kept out of that
    // surface. So neither oracle this migration recognizes exists for --apply's output today.
    // This test is downgraded from a hand-typed string comparison to proving apply()'s results
    // round-trip through apply_to_json() structurally — internal consistency, not contract
    // conformance.
    fn apply_json_shape() {
        let results = apply(&v(&["f"]), |_| (true, String::new()));
        let parsed = crate::json::Json::parse(&apply_to_json(&results))
            .expect("apply_to_json must emit valid JSON");
        assert_eq!(
            parsed.get("applied").and_then(crate::json::Json::as_bool),
            Some(true)
        );
        let evicted = parsed
            .get("evicted")
            .and_then(crate::json::Json::as_array)
            .expect("must carry an evicted array");
        assert_eq!(evicted.len(), 1);
        assert_eq!(
            evicted[0].get("path").and_then(crate::json::Json::as_str),
            Some("f")
        );
        assert_eq!(
            evicted[0].get("ok").and_then(crate::json::Json::as_bool),
            Some(true)
        );
        assert_eq!(
            evicted[0].get("stderr").and_then(crate::json::Json::as_str),
            Some("")
        );
    }

    #[test]
    fn json_escaping_is_valid() {
        let results = apply(&v(&["a\"b"]), |_| (false, "line\nbreak".into()));
        let j = apply_to_json(&results);
        assert!(j.contains("\\\""), "quote escaped: {j}");
        assert!(j.contains("\\n"), "newline escaped: {j}");
    }

    /// The preview and the apply must give the SAME answer about whether this platform can evict,
    /// and off macOS that answer is no. They used to disagree: `execute_apply_json` returned an
    /// `Err` while `dry_run_json` returned a perfectly well-formed `{applied:false, would_evict:…}`
    /// that the CLI wrapped `ok:true` — so "preview then apply" went success, then failure, on an
    /// unchanged machine.
    ///
    /// Both branches of [`platform_refusal`] run on every host because it takes the OS as an
    /// argument, and the macOS branch is additionally anchored to the capture: `evict.golden.json`
    /// is the real oracle's answer for the dry run, and its `supported:true` is precisely the
    /// claim that must survive on the platform that is NOT refused.
    #[test]
    fn the_preview_and_the_apply_agree_about_the_platform() {
        assert_eq!(
            platform_refusal("macos"),
            None,
            "macOS has brctl — refusing there would delete the only working form of the command"
        );
        for os in ["windows", "linux"] {
            let detail = platform_refusal(os)
                .unwrap_or_else(|| panic!("{os} has no brctl and no ported provider"));
            assert!(
                detail.contains("brctl"),
                "{os}: the refusal must name the missing tool, got {detail:?}"
            );
            assert!(
                detail.contains("--apply"),
                "{os}: the refusal must say it covers the apply too, got {detail:?}"
            );
        }

        // The macOS half, against the golden's OWN recorded fixture rather than a retyped shape:
        // rebuild a file at the path the capture names, run the real serializer over it, and
        // require every key the golden carries to come back with the golden's value. `supported`
        // is the load-bearing one — it is `true` in the capture, and the whole defect was that a
        // `false` here still rode inside an `ok:true` envelope.
        let golden = golden();
        let item = golden
            .get("would_evict")
            .and_then(crate::json::Json::as_array)
            .and_then(|a| a.first())
            .expect("golden.would_evict must carry a row (RULEBOOK §3b)");
        let fixture = item
            .get("path")
            .and_then(crate::json::Json::as_str)
            .expect("golden row must name its fixture path");
        assert_eq!(
            item.get("exists").and_then(crate::json::Json::as_bool),
            Some(true),
            "the capture's fixture existed; a rebuild that does not would prove nothing"
        );

        // Rebuilt in a scratch dir, not at the capture's `/tmp` path: the golden's `path` is the
        // one field that cannot be reproduced (and `check_tests.py` would not care if it were),
        // so it is compared by SHAPE while every other key is compared by value.
        let dir = std::env::temp_dir().join(format!("burrow_evict_golden_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let leaf = std::path::Path::new(fixture)
            .file_name()
            .expect("fixture path must have a leaf");
        let here = dir.join(leaf);
        std::fs::write(
            &here,
            b"an ordinary local file, exactly as the capture used\n",
        )
        .unwrap();

        let engine = crate::json::Json::parse(&dry_run_json(&v(&[here.to_str().unwrap()])))
            .expect("dry_run_json must emit valid JSON");
        assert_eq!(
            engine.get("applied"),
            golden.get("applied"),
            "the preview must still be a preview"
        );
        let row = engine
            .get("would_evict")
            .and_then(crate::json::Json::as_array)
            .and_then(|a| a.first())
            .expect("engine must report the path it was handed");
        let crate::json::Json::Object(fields) = item else {
            panic!("golden row must be a JSON object");
        };
        for key in fields.keys() {
            if key == "path" {
                assert_eq!(
                    row.get("path").and_then(crate::json::Json::as_str),
                    here.to_str(),
                    "the path is echoed back exactly as passed"
                );
                continue;
            }
            if key == "supported" && platform_refusal(std::env::consts::OS).is_some() {
                // The capture is a macOS capture, and `supported` is the ONE field whose value is
                // a property of the host rather than of the fixture. Off macOS the honest value is
                // the opposite of the golden's — and the point of this branch is that the opposite
                // value is now unreachable through the CLI: the arm refuses before it serializes.
                // `cli.rs`'s `the_evict_preview_refuses_off_macos_instead_of_previewing_a_refusal`
                // is the half that proves the refusal actually fires.
                assert_eq!(
                    row.get("supported").and_then(crate::json::Json::as_bool),
                    Some(false),
                    "off macOS the per-item flag stays honest; it is the ENVELOPE that had to change"
                );
                continue;
            }
            assert_eq!(
                row.get(key.as_str()),
                item.get(key.as_str()),
                "engine's {key} must match the capture's {key} over the capture's own fixture"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
