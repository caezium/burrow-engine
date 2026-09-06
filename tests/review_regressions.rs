#[cfg(unix)]
use burrow_engine::{clean, platform};
use burrow_engine::{cli, rules};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(unix)]
struct Scratch(PathBuf);
#[cfg(unix)]
impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "burrow_engine_review_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir.canonicalize().unwrap())
    }
}
#[cfg(unix)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn candidate(path: &Path, size: u64) -> clean::plan::CleanCandidate {
    clean::plan::CleanCandidate {
        path: path.to_str().unwrap().into(),
        label: "fixture".into(),
        size,
    }
}

#[cfg(unix)]
#[test]
fn crash_report_cleanup_keeps_recent_reports_and_directories() {
    use clean::plan::{plan_clean, PlanMode, UNIVERSAL_TARGETS};
    use std::time::{Duration, SystemTime};
    let dir = Scratch::new();
    let reports = dir.0.join("Library/Application Support/CrashReporter");
    let nested = reports.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let old = nested.join("old.crash");
    let recent = nested.join("recent.crash");
    fs::write(&old, b"old").unwrap();
    fs::write(&recent, b"recent").unwrap();
    fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_times(
            fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(32 * 86_400)),
        )
        .unwrap();
    let target = UNIVERSAL_TARGETS
        .iter()
        .find(|t| t.path.ends_with("/CrashReporter"))
        .unwrap();
    let plan = plan_clean(
        std::slice::from_ref(target),
        dir.0.to_str().unwrap(),
        &[],
        PlanMode::Apply,
    );
    assert_eq!(
        plan.len(),
        1,
        "only old regular files are candidates: {plan:?}"
    );
    assert_eq!(plan[0].path, old.to_str().unwrap());
    let out =
        clean::execute::execute_clean(&plan, &[], true, clean::protect::ProtectionMode::Cleanup);
    assert_eq!(out.removed.len(), 1);
    assert!(nested.is_dir() && recent.exists());
    let bypass = clean::execute::execute_clean(
        &[candidate(&reports, 6), candidate(&recent, 6)],
        &[],
        true,
        clean::protect::ProtectionMode::Cleanup,
    );
    assert_eq!(bypass.protected.len(), 2);
    assert!(recent.exists());
}

#[test]
fn json_nesting_is_bounded_before_the_process_stack_is_exhausted() {
    let input = format!("{}0{}", "[".repeat(1024), "]".repeat(1024));
    assert!(burrow_engine::json::Json::parse(&input).is_err());
}

#[cfg(unix)]
#[test]
fn deletion_checks_protected_and_whitelisted_symlink_ancestors() {
    use clean::protect::ProtectionMode;
    for protected_by_table in [true, false] {
        let dir = Scratch::new();
        let kept = dir.0.join(if protected_by_table {
            "Library/Keychains"
        } else {
            "kept"
        });
        fs::create_dir_all(&kept).unwrap();
        fs::write(kept.join("artifact"), b"keep me").unwrap();
        let alias = dir.0.join("cache");
        std::os::unix::fs::symlink(&kept, &alias).unwrap();
        let whitelist = if protected_by_table {
            vec![]
        } else {
            vec![kept.to_str().unwrap()]
        };
        let out = clean::execute::execute_clean(
            &[candidate(&alias.join("artifact"), 7)],
            &whitelist,
            true,
            ProtectionMode::Cleanup,
        );
        assert!(
            kept.join("artifact").exists(),
            "protected data removed: {out:?}"
        );
        assert_eq!(out.protected.len(), 1, "{out:?}");
    }
}

#[cfg(unix)]
#[test]
fn exact_plan_rechecks_ancestor_symlinks_after_review() {
    use clean::plan_file::{PlanFile, Verdict};
    let dir = Scratch::new();
    let cache = dir.0.join("Library/Caches/example");
    let kept = dir.0.join("Documents");
    fs::create_dir_all(&cache).unwrap();
    fs::create_dir_all(&kept).unwrap();
    fs::write(cache.join("artifact"), b"cache").unwrap();
    fs::write(kept.join("artifact"), b"keep me").unwrap();
    let plan_path = dir.0.join("plan.txt");
    fs::write(&plan_path, cache.join("artifact").to_str().unwrap()).unwrap();
    let targets = &[clean::plan::CleanTarget {
        path: "~/Library/Caches/*",
        label: "cache",
    }];
    let plan = PlanFile::read(
        plan_path.to_str().unwrap(),
        targets,
        dir.0.to_str().unwrap(),
        &[],
    )
    .unwrap();
    assert!(matches!(plan.entries[0].verdict, Verdict::Candidate(_)));
    fs::remove_dir_all(&cache).unwrap();
    std::os::unix::fs::symlink(&kept, &cache).unwrap();
    let out = plan.execute(
        &[],
        true,
        |_| {},
        |p, _| {
            fs::remove_file(p).map_err(|e| e.to_string())?;
            Ok(clean::execute::Removal::Removed)
        },
    );
    assert!(
        kept.join("artifact").exists(),
        "reviewed path was redirected: {out:?}"
    );
    assert_eq!(out.protected.len(), 1);
    let reread = PlanFile::read(
        plan_path.to_str().unwrap(),
        targets,
        dir.0.to_str().unwrap(),
        &[],
    )
    .unwrap();
    assert!(matches!(reread.entries[0].verdict, Verdict::Refused { .. }));
}

#[cfg(unix)]
#[test]
fn child_then_parent_does_not_count_the_same_bytes_twice() {
    let dir = Scratch::new();
    let cache = dir.0.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let child = cache.join("blob");
    fs::write(&child, [b'x'; 32]).unwrap();
    let out = clean::execute::execute_clean(
        &[candidate(&child, 32), candidate(&cache, 32)],
        &[],
        true,
        clean::protect::ProtectionMode::Cleanup,
    );
    assert_eq!(out.freed_bytes, 32, "{out:?}");
}

#[cfg(unix)]
#[test]
fn a_surviving_hardlink_prevents_freed_byte_credit() {
    let dir = Scratch::new();
    let first = dir.0.join("first");
    let second = dir.0.join("second");
    fs::write(&first, [b'x'; 32]).unwrap();
    fs::hard_link(&first, &second).unwrap();
    let out = clean::execute::execute_clean(
        &[candidate(&first, 32)],
        &[],
        true,
        clean::protect::ProtectionMode::Cleanup,
    );
    assert_eq!(out.freed_bytes, 0, "hardlink still retains bytes: {out:?}");
    assert_eq!(fs::read(&second).unwrap().len(), 32);
}

#[test]
fn unknown_conditions_are_not_silently_dropped() {
    let rule = r#"{"schema":"burrow.rules/v1","app":{"bundle_ids":["com.example.app"],"name":"example"},"rules":[{"id":"cache","category":"cache","risk":"safe","recommend":true,"targets":[{"path":"/tmp/cache","when":{"min_size_bytes":0,"max_age_days":30}}],"action":{"type":"delete"}}],"provenance":{"source":"test"}}"#;
    assert!(
        rules::parse(rule).is_err(),
        "an unknown restriction became an unconditional match"
    );
}

#[test]
fn missing_keep_value_cannot_swallow_apply() {
    let args = ["dupes", "remove", "/tmp/fixture", "--keep", "--apply"].map(str::to_string);
    let (output, code) = cli::dispatch(&args);
    assert_eq!(code, 2, "{output}");
    assert!(output.contains("--keep"));
    assert!(burrow_engine::dupes::plan("remove", &args[2..], true).is_err());
}

#[cfg(unix)]
#[test]
fn duplicate_keep_roots_protect_their_symlink_destinations() {
    let dir = Scratch::new();
    let kept = dir.0.join("kept");
    let copy = dir.0.join("other");
    fs::create_dir_all(&kept).unwrap();
    fs::write(kept.join("blob"), b"same").unwrap();
    fs::write(&copy, b"same").unwrap();
    let alias = dir.0.join("alias");
    std::os::unix::fs::symlink(&kept, &alias).unwrap();
    let report = format!(
        r#"{{"groups":[{{"files":["{}","{}"]}}]}}"#,
        copy.display(),
        kept.join("blob").display()
    );
    let (filtered, _) =
        burrow_engine::dupes::filter_report(&report, &[alias.to_str().unwrap().to_string()])
            .unwrap();
    let parsed = burrow_engine::json::Json::parse(&filtered).unwrap();
    let survivor = parsed
        .get("groups")
        .unwrap()
        .at(0)
        .unwrap()
        .get("files")
        .unwrap()
        .at(0)
        .unwrap()
        .as_str()
        .unwrap();
    assert_eq!(
        survivor,
        kept.join("blob").to_str().unwrap(),
        "keep path must be the retained copy"
    );

    // A stale report can name a child that vanished under a symlink. Its surviving
    // physical parent must still match the reference folder's keep rule.
    let missing_report = format!(
        r#"{{"groups":[{{"files":[{},{}]}}]}}"#,
        burrow_engine::json::Json::String(alias.join("missing-first").to_str().unwrap().into())
            .to_json_string(),
        burrow_engine::json::Json::String(alias.join("missing-second").to_str().unwrap().into())
            .to_json_string()
    );
    let (_, actionable) =
        burrow_engine::dupes::filter_report(&missing_report, &[kept.to_str().unwrap().to_string()])
            .unwrap();
    assert_eq!(actionable, 0, "missing alias children remain protected");
}

#[test]
fn json_reader_rejects_invalid_number_and_string_grammar() {
    for invalid in ["01", "-01", "1.", "1.e2", "1e999", "\"unescaped\nnewline\""] {
        assert!(
            burrow_engine::json::Json::parse(invalid).is_err(),
            "invalid JSON accepted: {invalid:?}"
        );
    }
}

#[test]
fn out_of_range_watch_interval_returns_an_error_without_panicking() {
    let args = ["status", "--watch", "--interval", "1e100"].map(str::to_string);
    let (_, code) = cli::dispatch(&args);
    assert_eq!(code, 2);
}

#[cfg(unix)]
#[test]
fn subprocess_deadline_includes_stdout_inherited_by_descendants() {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let result = platform::run_command_checked(
        "/bin/sh",
        &["-c", "sleep 2 & exit 0"],
        Duration::from_millis(100),
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "stdout wait exceeded the deadline"
    );
    assert!(matches!(result, Err(platform::CommandFailure::TimedOut(_))));
}

#[cfg(unix)]
#[test]
fn report_input_and_tool_output_are_pumped_concurrently() {
    let report = "x".repeat(512 * 1024);
    let out = burrow_engine::dupes::system_fclones(
        Path::new("/bin/sh"),
        &[
            "-c",
            "/bin/dd if=/dev/zero bs=65536 count=8 2>/dev/null; /bin/cat >/dev/null",
        ],
        Some(&report),
    )
    .unwrap();
    assert_eq!(out.len(), report.len());
}

#[cfg(unix)]
#[test]
fn elevated_children_use_the_requested_home_and_trusted_path() {
    if let Ok(expected) = std::env::var("BURROW_REVIEW_EXPECT_HOME") {
        let out = platform::run_command_checked(
            "/bin/sh",
            &[
                "-c",
                "printf '%s\\n' \"$HOME\"; command -v burrow_review_untrusted_tool || :",
            ],
            std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(out, format!("{expected}\n"));
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let helper = dir.0.join("burrow_review_untrusted_tool");
    fs::write(&helper, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "elevated_children_use_the_requested_home_and_trusted_path",
        ])
        .env("BURROW_REVIEW_EXPECT_HOME", &dir.0)
        .env("BURROW_HOME", &dir.0)
        .env("BURROW_PRIVILEGED", "1")
        .env("HOME", "/var/root")
        .env("PATH", format!("{}:/usr/bin:/bin", dir.0.display()))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn exact_plan_previews_list_every_path_the_apply_will_consider() {
    use burrow_engine::json::Json;
    let dir = Scratch::new();
    let cache = dir.0.join("Library/Caches/reviewcache");
    fs::create_dir_all(&cache).unwrap();
    let a = cache.join("a");
    let b = cache.join("b");
    fs::write(&a, b"same").unwrap();
    fs::hard_link(&a, &b).unwrap();
    let plan = dir.0.join("plan");
    fs::write(
        &plan,
        format!("{}\n{}\n{}\n", a.display(), b.display(), a.display()),
    )
    .unwrap();
    let run = |stream: bool| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_burrow-engine"));
        command
            .args(["clean", "--plan"])
            .arg(&plan)
            .env("BURROW_HOME", &dir.0);
        if stream {
            command.arg("--stream");
        }
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let buffered = Json::parse(&run(false)).unwrap();
    assert_eq!(
        buffered
            .get("data")
            .unwrap()
            .get("items")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let stream = run(true);
    let lines: Vec<Json> = stream
        .lines()
        .map(|line| Json::parse(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines.last().unwrap().get("count").unwrap().as_u64(),
        Some(3)
    );
    assert!(
        a.exists() && b.exists(),
        "review must leave both names intact"
    );
}

#[test]
fn malformed_fat64_sizes_are_refused_before_savings_can_overflow() {
    use burrow_engine::macho::{parse_fat, CPU_ARM64, CPU_X86_64};
    let mut header = Vec::new();
    header.extend_from_slice(&0xcafe_babfu32.to_be_bytes());
    header.extend_from_slice(&3u32.to_be_bytes());
    for (cpu, size) in [(CPU_ARM64, 1u64), (CPU_X86_64, u64::MAX), (7, 2)] {
        header.extend_from_slice(&cpu.to_be_bytes());
        header.extend_from_slice(&0u32.to_be_bytes());
        header.extend_from_slice(&0u64.to_be_bytes());
        header.extend_from_slice(&size.to_be_bytes());
        header.extend_from_slice(&0u64.to_be_bytes());
    }
    assert!(parse_fat(&header).is_err());
}

#[cfg(unix)]
#[test]
fn sweep_plan_cli_previews_and_applies_only_the_reviewed_temporary_paths() {
    use burrow_engine::json::Json;
    for (command, relative, late_relative, field) in [
        (
            "purge",
            "dev/project/target",
            "dev/project/node_modules",
            "artifacts",
        ),
        (
            "installer",
            "Downloads/reviewed.dmg",
            "Downloads/late.pkg",
            "installers",
        ),
    ] {
        let dir = Scratch::new();
        let reviewed = dir.0.join(relative);
        let late = dir.0.join(late_relative);
        fs::create_dir_all(reviewed.parent().unwrap()).unwrap();
        if command == "purge" {
            fs::create_dir(&reviewed).unwrap();
            fs::create_dir(&late).unwrap();
        } else {
            fs::write(&reviewed, b"reviewed").unwrap();
            fs::write(&late, b"later").unwrap();
        }
        let plan = dir.0.join("review.plan");
        fs::write(&plan, format!("# reviewed paths\n{}\n", reviewed.display())).unwrap();
        let run = |apply: bool, stream: bool| {
            let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_burrow-engine"));
            child
                .args([command, "--plan"])
                .arg(&plan)
                .env("BURROW_HOME", &dir.0)
                .env_remove("PURGE_PATHS_CONFIG");
            if apply {
                child.args(["--apply", "--permanent"]);
            }
            if stream {
                child.arg("--stream");
            }
            let out = child.output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stdout)
            );
            String::from_utf8(out.stdout).unwrap()
        };
        let preview = Json::parse(&run(false, false)).unwrap();
        let listed = preview
            .get("data")
            .unwrap()
            .get(field)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].get("path").unwrap().as_str(), reviewed.to_str());
        assert!(reviewed.exists() && late.exists());
        if command == "purge" {
            let stream = run(false, true);
            assert_eq!(
                stream.lines().count(),
                2,
                "one candidate and one terminal event"
            );
            assert!(!stream.contains(late.to_str().unwrap()));
        }
        let _ = run(true, command == "purge");
        assert!(!reviewed.exists());
        assert!(
            late.exists(),
            "unreviewed candidate survives a real fixture apply"
        );
    }
}
