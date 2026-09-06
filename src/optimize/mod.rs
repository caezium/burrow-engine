//! System maintenance — the engine reimplementation of digger's `optimize`. A fixed set of safe,
//! non-destructive maintenance tasks (flush the DNS cache, refresh the Dock, repair Launch
//! Services). None delete user data; they refresh caches and restart UI services.
//!
//! Mirrors the clean design: dry-run (list the tasks) is the default, `--apply` runs them. The
//! command execution is injected as a closure, so the run/collect logic is fully unit-tested
//! without spawning anything — and so the exact argv of every step is pinned against the oracle
//! (`lib/optimize/tasks.sh`), which is where the previous list drifted: it ran `lsregister -kill`,
//! which WIPES the Launch Services database rather than repairing it, and restarted Finder,
//! which no digger task does.
//!
//! The oracle runs its DNS flush under `sudo`, and skips the whole task when sudo is not available
//! (`flush_dns_cache`, `tasks.sh:160`: `if ! optimize_sudo_available; then return 1`, and the
//! caller only prints on success). This binary never elevates itself, so unelevated it does the
//! same: a task marked `requires_admin` is reported as `skipped` with reason [`REQUIRES_ADMIN`]
//! rather than run into a `killall -HUP mDNSResponder` that fails without root and then reported
//! as a failed task. The app's privileged helper is the elevated path, and under it (effective uid
//! 0) the task runs for real.

/// One command line a task runs. `required: false` is the oracle's `|| true`: the step runs,
/// and its failure does not fail the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    pub program: &'static str,
    pub args: &'static [&'static str],
    pub required: bool,
}

/// One maintenance task: a label + the command lines it runs, in order, short-circuiting on the
/// first required failure — `a && b` in the oracle. `fallback` runs only when a required step
/// failed, and then decides the task on its own (the oracle's `if [[ $success -ne 0 ]]; then …`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimizeTask {
    pub name: &'static str,
    pub description: &'static str,
    pub steps: &'static [Step],
    pub fallback: &'static [Step],
    /// The oracle runs every step under `sudo` and skips the task when it cannot elevate. Such a
    /// task is skipped here too unless the engine already runs as root.
    pub requires_admin: bool,
}

/// The `reason` a task skipped for want of elevation carries.
pub const REQUIRES_ADMIN: &str = "requires_admin";

const LSREGISTER: &str =
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

const fn step(program: &'static str, args: &'static [&'static str]) -> Step {
    Step {
        program,
        args,
        required: true,
    }
}

const fn optional(program: &'static str, args: &'static [&'static str]) -> Step {
    Step {
        program,
        args,
        required: false,
    }
}

/// The built-in maintenance tasks, each transcribed from `lib/optimize/tasks.sh`.
pub const TASKS: &[OptimizeTask] = &[
    // `flush_dns_cache` (`tasks.sh:160`): `sudo dscacheutil -flushcache && sudo killall -HUP
    // mDNSResponder`. Both halves, in that order, the second only after the first succeeded.
    OptimizeTask {
        name: "flush_dns",
        description: "Flush the DNS resolver cache",
        steps: &[
            step("dscacheutil", &["-flushcache"]),
            step("killall", &["-HUP", "mDNSResponder"]),
        ],
        fallback: &[],
        requires_admin: true,
    },
    // `opt_dock_refresh` (`tasks.sh:843-854`): `killall Dock`.
    OptimizeTask {
        name: "restart_dock",
        description: "Restart the Dock",
        steps: &[step("killall", &["Dock"])],
        fallback: &[],
        requires_admin: false,
    },
    // `opt_launchservices_repair` (`tasks.sh:552-557`): `lsregister -gc || true`, then
    // `lsregister -r -f -domain local -domain user -domain system`; if that fails, the same
    // without the system domain. NOT `-kill`: that discards the database instead of rescanning it.
    OptimizeTask {
        name: "rebuild_launch_services",
        description:
            "Rebuild the Launch Services database (fixes duplicate/stale 'Open With' entries)",
        steps: &[
            optional(LSREGISTER, &["-gc"]),
            step(
                LSREGISTER,
                &[
                    "-r", "-f", "-domain", "local", "-domain", "user", "-domain", "system",
                ],
            ),
        ],
        fallback: &[step(
            LSREGISTER,
            &["-r", "-f", "-domain", "local", "-domain", "user"],
        )],
        requires_admin: false,
    },
];

/// The result of running one task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResult {
    pub name: String,
    /// `true` unless the task RAN and failed. A skipped task is not a failure — nothing was
    /// attempted — so it keeps `ok: true` and says why in `skipped`.
    pub ok: bool,
    pub error: Option<String>,
    /// `Some(reason)` when the task was not run at all (today only [`REQUIRES_ADMIN`]).
    pub skipped: Option<&'static str>,
}

impl TaskResult {
    /// Ran and succeeded — what "Applied N optimizations" counts.
    pub fn applied(&self) -> bool {
        self.ok && self.skipped.is_none()
    }
}

/// Run each task via the injected `runner` (which returns `Ok(())` on success or `Err(msg)`),
/// collecting per-task results. `elevated` is whether this process runs as root: a task whose
/// `requires_admin` is set is skipped (not failed) when it is `false`. Pure w.r.t. the runner and
/// the elevation flag, so it's testable without spawning or being root.
pub fn run_optimize(
    tasks: &[OptimizeTask],
    elevated: bool,
    runner: impl Fn(&str, &[&str]) -> Result<(), String>,
) -> Vec<TaskResult> {
    run_optimize_with(tasks, elevated, runner, |_| {})
}

/// Like [`run_optimize`] but invokes `emit` with each [`TaskResult`] as it completes — the
/// streaming core for `optimize --stream`. Results come back in task order.
pub fn run_optimize_with(
    tasks: &[OptimizeTask],
    elevated: bool,
    runner: impl Fn(&str, &[&str]) -> Result<(), String>,
    mut emit: impl FnMut(&TaskResult),
) -> Vec<TaskResult> {
    tasks
        .iter()
        .map(|t| {
            let result = if t.requires_admin && !elevated {
                TaskResult {
                    name: t.name.to_string(),
                    ok: true,
                    error: None,
                    skipped: Some(REQUIRES_ADMIN),
                }
            } else {
                match run_task(t, &runner) {
                    Ok(()) => TaskResult {
                        name: t.name.to_string(),
                        ok: true,
                        error: None,
                        skipped: None,
                    },
                    Err(e) => TaskResult {
                        name: t.name.to_string(),
                        ok: false,
                        error: Some(e),
                        skipped: None,
                    },
                }
            };
            emit(&result);
            result
        })
        .collect()
}

/// Run one task's steps in order — `a && b`: the first required failure stops the sequence and,
/// unless a `fallback` exists and succeeds, fails the task with that step's error, named by its
/// command line so a failed run says WHICH command failed.
fn run_task(
    task: &OptimizeTask,
    runner: &impl Fn(&str, &[&str]) -> Result<(), String>,
) -> Result<(), String> {
    let run_all = |steps: &[Step]| -> Result<(), String> {
        for s in steps {
            match runner(s.program, s.args) {
                Ok(()) => {}
                Err(_) if !s.required => {}
                Err(e) => {
                    return Err(format!("{} {}: {e}", s.program, s.args.join(" ")));
                }
            }
        }
        Ok(())
    };
    match run_all(task.steps) {
        Ok(()) => Ok(()),
        Err(_) if !task.fallback.is_empty() => run_all(task.fallback),
        Err(e) => Err(e),
    }
}

use crate::json::escape as esc;

/// The `,"skipped":true,"reason":R` tail a skipped task's JSON object carries — additive, so a
/// task that ran keeps the exact `{name,ok,error}` bytes it always had.
fn skipped_fields(result: &TaskResult) -> String {
    match result.skipped {
        Some(reason) => format!(",\"skipped\":true,\"reason\":{}", esc(reason)),
        None => String::new(),
    }
}

/// One NDJSON line for a completed task (the `optimize --stream` unit). A skipped task adds
/// `skipped:true,reason` to the same `task` event rather than a new event kind, so a reader that
/// only knows `task`/`done` still counts it.
pub fn task_ndjson(result: &TaskResult) -> String {
    format!(
        "{{\"event\":\"task\",\"name\":{},\"ok\":{},\"error\":{}{}}}",
        esc(&result.name),
        result.ok,
        result
            .error
            .as_deref()
            .map(esc)
            .unwrap_or_else(|| "null".to_string()),
        skipped_fields(result)
    )
}

/// One NDJSON line for a task in a DRY-RUN stream (the task is NOT run). The GUI streams previews,
/// so `optimize --stream` without `--apply` emits these.
pub fn would_run_ndjson(task: &OptimizeTask) -> String {
    format!(
        "{{\"event\":\"would_run\",\"name\":{},\"description\":{}}}",
        esc(task.name),
        esc(task.description)
    )
}

/// The terminal NDJSON line for a finished DRY-RUN optimize stream.
pub fn preview_done_ndjson(tasks: &[OptimizeTask]) -> String {
    format!(
        "{{\"event\":\"done\",\"dry_run\":true,\"tasks\":{}}}",
        tasks.len()
    )
}

/// The terminal NDJSON line for a finished optimize run.
pub fn done_ndjson(results: &[TaskResult]) -> String {
    let failed = results.iter().filter(|r| !r.ok).count();
    format!(
        "{{\"event\":\"done\",\"ok\":{},\"tasks\":{},\"failed\":{failed}}}",
        failed == 0,
        results.len()
    )
}

const RULE: &str = "======================================================================";

/// Human-readable report text alongside the structured fields — see
/// `crate::purge::render_dry_run_text`'s doc for why this exists. Reuses `bin/optimize.sh`'s
/// section markers and its "Would apply N optimizations" / "Run without --dry-run …" wording.
/// Verified against `optimize.golden.json` through the real, unmodified `parseTaskReport`
/// (repoint-redo Gate 1 harness): neither the oracle's own text nor this rendering matches
/// `mergeSummaryFields` (it only recognises `clean`-only phrasing — "potential space" / "tracked
/// cleanup" / "free space change" / "free space now"), so `summary` is nil for optimize on BOTH
/// sides. That's parity with the oracle, not a regression.
fn render_preview_text(tasks: &[OptimizeTask]) -> String {
    let mut out = String::new();
    out.push_str("Optimize\n");
    out.push_str("DRY RUN MODE, No files will be modified\n\n");
    if !tasks.is_empty() {
        out.push_str("➤ Maintenance Tasks\n");
        for t in tasks {
            out.push_str(&format!("  → {}\n", t.description));
        }
        out.push('\n');
    }
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Dry Run Complete, No Changes Made\n");
    out.push_str(&format!("Would apply {} optimizations\n", tasks.len()));
    out.push_str("Run without --dry-run to apply these changes\n");
    out.push_str(RULE);
    out
}

/// Same idea as [`render_preview_text`] for a completed (`--apply`) run: "Applied N
/// optimizations" is `bin/optimize.sh`'s real live-mode wording, equally unrecognised by
/// `mergeSummaryFields` — see [`render_preview_text`].
fn render_results_text(results: &[TaskResult]) -> String {
    let mut out = String::new();
    out.push_str("Optimize\n\n");
    let failed = results.iter().filter(|r| !r.ok).count();
    let applied = results.iter().filter(|r| r.applied()).count();
    if !results.is_empty() {
        out.push_str("➤ Maintenance Tasks\n");
        for r in results {
            match (&r.error, r.skipped) {
                (_, Some(reason)) => out.push_str(&format!("  – {}: skipped ({reason})\n", r.name)),
                (None, None) => out.push_str(&format!("  ✓ {}\n", r.name)),
                (Some(e), None) => out.push_str(&format!("  ✗ {}: {e}\n", r.name)),
            }
        }
        out.push('\n');
    }
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Optimization Complete\n");
    if failed > 0 {
        out.push_str(&format!(
            "Applied {applied} optimizations, {failed} failed\n"
        ));
    } else {
        out.push_str(&format!(
            "Applied {applied} optimizations, all services tuned\n"
        ));
        out.push_str("System fully optimized\n");
    }
    out.push_str(RULE);
    out
}

/// Serialize the dry-run optimize report (zero-dep): `{dry_run:true,tasks:[{name,description}],text:S}`.
///
/// NOT YET CALLED from `src/cli.rs`'s `optimize()` dry-run path, which today builds this same
/// `tasks` shape inline with its own `format!` (minus `text`) rather than delegating to this
/// module — see `crate::clean::execute::outcome_to_json`'s doc for why (the repoint-redo
/// contract-conformance round has `cli.rs` off-limits for this slice). Wiring this in is a
/// one-line follow-up: replace the inline `format!` with a call to this function.
pub fn to_json(tasks: &[OptimizeTask]) -> String {
    let items = tasks
        .iter()
        .map(|t| {
            format!(
                "{{\"name\":{},\"description\":{}}}",
                esc(t.name),
                esc(t.description)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = render_preview_text(tasks);
    format!(
        "{{\"dry_run\":true,\"tasks\":[{items}],\"text\":{}}}",
        esc(&text)
    )
}

/// Serialize a completed optimize run (zero-dep):
/// `{dry_run:false,results:[{name,ok,error,skipped?,reason?}],text:S}`. `skipped:true,reason` appear
/// only on a task that was not run (see [`TaskResult::skipped`]).
pub fn outcome_to_json(results: &[TaskResult]) -> String {
    let items = results
        .iter()
        .map(|r| {
            format!(
                "{{\"name\":{},\"ok\":{},\"error\":{}{}}}",
                esc(&r.name),
                r.ok,
                r.error
                    .as_deref()
                    .map(esc)
                    .unwrap_or_else(|| "null".to_string()),
                skipped_fields(r)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = render_results_text(results);
    format!(
        "{{\"dry_run\":false,\"results\":[{items}],\"text\":{}}}",
        esc(&text)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;
    use std::cell::RefCell;

    /// Every command line each task runs, in order, as the injected runner sees it.
    fn argv_of(
        task: &OptimizeTask,
        runner_verdict: impl Fn(&str, &[&str]) -> Result<(), String>,
    ) -> Vec<(String, Vec<String>)> {
        let calls = RefCell::new(Vec::new());
        let runner = |program: &str, args: &[&str]| {
            calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|a| a.to_string()).collect(),
            ));
            runner_verdict(program, args)
        };
        let _ = run_optimize(std::slice::from_ref(task), true, runner);
        calls.into_inner()
    }

    fn task(name: &str) -> &'static OptimizeTask {
        TASKS.iter().find(|t| t.name == name).unwrap()
    }

    fn argv(program: &str, args: &[&str]) -> (String, Vec<String>) {
        (
            program.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
        )
    }

    #[test]
    fn task_list_never_elevates_itself_and_never_spawns_sudo() {
        assert!(!TASKS.is_empty());
        assert!(TASKS.iter().all(|t| t
            .steps
            .iter()
            .chain(t.fallback)
            .all(|s| s.program != "sudo" && s.program != "purge")));
        assert!(TASKS.iter().any(|t| t.name == "flush_dns"));
    }

    /// `lib/optimize/tasks.sh:160`: `sudo dscacheutil -flushcache && sudo killall -HUP
    /// mDNSResponder`. The engine ran only the first half, so the resolver kept its cache.
    #[test]
    fn flush_dns_runs_the_oracles_two_commands_in_order() {
        assert_eq!(
            argv_of(task("flush_dns"), |_, _| Ok(())),
            vec![
                argv("dscacheutil", &["-flushcache"]),
                argv("killall", &["-HUP", "mDNSResponder"]),
            ]
        );
    }

    #[test]
    fn flush_dns_short_circuits_like_the_oracles_double_ampersand() {
        let calls = argv_of(task("flush_dns"), |p, _| {
            if p == "dscacheutil" {
                Err("boom".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(calls, vec![argv("dscacheutil", &["-flushcache"])]);
        let results = run_optimize(std::slice::from_ref(task("flush_dns")), true, |_, _| {
            Err("boom".to_string())
        });
        assert!(!results[0].ok);
        assert!(
            results[0]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("dscacheutil -flushcache")),
            "the failed command is named: {:?}",
            results[0].error
        );
    }

    /// `tasks.sh:552-557`: `lsregister -gc || true`, then `-r -f -domain local -domain user
    /// -domain system`. The engine ran `-kill -r …`, which throws the database away.
    #[test]
    fn launch_services_repair_runs_gc_then_a_forced_rescan_never_kill() {
        let calls = argv_of(task("rebuild_launch_services"), |_, _| Ok(()));
        assert_eq!(
            calls,
            vec![
                argv(LSREGISTER, &["-gc"]),
                argv(
                    LSREGISTER,
                    &["-r", "-f", "-domain", "local", "-domain", "user", "-domain", "system"]
                ),
            ]
        );
        for t in TASKS {
            for s in t.steps.iter().chain(t.fallback) {
                assert!(!s.args.contains(&"-kill"), "{}: {:?}", t.name, s.args);
            }
        }
    }

    #[test]
    fn launch_services_gc_failure_is_ignored_and_a_rescan_failure_falls_back_to_two_domains() {
        // `-gc` is `|| true` in the oracle: its failure does not stop the rescan.
        let calls = argv_of(task("rebuild_launch_services"), |_, a| {
            if a == ["-gc"] {
                Err("gc failed".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(calls.len(), 2, "{calls:?}");
        let results = run_optimize(
            std::slice::from_ref(task("rebuild_launch_services")),
            true,
            |_, a| {
                if a == ["-gc"] {
                    Err("gc failed".into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(results[0].ok, "{results:?}");

        // The three-domain rescan failing runs the oracle's two-domain retry, which decides.
        let calls = argv_of(task("rebuild_launch_services"), |_, a| {
            if a.contains(&"system") {
                Err("no system domain".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(
            calls.last(),
            Some(&argv(
                LSREGISTER,
                &["-r", "-f", "-domain", "local", "-domain", "user"]
            )),
            "{calls:?}"
        );
        let results = run_optimize(
            std::slice::from_ref(task("rebuild_launch_services")),
            true,
            |_, a| {
                if a.contains(&"system") {
                    Err("no system domain".into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(results[0].ok, "the fallback succeeded: {results:?}");
        let results = run_optimize(
            std::slice::from_ref(task("rebuild_launch_services")),
            true,
            |_, a| {
                if a.contains(&"-r") {
                    Err("nope".into())
                } else {
                    Ok(())
                }
            },
        );
        assert!(!results[0].ok, "both rescans failed: {results:?}");
    }

    /// `opt_dock_refresh` (`tasks.sh:850`) is `killall Dock`; nothing in `lib/optimize` restarts
    /// Finder, and the engine's `restart_finder` task did not come from anywhere in the oracle.
    #[test]
    fn the_dock_is_restarted_and_finder_never_is() {
        assert_eq!(
            argv_of(task("restart_dock"), |_, _| Ok(())),
            vec![argv("killall", &["Dock"])]
        );
        assert!(TASKS.iter().all(|t| t.name != "restart_finder"));
        for t in TASKS {
            for s in t.steps.iter().chain(t.fallback) {
                assert!(
                    !(s.program == "killall" && s.args.contains(&"Finder")),
                    "{}: {:?}",
                    t.name,
                    s.args
                );
            }
        }
    }

    #[test]
    fn run_optimize_runs_every_task_and_collects_results() {
        let seen = RefCell::new(std::collections::BTreeSet::new());
        let runner = |program: &str, args: &[&str]| {
            seen.borrow_mut().insert(program.to_string());
            // Simulate the Dock restart failing (e.g. not running), everything else OK.
            if args == ["Dock"] {
                Err("No matching processes".to_string())
            } else {
                Ok(())
            }
        };
        let results = run_optimize(TASKS, true, runner);
        assert_eq!(results.len(), TASKS.len());
        for t in TASKS {
            for s in t.steps {
                assert!(seen.borrow().contains(s.program), "{} ran", s.program);
            }
        }
        let dock = results.iter().find(|r| r.name == "restart_dock").unwrap();
        assert!(!dock.ok);
        assert_eq!(
            dock.error.as_deref(),
            Some("killall Dock: No matching processes")
        );
        assert!(results.iter().find(|r| r.name == "flush_dns").unwrap().ok);
    }

    #[test]
    fn run_optimize_with_emits_each_task_in_order() {
        let mut emitted = Vec::new();
        let results =
            run_optimize_with(TASKS, true, |_, _| Ok(()), |r| emitted.push(r.name.clone()));
        assert_eq!(emitted.len(), TASKS.len());
        assert_eq!(emitted[0], "flush_dns", "emitted in task order");
        assert_eq!(results.len(), TASKS.len());
    }

    // Was `assert_eq!(task_ndjson(...), "<hand-typed JSON literal>")` — a full-string compare
    // that can only confirm the serializer matches a string the same person who wrote the
    // serializer also typed (check_tests.py's RULEBOOK §6 rule). This NDJSON wire format has no
    // reference capture to load — judge.py's fixtures are all request/response envelopes, not a
    // streamed line feed — the contract is instead pinned by the real Swift consumer
    // (`BurrowStreamReport.swift`, RULEBOOK §5). So instead of a blob compare, parse the output
    // with the engine's own JSON reader and assert individual fields: that round-trips through a
    // real parser and would catch a malformed-JSON regression (trailing comma, bad escape) that a
    // substring `.contains()` check would miss, without pinning key order or spacing the way the
    // original literal did.
    #[test]
    fn stream_ndjson_shapes() {
        let ok = TaskResult {
            name: "flush_dns".into(),
            ok: true,
            error: None,
            skipped: None,
        };
        let line = task_ndjson(&ok);
        let parsed = Json::parse(&line).expect("must be valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("task"));
        assert_eq!(parsed.get("name").and_then(Json::as_str), Some("flush_dns"));
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(true));
        assert!(
            matches!(parsed.get("error"), Some(Json::Null)),
            "no error -> explicit null: {line}"
        );

        let bad = TaskResult {
            name: "restart_dock".into(),
            ok: false,
            error: Some("no proc".into()),
            skipped: None,
        };
        let line = task_ndjson(&bad);
        let parsed = Json::parse(&line).expect("must be valid JSON");
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(false));
        assert_eq!(parsed.get("error").and_then(Json::as_str), Some("no proc"));

        let line = done_ndjson(&[ok, bad]);
        let parsed = Json::parse(&line).expect("must be valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("done"));
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(false));
        assert_eq!(parsed.get("tasks").and_then(Json::as_u64), Some(2));
        assert_eq!(parsed.get("failed").and_then(Json::as_u64), Some(1));
    }

    #[test]
    fn preview_stream_shapes() {
        let line = would_run_ndjson(&TASKS[0]);
        let parsed = Json::parse(&line).expect("must be valid JSON");
        assert_eq!(
            parsed.get("event").and_then(Json::as_str),
            Some("would_run")
        );
        assert_eq!(
            parsed.get("name").and_then(Json::as_str),
            Some(TASKS[0].name)
        );
        assert_eq!(
            parsed.get("description").and_then(Json::as_str),
            Some(TASKS[0].description)
        );

        let line = preview_done_ndjson(TASKS);
        let parsed = Json::parse(&line).expect("must be valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("done"));
        assert_eq!(parsed.get("dry_run").and_then(Json::as_bool), Some(true));
        assert_eq!(
            parsed.get("tasks").and_then(Json::as_u64),
            Some(TASKS.len() as u64)
        );
    }

    #[test]
    fn to_json_matches_clis_current_inline_tasks_shape_plus_text() {
        let j = to_json(TASKS);
        assert!(j.contains("\"dry_run\":true"));
        assert!(j.contains(&format!(
            "\"name\":\"{}\",\"description\":\"{}\"",
            TASKS[0].name, TASKS[0].description
        )));
        assert!(j.contains("\"text\":\""), "text field is present: {j}");
    }

    #[test]
    fn outcome_to_json_matches_clis_current_inline_results_shape_plus_text() {
        let results = vec![
            TaskResult {
                name: "flush_dns".into(),
                ok: true,
                error: None,
                skipped: None,
            },
            TaskResult {
                name: "restart_dock".into(),
                ok: false,
                error: Some("no proc".into()),
                skipped: None,
            },
        ];
        let j = outcome_to_json(&results);
        assert!(j.contains("\"dry_run\":false"));
        assert!(j.contains("\"name\":\"flush_dns\",\"ok\":true,\"error\":null"));
        assert!(j.contains("\"name\":\"restart_dock\",\"ok\":false,\"error\":\"no proc\""));
        assert!(j.contains("\"text\":\""), "text field is present: {j}");
    }

    // -- text field: matched against bin/optimize.sh's real wording. Verified via the repoint-
    // redo Gate 1 harness that neither the oracle's own text nor this rendering trips the real
    // parser's `mergeSummaryFields` (clean-only phrasing) — see render_preview_text's doc.

    #[test]
    fn preview_text_matches_optimize_sh_wording() {
        let text = render_preview_text(TASKS);
        assert!(text.contains("DRY RUN MODE"));
        assert!(text.contains("Dry Run Complete, No Changes Made"));
        // bin/optimize.sh: `summary_details+=("Would apply ${total_applied:-0} optimizations")`.
        assert!(text.contains(&format!("Would apply {} optimizations", TASKS.len())));
        assert!(text.contains("Run without --dry-run to apply these changes"));
        for t in TASKS {
            assert!(text.contains(t.description), "{}", t.description);
        }
    }

    #[test]
    fn results_text_matches_optimize_sh_wording_all_ok() {
        let results = vec![TaskResult {
            name: "flush_dns".into(),
            ok: true,
            error: None,
            skipped: None,
        }];
        let text = render_results_text(&results);
        assert!(text.contains("Optimization Complete"));
        assert!(text.contains("Applied 1 optimizations, all services tuned"));
        assert!(text.contains("System fully optimized"));
        assert!(!text.contains("failed"));
    }

    #[test]
    fn results_text_matches_optimize_sh_wording_with_a_failure() {
        let results = vec![
            TaskResult {
                name: "flush_dns".into(),
                ok: true,
                error: None,
                skipped: None,
            },
            TaskResult {
                name: "restart_dock".into(),
                ok: false,
                error: Some("no proc".into()),
                skipped: None,
            },
        ];
        let text = render_results_text(&results);
        assert!(text.contains("Applied 1 optimizations, 1 failed"));
        assert!(text.contains("restart_dock: no proc"));
        assert!(
            !text.contains("System fully optimized"),
            "a failed task means the run wasn't fully clean: {text}"
        );
    }

    #[test]
    fn text_never_trips_the_swift_parsers_summary_phrases() {
        let dry = render_preview_text(TASKS).to_lowercase();
        let results: Vec<TaskResult> = TASKS
            .iter()
            .map(|t| TaskResult {
                name: t.name.to_string(),
                ok: true,
                error: None,
                skipped: None,
            })
            .collect();
        let applied = render_results_text(&results).to_lowercase();
        for phrase in [
            "potential space",
            "tracked cleanup",
            "free space change",
            "free space now",
        ] {
            assert!(
                !dry.contains(phrase),
                "dry-run text unexpectedly contains {phrase:?}"
            );
            assert!(
                !applied.contains(phrase),
                "applied text unexpectedly contains {phrase:?}"
            );
        }
    }
    /// `tasks.sh:160`: `if ! optimize_sudo_available; then return 1` — without elevation the
    /// oracle never runs the DNS flush and never reports it as failed. Unelevated, this engine
    /// skips the task the same way (nothing is spawned) and says so, rather than running a
    /// `killall -HUP mDNSResponder` that fails without root and calling that a failed task.
    #[test]
    fn flush_dns_is_skipped_not_failed_when_unelevated() {
        let calls = RefCell::new(Vec::new());
        let results = run_optimize(std::slice::from_ref(task("flush_dns")), false, |p, _| {
            calls.borrow_mut().push(p.to_string());
            Ok(())
        });
        assert!(calls.borrow().is_empty(), "nothing spawned: {calls:?}");
        assert_eq!(
            results,
            vec![TaskResult {
                name: "flush_dns".into(),
                ok: true,
                error: None,
                skipped: Some(REQUIRES_ADMIN),
            }]
        );
        assert!(!results[0].applied());
        // Elevated, it runs both halves for real.
        let results = run_optimize(std::slice::from_ref(task("flush_dns")), true, |p, _| {
            calls.borrow_mut().push(p.to_string());
            Ok(())
        });
        assert_eq!(calls.borrow().as_slice(), ["dscacheutil", "killall"]);
        assert_eq!(results[0].skipped, None);
    }

    #[test]
    fn only_the_dns_flush_needs_elevation() {
        let needs: Vec<&str> = TASKS
            .iter()
            .filter(|t| t.requires_admin)
            .map(|t| t.name)
            .collect();
        assert_eq!(needs, ["flush_dns"]);
    }

    /// A skipped task's line and object carry `skipped:true,reason:"requires_admin"`; a task that
    /// ran carries neither key, so the pre-existing `{name,ok,error}` bytes are untouched, and the
    /// run's `done` line does not count the skip as a failure.
    #[test]
    fn skipped_task_is_reported_in_stream_and_buffered_json_without_failing_the_run() {
        let results = run_optimize(TASKS, false, |_, _| Ok(()));
        let skipped = results.iter().find(|r| r.name == "flush_dns").unwrap();
        let line = task_ndjson(skipped);
        let parsed = Json::parse(&line).expect("valid JSON");
        assert_eq!(parsed.get("event").and_then(Json::as_str), Some("task"));
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(true));
        assert_eq!(parsed.get("skipped").and_then(Json::as_bool), Some(true));
        assert_eq!(
            parsed.get("reason").and_then(Json::as_str),
            Some("requires_admin")
        );
        let ran = results.iter().find(|r| r.name == "restart_dock").unwrap();
        let line = task_ndjson(ran);
        assert!(!line.contains("skipped"), "{line}");
        let ran_payload = Json::parse(&line).unwrap();
        assert_eq!(
            ran_payload.get("name").and_then(Json::as_str),
            Some(ran.name.as_str())
        );
        assert_eq!(ran_payload.get("ok").and_then(Json::as_bool), Some(ran.ok));
        assert!(ran_payload.get("reason").is_none());

        let done = Json::parse(&done_ndjson(&results)).unwrap();
        assert_eq!(done.get("failed").and_then(Json::as_u64), Some(0));
        assert_eq!(done.get("ok").and_then(Json::as_bool), Some(true));

        let data = Json::parse(&outcome_to_json(&results)).unwrap();
        let items = data.get("results").and_then(Json::as_array).unwrap();
        let dns = items
            .iter()
            .find(|i| i.get("name").and_then(Json::as_str) == Some("flush_dns"))
            .unwrap();
        assert_eq!(dns.get("skipped").and_then(Json::as_bool), Some(true));
        assert_eq!(
            dns.get("reason").and_then(Json::as_str),
            Some("requires_admin")
        );
        let dock = items
            .iter()
            .find(|i| i.get("name").and_then(Json::as_str) == Some("restart_dock"))
            .unwrap();
        assert!(dock.get("skipped").is_none());
        let text = data.get("text").and_then(Json::as_str).unwrap();
        assert!(
            text.contains("flush_dns: skipped (requires_admin)"),
            "{text}"
        );
        assert!(
            text.contains(&format!("Applied {} optimizations", TASKS.len() - 1)),
            "a skipped task is not an applied one: {text}"
        );
    }
}
