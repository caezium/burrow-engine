//! Command dispatch for the `burrow-engine` binary — the engine's own command surface.
//!
//! Every command returns the stable Burrow envelope (the same contract burrow-cli speaks), so a GUI
//! or agent parses one shape regardless of who serves it. Dispatch is factored out of `main.rs` and
//! returns `(stdout, exit_code)` so it's unit-testable without spawning a process — the only I/O is
//! whatever the command itself touches (e.g. the directory `analyze` scans).

use crate::analyze::{json, scanner};
use crate::envelope;
use std::path::Path;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const ENGINE: &str = "burrow-engine";

/// Run one engine command. `args` is argv without the program name (command + its arguments).
pub fn dispatch(args: &[String]) -> (String, i32) {
    let cmd = args.first().map(String::as_str);
    // The oracle takes all three spellings and exits 0 (`mole:1080`). Matched before flag
    // validation because two of them are themselves flag-shaped.
    if matches!(cmd, Some("version") | Some("--version") | Some("-V")) {
        return version();
    }
    // `mole:1076-1079`, two lines above the version case and in the same `case` block:
    // `"help" | "--help" | "-h") show_help; exit 0`. The port took the version arm and not this
    // one, so `--help` answered `unknown command` with exit 2 where the original exits 0.
    if matches!(cmd, Some("help") | Some("--help") | Some("-h")) {
        return help();
    }
    // An unrecognised flag is an error, not a silent no-op — see `allowed_flags`. Two flags that
    // contradict each other are the same class of malformed argv and are refused right beside it:
    // see `reject_contradictory_flags` for why that beats resolving them silently. Both run BEFORE
    // the command, which is also where bash validates — its `for arg in "$@"` loop
    // (`bin/uninstall.sh:1326-1360`) exits 1 on a bad flag before the `list_mode` short-circuit at
    // `:1364`, so `uninstall --list --apply --dry-run` is a refusal there too, not a listing.
    if let Some(cmd) = cmd {
        if let Some(err) = reject_unknown_flag(cmd, &args[1..]) {
            return err;
        }
        if let Some(err) = reject_missing_flag_value(cmd, &args[1..]) {
            return err;
        }
        if let Some(err) = reject_contradictory_flags(cmd, &args[1..]) {
            return err;
        }
    }
    match cmd {
        Some("analyze") => analyze(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("clean") => clean(&args[1..]),
        Some("optimize") => optimize(&args[1..]),
        Some("uninstall") => uninstall(&args[1..]),
        Some("net") => net(&args[1..]),
        Some("orphans") => orphans(&args[1..]),
        Some("slim-check") => slim_check(&args[1..]),
        Some("evict") => evict(&args[1..]),
        Some("dupes") => dupes(&args[1..]),
        Some("photos") => photos(&args[1..]),
        Some("history") => history(&args[1..]),
        Some("purge") => purge(&args[1..]),
        Some("installer") => installer(&args[1..]),
        Some("rules") => rules(&args[1..]),
        Some("sentinel") => sentinel(&args[1..]),
        Some(other) => (
            envelope::error_envelope(VERSION, other, &format!("unknown command: {other}")),
            2,
        ),
        None => (envelope::error_envelope(VERSION, "", "no command given"), 2),
    }
}

/// `status` — collect a system snapshot (health score + cpu/memory/disk/battery/proxy/uptime) and
/// emit it envelope-wrapped. Optional panes still degrade to empties; a collection in which NONE of
/// the health score's four inputs could be read is a classified `unsupported` failure instead.
///
/// It used to be "always succeeds". Reproduced with the collector binaries out of reach —
/// `env -i PATH=/nonexistent burrow-engine status` — that produced `exit 0, ok:true,
/// health_score:100, health_score_msg:"Excellent"` over `procs:0, host:"", uptime_seconds:0,
/// cpu.usage:0, memory.total:0, disks:[]`. Every collector had degraded to a zero, every penalty
/// branch in `calculate_health_score` is a `>` threshold that zero cannot trip, and the score stayed
/// at the `100` it starts from. A confident healthy verdict computed from nothing measured, with a
/// success envelope around it and nothing in the payload to tell a caller otherwise.
///
/// The mechanism is deliberately NOT a `cfg!(target_os = "macos")` gate, even though Windows is
/// where this is guaranteed to bite: the reproduction above was on macOS. A platform check would
/// have fixed the CI leg and left the real bug — a stripped `PATH`, a sandbox, a wedged volume that
/// kills `df` — reporting "Excellent" forever. What decides here is whether the metrics were
/// actually measured, so Windows (where every probe fails to spawn) and a broken macOS environment
/// take the same path and get a reason naming the probe that failed.
///
/// The failure shape follows `net`/`orphans`: `ok:false`, `error.kind` `unsupported`, plus the
/// `feature`. The refusal is total — no `data` at all — because a snapshot with nothing in it has no
/// health score to report, and `health_score` cannot simply be nulled: `MoleStatus.swift` decodes it
/// with a non-optional `try c.decode(Int.self, …)`, so a null would throw and blank the dashboard,
/// history charts, MetricsStore and QueryServer together. A partial collection still returns
/// `ok:true` with the snapshot, its score marked `Degraded` and `metrics_unavailable` naming what
/// was missed — see `snapshot::health_of`.
///
/// `--watch [--interval <secs>]` turns the one-shot into a stream: see [`status_watch`].
fn status(args: &[String]) -> (String, i32) {
    if args.iter().any(|a| a == "--watch") {
        return status_watch(args);
    }
    if args.iter().any(|a| a == "--interval") {
        return (
            envelope::error_envelope(VERSION, "status", "--interval only applies with --watch"),
            2,
        );
    }
    status_response(&crate::status::snapshot::collect())
}

/// The one-shot's answer for a collected snapshot: the refusal when nothing was measured, the
/// enveloped `data` otherwise. Pure over the snapshot, so the refusal shape is tested without a
/// machine on which nothing can be measured.
fn status_response(snap: &crate::status::snapshot::Snapshot) -> (String, i32) {
    if snap.nothing_was_measured() {
        return (status_unsupported(snap), 1);
    }
    let data = crate::status::snapshot::to_json(snap);
    (envelope::envelope(VERSION, "status", ENGINE, &data), 0)
}

/// The refusal a snapshot in which nothing was measured gets — shared by the one-shot and the
/// stream so the two cannot word it differently.
fn status_unsupported(snap: &crate::status::snapshot::Snapshot) -> String {
    envelope::unsupported_envelope(
        VERSION,
        "status",
        "status",
        &format!(
            "system metrics unavailable: none of the health inputs could be measured — {}",
            snap.unavailable_summary()
        ),
    )
}

/// The environment variable that bounds a `status --watch` run to N frames. Read once at
/// start-up, by the binary only; tests drive [`status_watch_with`] with the bound injected.
pub(crate) const WATCH_FRAMES_VAR: &str = "BURROW_WATCH_FRAMES";

/// `status --watch [--interval <secs>]` — the streaming form the app's dashboard polls
/// (`MoEngine.swift:206`, gated on `supportsWatch()`), which this engine used to refuse.
///
/// Raw NDJSON on stdout: one line per tick, each line the SAME object the buffered `status` puts
/// in its envelope's `data` (`snapshot::to_json`, unwrapped), at `--interval` seconds (default 2).
/// It runs until stdout closes — the reader going away is the normal way a watch ends, so a write
/// error (EPIPE, since the Rust runtime ignores SIGPIPE) stops the loop with exit 0 rather than a
/// panic — or until `BURROW_WATCH_FRAMES` frames have been written. A tick in which nothing could be
/// measured writes the one-shot's `unsupported` envelope as the line (it carries `ok:false`, which
/// no snapshot object does) and exits 1: the stream has nothing to stream.
fn status_watch(args: &[String]) -> (String, i32) {
    let interval = match watch_interval(args) {
        Ok(d) => d,
        Err(e) => return (envelope::error_envelope(VERSION, "status", &e), 2),
    };
    let frames = frames_from_env(std::env::var(WATCH_FRAMES_VAR).ok().as_deref());
    let mut out = std::io::stdout().lock();
    // ONE CPU sampler for the whole watch: each frame's CPU window is the previous interval
    // (`status::cpu`), so no frame sleeps for a sample the way a one-shot `status` must.
    let mut sampler = crate::status::cpu::CpuSampler::new();
    let mut watcher = crate::status::process_watch::ProcessWatcher::new(Default::default());
    let started = std::time::Instant::now();
    let code = status_watch_with(
        interval,
        frames,
        || {
            crate::status::snapshot::collect_with_watch(
                &mut sampler,
                &mut watcher,
                started.elapsed(),
            )
        },
        &mut out,
        std::thread::sleep,
    );
    (String::new(), code)
}

/// `BURROW_WATCH_FRAMES` parsed: a positive frame count, or unbounded for anything else.
fn frames_from_env(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
}

/// `--interval <secs>` from argv (default 2s). Fractional seconds are accepted; zero, negative
/// and non-numeric values are refused — a cadence of nothing is not a cadence.
fn watch_interval(args: &[String]) -> Result<std::time::Duration, String> {
    let Some(i) = args.iter().position(|a| a == "--interval") else {
        return Ok(std::time::Duration::from_secs(2));
    };
    let raw = args
        .get(i + 1)
        .ok_or_else(|| "--interval needs a value in seconds".to_string())?;
    let secs: f64 = raw
        .parse()
        .map_err(|_| format!("--interval must be a number of seconds, got {raw}"))?;
    if !secs.is_finite() || secs <= 0.0 {
        return Err(format!("--interval must be positive, got {raw}"));
    }
    std::time::Duration::try_from_secs_f64(secs)
        .ok()
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| format!("--interval is outside the supported duration range: {raw}"))
}

/// [`status_watch`]'s loop with the collector, the sink, the sleep and the frame bound injected:
/// the frame shape and the stop conditions are pinned without sampling a real machine or waiting
/// out a real interval. Returns the exit code.
fn status_watch_with(
    interval: std::time::Duration,
    frames: Option<u64>,
    mut collect: impl FnMut() -> crate::status::snapshot::Snapshot,
    out: &mut impl std::io::Write,
    sleep: impl Fn(std::time::Duration),
) -> i32 {
    let mut written = 0u64;
    loop {
        let snap = collect();
        if snap.nothing_was_measured() {
            let _ = writeln!(out, "{}", status_unsupported(&snap));
            let _ = out.flush();
            return 1;
        }
        let line = crate::status::snapshot::to_json(&snap);
        if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
            // The reader closed the pipe: the watch is over, and that is not an error.
            return 0;
        }
        written += 1;
        if frames.is_some_and(|n| written >= n) {
            return 0;
        }
        sleep(interval);
    }
}

/// `clean [--apply] [--permanent]` — without `--apply`, a DRY-RUN reporting what would be cleaned
/// (deletes nothing). With `--apply`, actually removes the planned universal cache/log targets:
/// recoverably (the real macOS Trash) by default, or immediately via `--permanent`. The user's
/// whitelist (`~/.config/mole/whitelist` — this is where the GUI's Review screen writes UNTICKED
/// paths before a real run) guards both the plan and a per-item re-check in the destructive step.
///
/// Refuses outright when the home directory is unknown (see [`home_or_refuse`]): every universal
/// target is `~`-relative, so an empty home turns the whole plan into absolute `/Library/…` paths
/// that exist on no machine, and the command reported a clean sweep of nothing.
/// The deletion rails only speak unix paths (`clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS`),
/// so off unix every `--apply` candidate would come back `protected` — a run that looks like it
/// tried and was refused item by item, when the truth is that the command cannot delete here at
/// all. Say that up front, as the classified `unsupported` failure every other platform gap uses,
/// so a caller can tell "refused" from "not available". Previews are unaffected: scanning is
/// portable, only removal is not.
fn refuse_apply_off_unix(command: &str) -> Option<(String, i32)> {
    if crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS {
        return None;
    }
    Some((
        envelope::unsupported_envelope(
            VERSION,
            command,
            &format!("{command} --apply"),
            "removal is macOS only: the deletion rails do not speak this platform's paths",
        ),
        1,
    ))
}

fn clean(args: &[String]) -> (String, i32) {
    use crate::clean::{
        execute::execute_clean_with_remover, plan, protect::ProtectionMode, tool_delegate,
        whitelist,
    };
    let apply = wants_apply("clean", args);
    if apply {
        if let Some(refusal) = refuse_apply_off_unix("clean") {
            return refusal;
        }
    }
    let permanent = args.iter().any(|a| a == "--permanent");
    let home = match home_or_refuse("clean") {
        Ok(h) => h,
        Err(refusal) => return refusal,
    };
    // Load the user's active protection list. A missing/unreadable file means no EXTRA
    // protections (see `resolve_whitelist`'s doc comment for why this doesn't fall back to a
    // built-in default list) — the universal targets are still exactly what plan_clean considers.
    let whitelist_patterns = whitelist::resolve_whitelist(&home);
    let whitelist_refs: Vec<&str> = whitelist_patterns.iter().map(String::as_str).collect();
    let stream = args.iter().any(|a| a == "--stream");
    // `--plan <file>`: an exact list stands in for the scan. Branches here, after the home and
    // the whitelist are resolved and before either planner runs, because the whole point is that
    // neither planner runs — see `clean_from_plan`.
    if let Some(i) = args.iter().position(|a| a == "--plan") {
        let Some(file) = args.get(i + 1) else {
            return (
                envelope::error_envelope(VERSION, "clean", "--plan needs a file path"),
                2,
            );
        };
        return clean_from_plan(file, apply, permanent, stream, &home, &whitelist_refs);
    }
    // The static universal targets (see `plan::UNIVERSAL_TARGETS`'s doc comment) plus the dev-tool
    // caches that need an env-var guard, install-location variants, or a preference for the tool's
    // own cache-clean command (`tool_delegate`) — merged into ONE candidate list so every existing
    // consumer (JSON rendering, the NDJSON stream, the whitelist re-check, Trash-vs-permanent) sees
    // exactly the same `CleanCandidate` shape regardless of which planner produced it.
    //
    // `mode` is the `DRY_RUN` fence `plan::PlanMode` ports: identity-deduping is a PREVIEW
    // behaviour, and handing a deduped list to the executor would strand bytes. It is applied
    // again to the MERGED list because that is the scope bash's registry has — a whole-run global
    // (`DRY_RUN_SEEN_IDENTITIES`, reset once at `bin/clean.sh:975`) rather than a per-planner one —
    // so a delegated candidate that names the same bytes as a universal target collapses too. See
    // `plan::dedupe_for`, whose doc comment names this call site.
    let mode = if apply {
        plan::PlanMode::Apply
    } else {
        plan::PlanMode::DryRun
    };
    // The same `apply` fence, applied to whether resolving a dev-tool cache may SPAWN that tool.
    // Without `--apply` this run is a preview and must leave the filesystem exactly as it found it,
    // which a probe does not: `pnpm --version` through a corepack shim downloads a 38 MB tarball,
    // and `bun pm cache` / `mise cache path` / `go env GOCACHE` each create the directory they are
    // asked about. The oracle probes on its dry-run path too — see `tool_delegate::Detection` for
    // the measurement and why this is the one place the port deliberately does not follow it.
    let delegated = tool_delegate::resolve_candidates(
        &home,
        &whitelist_refs,
        if apply {
            tool_delegate::Detection::MayInvoke
        } else {
            tool_delegate::Detection::PathOnly
        },
    );
    let mut candidates = plan::plan_clean(plan::UNIVERSAL_TARGETS, &home, &whitelist_refs, mode);
    candidates.extend(delegated.iter().map(|dc| dc.candidate.clone()));
    let candidates = plan::dedupe_for(candidates, mode);

    if !apply {
        // `--stream` preview: emit one `would_remove` line per candidate (deleting nothing) + a
        // dry-run `done`. The GUI streams previews as well as live runs, so both must stream.
        if stream {
            use crate::clean::stream::{preview_done_ndjson, would_remove_ndjson};
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            for c in &candidates {
                let _ = writeln!(out, "{}", would_remove_ndjson(c));
                let _ = out.flush();
            }
            let _ = writeln!(out, "{}", preview_done_ndjson(&candidates));
            let _ = out.flush();
            return (String::new(), 0);
        }
        let data = plan::plan_to_json(&candidates);
        return (envelope::envelope(VERSION, "clean", ENGINE, &data), 0);
    }
    // `--stream`: emit one NDJSON line per item as it's removed (live progress for a GUI), then a
    // terminal `done` line. A stream can't be one buffered envelope, so this prints directly (with
    // a per-line flush) and returns an empty buffer.
    // Both apply branches route through `execute_clean_with_remover` directly (rather than the
    // `execute_clean`/`execute_clean_with` convenience wrappers) with a remover that tries each
    // dev-tool cache's own clean command first — see `tool_delegate::remover_for`'s doc comment.
    // Every UNIVERSAL_TARGETS-derived candidate is untouched by this: it never matches an entry in
    // `delegated` and falls straight through to `remove_one`, identical to before this existed.
    let remover = tool_delegate::remover_for(
        &delegated,
        &whitelist_refs,
        crate::clean::execute::remove_one_reported,
    );

    if stream {
        use crate::clean::stream::{done_ndjson, event_ndjson};
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let outcome = record_session(
            "clean",
            Some(&home),
            || {
                execute_clean_with_remover(
                    &candidates,
                    &whitelist_refs,
                    permanent,
                    // `bin/clean.sh` never exports MOLE_UNINSTALL_MODE — cleanup is the stronger
                    // regime.
                    ProtectionMode::Cleanup,
                    |ev| {
                        let _ = writeln!(out, "{}", event_ndjson(&ev));
                        let _ = out.flush();
                    },
                    &remover,
                )
            },
            // Logged from the finished outcome rather than from the live event, for the same
            // reason the buffered branch below is: a `CleanEvent` says an item was processed, not
            // whether THIS run deleted its bytes, and only the latter may produce a `trash … ok`
            // record. The NDJSON feed still streams live; only the log write moved.
            |log, outcome| {
                crate::history::write::log_clean_session(
                    log,
                    crate::clean::execute::RemovalMode::from_permanent(permanent),
                    outcome,
                )
            },
        );
        let _ = writeln!(out, "{}", done_ndjson(&outcome));
        let _ = out.flush();
        let code = if outcome.errors.is_empty() { 0 } else { 1 };
        return (String::new(), code);
    }

    let outcome = record_session(
        "clean",
        Some(&home),
        || {
            execute_clean_with_remover(
                &candidates,
                &whitelist_refs,
                permanent,
                ProtectionMode::Cleanup,
                |_| {},
                &remover,
            )
        },
        |log, outcome| {
            crate::history::write::log_clean_session(
                log,
                crate::clean::execute::RemovalMode::from_permanent(permanent),
                outcome,
            )
        },
    );
    let data = crate::clean::execute::outcome_to_json(&outcome);
    let code = if outcome.errors.is_empty() { 0 } else { 1 };
    (envelope::envelope(VERSION, "clean", ENGINE, &data), code)
}

/// `clean --plan <file> [--apply] [--permanent] [--stream]` — remove EXACTLY the paths `file` lists,
/// in file order, without re-running either planner (BUR-142). The GUI writes the file from the
/// candidates its dry run showed and the user kept, so what is removed is what was reviewed and
/// not what a second scan happens to find. Without `--apply` it is a dry run over the same list,
/// with the same refusals; `--stream` emits the same NDJSON lines as the scan's stream does.
///
/// Every listed path goes through the shared guarded remover, and is refused before that unless
/// the clean target table could have enumerated it, or the planner's own rails would have kept
/// it out of a scan — `crate::clean::plan_file` carries the reasoning. The output is the scan's
/// shape plus a `plan` object
/// (`{file, listed, refused, missing, refusals:[{path, reason}]}`), and the history session and
/// the byte accounting are the ones `clean --apply` writes.
fn clean_from_plan(
    file: &str,
    apply: bool,
    permanent: bool,
    stream: bool,
    home: &str,
    whitelist: &[&str],
) -> (String, i32) {
    use crate::clean::{plan, plan_file::PlanFile};
    use std::io::Write;
    let plan = match PlanFile::read(file, plan::UNIVERSAL_TARGETS, home, whitelist) {
        Ok(p) => p,
        Err(e) => return (envelope::error_envelope(VERSION, "clean", &e), 1),
    };

    if !apply {
        let candidates = plan.candidates();
        if stream {
            use crate::clean::stream::preview_done_line;
            let mut out = std::io::stdout().lock();
            plan.preview_events(|line| {
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            });
            let total = candidates.iter().map(|c| c.size).sum();
            let _ = writeln!(out, "{}", preview_done_line(total, candidates.len()));
            let _ = out.flush();
            return (String::new(), 0);
        }
        let data = plan.with_summary(&plan::exact_plan_to_json(&candidates));
        return (envelope::envelope(VERSION, "clean", ENGINE, &data), 0);
    }

    let record = |log: &crate::history::write::SessionLog,
                  outcome: &crate::clean::execute::CleanOutcome| {
        crate::history::write::log_clean_session(
            log,
            crate::clean::execute::RemovalMode::from_permanent(permanent),
            outcome,
        )
    };
    let remover = crate::clean::execute::remove_one_reported;

    if stream {
        use crate::clean::stream::{done_ndjson, event_ndjson};
        let mut out = std::io::stdout().lock();
        let outcome = record_session(
            "clean",
            Some(home),
            || {
                plan.execute(
                    whitelist,
                    permanent,
                    |ev| {
                        let _ = writeln!(out, "{}", event_ndjson(&ev));
                        let _ = out.flush();
                    },
                    remover,
                )
            },
            record,
        );
        let _ = writeln!(out, "{}", done_ndjson(&outcome));
        let _ = out.flush();
        let code = if outcome.errors.is_empty() { 0 } else { 1 };
        return (String::new(), code);
    }

    let outcome = record_session(
        "clean",
        Some(home),
        || plan.execute(whitelist, permanent, |_| {}, remover),
        record,
    );
    let data = plan.with_summary(&crate::clean::execute::outcome_to_json(&outcome));
    let code = if outcome.errors.is_empty() { 0 } else { 1 };
    (envelope::envelope(VERSION, "clean", ENGINE, &data), code)
}

/// The one bracket every destructive command's `--apply` runs inside: open the history session,
/// do the work, record it, close the session.
///
/// The session is opened BEFORE `work` runs — not after, which is how three of the four buffered
/// paths used to do it. digger opens its session at the top of `main` (`bin/clean.sh`,
/// `bin/optimize.sh:218`, `bin/purge.sh`) and closes it in its EXIT trap, so `started_at` is when
/// the command began and `ended_at` is when it finished. Opening the log after the work had
/// finished stamped a multi-minute clean as a zero-second session that "started" the moment it
/// ended, and a run interrupted mid-way left no session at all. The stream path already had this
/// right; this makes the order a property of the helper rather than of each call site.
///
/// `home` is passed rather than re-read so a caller that enumerates under one home never records
/// under another (see [`crate::history::log_paths_under`]).
fn record_session<T>(
    command: &str,
    home: Option<&str>,
    work: impl FnOnce() -> T,
    record: impl FnOnce(&crate::history::write::SessionLog, &T),
) -> T {
    let log = crate::history::write::SessionLog::start_under(command, home);
    let result = work();
    record(&log, &result);
    result
}

/// `optimize [--apply]` — without `--apply`, list the maintenance tasks that would run (dry-run).
/// With `--apply`, run them (flush DNS, restart the Dock, rebuild Launch Services) and report
/// per-task results. Exits 1 if any task failed.
fn optimize(args: &[String]) -> (String, i32) {
    let runner = |program: &str, cmd_args: &[&str]| match crate::status::collect::run_command(
        program, cmd_args,
    ) {
        Some(_) => Ok(()),
        None => Err(format!("{program} failed or is unavailable")),
    };
    // Not `home_or_refuse`: no task here is home-relative, so a missing home costs the history
    // record (announced on stderr by `SessionLog::start_under`), never the maintenance itself.
    optimize_with(
        args,
        crate::platform::is_root(),
        runner,
        crate::platform::home_dir().as_deref(),
    )
}

/// [`optimize`] with the elevation flag, the task runner and the history-log home injected, so the
/// `--apply` path — including the session it records — is testable without restarting anyone's
/// Dock. `elevated` decides whether a `requires_admin` task runs or is reported `skipped`
/// (`crate::optimize::REQUIRES_ADMIN`); in production it is the effective uid.
///
/// An apply records an `optimize` history session like the oracle: `bin/optimize.sh:218` opens
/// one at the top of `main` and its EXIT trap closes it with `OPTIMIZE_SAFE_COUNT` items and size
/// `0` (`:181`) — the count of tasks in the run's list, and no bytes, because nothing is deleted.
/// No per-task operation line is written (the oracle writes none; `history.golden.json`'s optimize
/// session has `operation_count: 0`).
fn optimize_with(
    args: &[String],
    elevated: bool,
    runner: impl Fn(&str, &[&str]) -> Result<(), String>,
    home: Option<&str>,
) -> (String, i32) {
    use crate::optimize::{run_optimize, TASKS};
    let apply = wants_apply("optimize", args);
    let stream = args.iter().any(|a| a == "--stream");

    if !apply {
        // `--stream` preview: one `would_run` line per task (running nothing) + a dry-run `done`.
        if stream {
            use crate::optimize::{preview_done_ndjson, would_run_ndjson};
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            for t in TASKS {
                let _ = writeln!(out, "{}", would_run_ndjson(t));
                let _ = out.flush();
            }
            let _ = writeln!(out, "{}", preview_done_ndjson(TASKS));
            let _ = out.flush();
            return (String::new(), 0);
        }
        let data = crate::optimize::to_json(TASKS);
        return (envelope::envelope(VERSION, "optimize", ENGINE, &data), 0);
    }
    let end_session = |log: &crate::history::write::SessionLog, results: &Vec<_>| {
        log.end(results.len() as u64, 0);
    };
    // `--stream`: one NDJSON `task` line per completed task (live), then a `done` line.
    if stream {
        use crate::optimize::{done_ndjson, run_optimize_with, task_ndjson};
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let results = record_session(
            "optimize",
            home,
            || {
                run_optimize_with(TASKS, elevated, runner, |r| {
                    let _ = writeln!(out, "{}", task_ndjson(r));
                    let _ = out.flush();
                })
            },
            end_session,
        );
        let _ = writeln!(out, "{}", done_ndjson(&results));
        let _ = out.flush();
        let code = i32::from(results.iter().any(|r| !r.ok));
        return (String::new(), code);
    }
    let results = record_session(
        "optimize",
        home,
        || run_optimize(TASKS, elevated, runner),
        end_session,
    );
    let any_failed = results.iter().any(|r| !r.ok);
    let data = crate::optimize::outcome_to_json(&results);
    (
        envelope::envelope(VERSION, "optimize", ENGINE, &data),
        i32::from(any_failed),
    )
}

/// `net [--limit N]` — per-process network byte usage (macOS `nettop`), highest-traffic first.
/// Read-only. Default limit 15, matching burrow-cli's `run_net`; the golden was captured with the
/// default and carries exactly 15 rows. A collection failure (nettop missing, non-zero exit, or a
/// non-macOS platform) is a classified `unsupported` failure envelope, not a silent empty success
/// — an empty `by_total_bytes` under `ok:true` is indistinguishable from "no traffic".
fn net(args: &[String]) -> (String, i32) {
    net_with(args, crate::net::collect)
}

/// [`net`] with the collector injected, so the two halves of its contract — an error envelope on
/// a collection failure, and `metric_source` on every row of a success — are pinned on every
/// platform without a 30-second nettop sample.
fn net_with(
    args: &[String],
    collect: impl FnOnce() -> Result<Vec<crate::net::ProcNet>, String>,
) -> (String, i32) {
    let rows = match collect() {
        Ok(rows) => rows,
        Err(e) => {
            return (
                envelope::unsupported_envelope(
                    VERSION,
                    "net",
                    "net",
                    &format!("per-app network unavailable: {e}"),
                ),
                1,
            )
        }
    };
    let data = net_response(rows, net_limit(args));
    (envelope::envelope(VERSION, "net", ENGINE, &data), 0)
}

/// `--limit N` from argv, defaulting to 15 — burrow-cli's `run_net` default, which is also what
/// `net.golden.json` was captured with (15 rows, `count:15`). Split out from `net` so the default
/// and the flag override are unit-testable without a real (~30s) nettop sample.
fn net_limit(args: &[String]) -> usize {
    args.iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(15)
}

/// Truncate already-collected, already-sorted rows to `limit` and serialize. Split out from `net`
/// so the truncate-then-count interaction is unit-testable against synthetic rows: `count` is
/// `rows.len()` at serialization time (see `crate::net::to_json`), so truncating AFTER computing
/// it, or truncating a stale clone, would be the one way `count` could silently drift from
/// `by_total_bytes.len()` — and that seam is invisible to a real nettop sample, which never has
/// more than a handful of processes with nonzero traffic on a quiet dev machine.
fn net_response(mut rows: Vec<crate::net::ProcNet>, limit: usize) -> String {
    rows.truncate(limit);
    crate::net::to_json(&rows)
}

/// `orphans <dir> [--installed id1,id2,…]` — list leftover cache/log/saved-state files in
/// exactly `<dir>` (scanned non-recursively) with no owning installed app (macOS). Read-only:
/// the command reports candidates and never removes anything. `<dir>` is echoed back into
/// `roots` and hit paths EXACTLY as given (oracle parity); `orphan::scan` canonicalizes it
/// internally only to decide whether a hit lands under a protected root (Preferences/Keychains/
/// Mail/Containers), so a relative path or a symlink can't hide that from the safety check
/// without changing what gets reported.
///
/// There is no default scan root. The oracle (burrow-cli's `run_orphans`) refuses the no-arg
/// form outright on macOS — deleting the wrong directory's worth of "leftovers" because the
/// caller forgot an argument is not a mistake this command gets to make silently, so a missing
/// directory is a hard error rather than a fallback sweep of some hardcoded location.
///
/// `--installed <csv>` overrides the auto-detected inventory with exactly the given names
/// (`orphan::installed_from_cli_csv`, mirroring burrow-cli's `main.rs:348-353`) — `MCP.swift`'s
/// `burrow_orphans` tool advertises this flag as "overrides the auto-detected app inventory", so
/// silently dropping it would make an agent-requested narrow scan quietly widen back out to the
/// full real inventory. Without the flag, the inventory is auto-detected
/// (`orphan::enumerate_installed_apps`); a failure to enumerate it (off macOS, or a broken
/// `/Applications`) is reported as `unsupported` rather than silently treated as "zero apps
/// installed", which would flag every app-shaped file on the system as an orphan, including apps
/// that are genuinely installed and running.
fn orphans(args: &[String]) -> (String, i32) {
    let Some(root) = first_positional("orphans", args) else {
        return (
            envelope::error_envelope(VERSION, "orphans", "needs a directory to scan"),
            1,
        );
    };
    let installed_csv = args
        .iter()
        .position(|a| a == "--installed")
        .and_then(|i| args.get(i + 1));
    let apps = match installed_csv {
        Some(csv) => crate::orphan::installed_from_cli_csv(csv),
        None => match crate::orphan::enumerate_installed_apps() {
            Ok(apps) => apps,
            Err(e) => {
                return (
                    envelope::unsupported_envelope(
                        VERSION,
                        "orphans",
                        "orphans",
                        &format!("installed-app inventory unavailable: {e}"),
                    ),
                    1,
                )
            }
        },
    };
    let installed = crate::orphan::installed_identifiers(&apps);
    // `root` is passed through EXACTLY as given — `scan` canonicalizes internally for the
    // protected-roots safety check only, so the reported `roots`/hit paths stay byte-identical to
    // what the oracle would echo (it never canonicalizes either).
    let hits = crate::orphan::scan(Path::new(root), &installed);
    let inventory_sources = crate::orphan::inventory_source_counts(&apps);
    let roots = [root.to_string()];
    let data = crate::orphan::to_json(&hits, &roots, apps.len(), &inventory_sources);
    (envelope::envelope(VERSION, "orphans", ENGINE, &data), 0)
}

/// `slim-check <binary>` — read-only Mach-O fat analysis: arch slices + bytes a thin-to-host-arch
/// would reclaim. Reads only the 4KB header. (Thinning + ad-hoc re-sign is the deferred write step.)
fn slim_check(args: &[String]) -> (String, i32) {
    use std::io::Read;
    let Some(path) = first_positional("slim-check", args) else {
        return (
            envelope::error_envelope(VERSION, "slim-check", "needs a path to a Mach-O binary"),
            2,
        );
    };
    let mut buf = vec![0u8; 4096];
    let read = match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => n,
        Err(e) => {
            return (
                envelope::error_envelope(
                    VERSION,
                    "slim-check",
                    &format!("cannot read {path}: {e}"),
                ),
                1,
            )
        }
    };
    buf.truncate(read);
    match crate::macho::parse_fat(&buf) {
        Ok(slices) => {
            let data = crate::macho::slim_check_json(path, &slices);
            (envelope::envelope(VERSION, "slim-check", ENGINE, &data), 0)
        }
        Err(e) => (envelope::error_envelope(VERSION, "slim-check", &e), 1),
    }
}

/// `evict <path...> [--apply]` — cloud-file dehydration (macOS `brctl evict`). Without `--apply`,
/// a DRY-RUN reporting each path's existence (mutates nothing). With `--apply`, evicts the local
/// copies — reversible (the provider re-downloads on access) but gated. Needs at least one path.
///
/// Off macOS BOTH halves refuse, with one envelope and one reason — see
/// [`crate::evict::platform_refusal`] for why the preview could not stay `ok:true` while the
/// apply it previews errors.
fn evict(args: &[String]) -> (String, i32) {
    // ARGV FIRST, PLATFORM SECOND, and the order is pinned by the capture: the no-path form must
    // stay `{"kind":"error","message":"evict: needs at least one path"}` (exit 2) everywhere, not
    // become an `unsupported` about a platform, because `evict.golden.provenance.txt` records that
    // exact refusal as the oracle's answer and says an engine that accepts the no-arg form has
    // diverged. Malformed argv is malformed on every platform. This is also the order burrow-cli's
    // deleted `dupes` guard used — `plan(...)` first, then the platform gate — so the two commands
    // agree on which kind of wrongness gets named first.
    let paths = match crate::evict::parse(args) {
        Ok(v) => v,
        Err(e) => return (envelope::error_envelope(VERSION, "evict", &e), 2),
    };
    let apply = wants_apply("evict", args);
    if let Some(detail) = crate::evict::platform_refusal(std::env::consts::OS) {
        return (
            envelope::unsupported_envelope(VERSION, "evict", crate::evict::EVICT_FEATURE, detail),
            1,
        );
    }
    if !apply {
        let data = crate::evict::dry_run_json(&paths);
        return (envelope::envelope(VERSION, "evict", ENGINE, &data), 0);
    }
    match crate::evict::execute_apply_json(&paths) {
        Ok(data) => (envelope::envelope(VERSION, "evict", ENGINE, &data), 0),
        Err(e) => (envelope::error_envelope(VERSION, "evict", &e), 1),
    }
}

/// `dupes <group|dedupe|remove|link> [--keep <dir>]... <path...> [--apply]` — duplicate-file
/// engine over the fclones sidecar. `group` (and any action without `--apply`) is read-only:
/// `group` returns the report, the mutating actions return fclones's own `--dry-run` preview.
/// `--apply` runs the mutation (reference folders under `--keep` are never acted on).
///
/// The READ paths' payloads are already JSON and ride verbatim as the envelope's `data`; an
/// `--apply` is the exception, because fclones reports a completed action on stderr and leaves
/// stdout empty. See the `wrap` call below for why that distinction is load-bearing.
fn dupes(args: &[String]) -> (String, i32) {
    // The subcommand is OPTIONAL and defaults to the read-only `group`, exactly as the oracle's
    // `run_dupes` resolves it (`burrow-cli/src/main.rs:205-208`):
    //
    // ```rust
    // let (sub, rest) = match args.first().map(String::as_str) {
    //     Some(s @ ("group" | "dedupe" | "remove" | "link")) => (s, &args[1..]),
    //     _ => ("group", args),
    // };
    // ```
    //
    // Requiring it instead killed a live MCP tool: `burrow_dupes` sends
    // `callConductor("dupes", paths)` (`MCP.swift:1239`), which `BurrowConductor.argv` turns into
    // `["dupes", <path>, "--json"]` with no subcommand at all — so every agent call landed on
    // `unknown subcommand '<path>'` while the same argv works against the oracle. `DupesView`
    // spells `group` out (`DupesView.swift:544`) and is unaffected either way.
    let (sub, rest): (&str, &[String]) = match args.first().map(String::as_str) {
        Some(s @ ("group" | "dedupe" | "remove" | "link")) => (s, &args[1..]),
        _ => ("group", args),
    };
    let apply = wants_apply("dupes", args);
    let plan = match crate::dupes::plan(sub, rest, apply) {
        Ok(p) => p,
        Err(e) => return (envelope::error_envelope(VERSION, "dupes", &e), 2),
    };
    // The restored `--apply` guard, in the oracle's own position: AFTER `plan` (so a malformed
    // argv is still told it is malformed, on every platform) and BEFORE `resolve_fclones` (so
    // finding a real fclones cannot buy the mutation back — the promise burrow-cli's README made
    // was "Burrow does not delete duplicate files on Windows", not "unless you set an env var").
    //
    // Keyed on `--apply` anywhere in the FULL argv, exactly as `run_dupes` keyed it, rather than
    // on the resolved plan variant. The two differ on one input — `dupes group <dir> --apply`,
    // which `plan` collapses to a read-only `Group` and which the oracle refused anyway — and the
    // oracle's answer is the better one: `--apply` names a write, so silently serving a read
    // report for it would be the same accept-and-ignore this file refuses everywhere else.
    if apply {
        if let Some(detail) = crate::dupes::apply_refusal(std::env::consts::OS) {
            return (
                envelope::unsupported_envelope(
                    VERSION,
                    "dupes",
                    crate::dupes::APPLY_FEATURE,
                    detail,
                ),
                1,
            );
        }
    }
    let fclones = match crate::dupes::resolve_fclones() {
        Ok(f) => f,
        Err(e) => return (envelope::error_envelope(VERSION, "dupes", &e), 1),
    };
    match crate::dupes::execute(&fclones, &plan) {
        Ok(data) => (dupes_envelope(&data), 0),
        Err(e) => (envelope::error_envelope(VERSION, "dupes", &e), 1),
    }
}

/// Wrap whatever `dupes::execute` returned in the envelope.
///
/// `wrap`, NOT `envelope` — `dupes` is the one command whose `data` is a foreign process's stdout
/// rather than something this crate serialized, so it is the one call site where `envelope`'s
/// "already-valid JSON" precondition can actually be false.
///
/// `fclones remove|link|dedupe` write their report to STDERR and print NOTHING on stdout, so an
/// `--apply` reached `envelope` — which splices `data` in verbatim — holding an empty string, and
/// emitted `{…,"data":}`, which is not JSON at all. The run had really deleted the file by then, so
/// every consumer failed to decode a SUCCESS: the one shape where a caller cannot tell success from
/// catastrophe.
///
/// `wrap` is the ORACLE's answer, not a nicer one invented here. `run_dupes` handed fclones's
/// stdout to `emit` -> `emit_as` -> `output::wrap` (`burrow-cli/src/main.rs:181,932-943` at
/// 3633c19^), whose text branch produced `data:{"text":""}` — captured from the shipping binary
/// into `dupes-apply.golden.json`. Synthesizing a richer result (files removed, bytes freed) was
/// the tempting alternative and it is the wrong one twice over: the numbers exist only in
/// fclones's stderr, which the oracle never reads, and `BurrowConductor`/the MCP tools were
/// written against the text shape.
///
/// The READ payloads are untouched — `group`'s report, `Preview`'s `preview_json` and
/// `NOTHING_ACTIONABLE` all start with `{`, so `wrap` routes them through `envelope` verbatim
/// exactly as before. It is a separate function only so a test can pin THIS boundary without a
/// real fclones on the box; inlining it put the contract out of reach of `cargo test` on every
/// runner, which is how the bug shipped.
pub(crate) fn dupes_envelope(data: &str) -> String {
    envelope::wrap(VERSION, "dupes", ENGINE, data)
}

/// `photos <dir> [--threshold N]` — find visually-similar PNG/JPEG images via perceptual hashing
/// (dHash, default threshold 10). Read-only: reports similar groups + a tally of formats it
/// couldn't decode (HEIC & friends) so an iPhone folder reads as "can't decode yet", not empty.
fn photos(args: &[String]) -> (String, i32) {
    let Some(dir) = first_positional("photos", args) else {
        return (
            envelope::error_envelope(VERSION, "photos", "photos needs a directory to scan"),
            2,
        );
    };
    let threshold = args
        .iter()
        .position(|a| a == "--threshold")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(10);
    let path = Path::new(dir);
    let groups = crate::photos::scan(path, threshold, |p| crate::photos::hash_file(p).ok());
    let unsupported = crate::photos::count_unsupported(path);
    let data = crate::photos::report_json(dir, threshold, &groups, &unsupported);
    (envelope::envelope(VERSION, "photos", ENGINE, &data), 0)
}

/// `history [--limit N]` — review past cleanup activity. Reads the mole operations + deletions
/// logs and emits the sessions/deletions (newest-first, default 20, max 200). Read-only.
///
/// Log files that do not exist yet stay a successful empty history — that is a fresh install. Log
/// paths that could not be RESOLVED are a failure, because the empty history they used to produce
/// was indistinguishable from the fresh-install case while naming a `/Library/Logs/…` file the user
/// has never had. Unlike its five siblings this does not go through `home_or_refuse`: a complete
/// pair of `MOLE_OPERATIONS_LOG`/`MOLE_DELETE_LOG` overrides answers with no home at all, so the
/// condition belongs in `history::log_paths` where that is visible, not here.
fn history(args: &[String]) -> (String, i32) {
    let limit = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u64>().ok());
    match crate::history::collect(limit) {
        Ok(data) => (envelope::envelope(VERSION, "history", ENGINE, &data), 0),
        Err(e) => (envelope::error_envelope(VERSION, "history", &e), 1),
    }
}

/// `purge [--apply]` — find heavy, regenerable project build artifacts (node_modules, target,
/// DerivedData…) under the user's code roots. Without `--apply`, a DRY-RUN reporting candidates +
/// total size (deletes nothing). With `--apply`, removes them — recoverably (the real macOS Trash)
/// by default, or immediately via `--permanent` — the protection guard is re-checked per item
/// (defense in depth) so bin//vendor/global-DerivedData are never removed. The removal is recorded
/// to the mole history log as a `purge` session.
///
/// `--stream` emits the run as NDJSON instead of one envelope — the SAME lines `clean --stream`
/// emits (`would_remove` … `done{dry_run:true,…}` for a preview; `removed`/`failed`/`protected` …
/// `done{freed_bytes,…}` live), so the app's one stream reader serves both. See
/// [`crate::clean::stream`].
fn purge(args: &[String]) -> (String, i32) {
    let apply = wants_apply("purge", args);
    if apply {
        if let Some(refusal) = refuse_apply_off_unix("purge") {
            return refusal;
        }
    }
    let permanent = args.iter().any(|a| a == "--permanent");
    let stream = args.iter().any(|a| a == "--stream");
    // Every search root is `~`-relative (`purge::resolve_search_paths`), so with no home this used
    // to scan `/Developer`, `/code`, … — nonexistent absolute paths — and report a successful
    // "no build artifacts found". See `home_or_refuse`.
    let home = match home_or_refuse("purge") {
        Ok(h) => h,
        Err(refusal) => return refusal,
    };
    let roots = crate::purge::resolve_search_paths(&home);
    let reviewed = args.iter().any(|a| a == "--plan");
    let artifacts = if reviewed {
        match sweep_plan_paths(args)
            .and_then(|paths| crate::purge::from_reviewed_paths(&paths, &roots))
        {
            Ok(artifacts) => artifacts,
            Err(error) => return (envelope::error_envelope(VERSION, "purge", &error), 1),
        }
    } else {
        crate::purge::scan(&roots)
    };

    if !apply {
        if stream {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            for line in crate::purge::preview_stream_lines(&artifacts) {
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
            return (String::new(), 0);
        }
        let data = crate::purge::to_json(&artifacts);
        return (envelope::envelope(VERSION, "purge", ENGINE, &data), 0);
    }
    if stream {
        use crate::clean::stream::{done_ndjson, event_ndjson};
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let outcome = record_session(
            "purge",
            Some(&home),
            || {
                let emit = |ev: crate::clean::execute::CleanEvent<'_>| {
                    let _ = writeln!(out, "{}", event_ndjson(&ev));
                    let _ = out.flush();
                };
                if reviewed {
                    crate::purge::execute_reviewed_with(&artifacts, &roots, permanent, emit)
                } else {
                    crate::purge::execute_with(&artifacts, permanent, emit)
                }
            },
            |log, outcome| {
                crate::history::write::log_clean_session(
                    log,
                    crate::clean::execute::RemovalMode::from_permanent(permanent),
                    outcome,
                )
            },
        );
        let _ = writeln!(out, "{}", done_ndjson(&outcome));
        let _ = out.flush();
        let code = if outcome.errors.is_empty() { 0 } else { 1 };
        return (String::new(), code);
    }
    // Recorded to the mole history logs with the same lines, from the same outcome shape, as
    // `clean` (REMOVED per artifact + a deletion audit record for each one this run really removed).
    let outcome = record_session(
        "purge",
        Some(&home),
        || {
            if reviewed {
                crate::purge::execute_reviewed_with(&artifacts, &roots, permanent, |_| {})
            } else {
                crate::purge::execute(&artifacts, permanent)
            }
        },
        |log, outcome| {
            crate::history::write::log_clean_session(
                log,
                crate::clean::execute::RemovalMode::from_permanent(permanent),
                outcome,
            )
        },
    );

    let data = crate::purge::outcome_to_json(&outcome);
    let code = if outcome.errors.is_empty() { 0 } else { 1 };
    (envelope::envelope(VERSION, "purge", ENGINE, &data), code)
}

/// `installer [--apply] [--permanent]` — find leftover installer files (.dmg/.pkg/.mpkg/.iso/.xip +
/// installer .zips) in the download locations. Without `--apply`, a DRY-RUN reporting them + total
/// size (deletes nothing). With `--apply`, removes them — recoverably (the real macOS Trash) by
/// default, or immediately via `--permanent` — and records an `installer` history session.
fn installer(args: &[String]) -> (String, i32) {
    let apply = wants_apply("installer", args);
    if apply {
        if let Some(refusal) = refuse_apply_off_unix("installer") {
            return refusal;
        }
    }
    let permanent = args.iter().any(|a| a == "--permanent");
    // `installer::scan_paths` is entirely `~/Downloads`, `~/Desktop`, `~/Documents`. With no home
    // those became `/Downloads`, `/Desktop`, `/Documents` and the command always found zero
    // leftover installers, successfully. See `home_or_refuse`.
    let home = match home_or_refuse("installer") {
        Ok(h) => h,
        Err(refusal) => return refusal,
    };
    let roots = crate::installer::scan_paths(&home);
    let reviewed = args.iter().any(|a| a == "--plan");
    let installers = if reviewed {
        match sweep_plan_paths(args)
            .and_then(|paths| crate::installer::from_reviewed_paths(&paths, &roots))
        {
            Ok(installers) => installers,
            Err(error) => return (envelope::error_envelope(VERSION, "installer", &error), 1),
        }
    } else {
        crate::installer::scan(&roots)
    };

    if !apply {
        let data = crate::installer::to_json(&installers);
        return (envelope::envelope(VERSION, "installer", ENGINE, &data), 0);
    }
    let outcome = record_session(
        "installer",
        Some(&home),
        || {
            if reviewed {
                crate::installer::execute_reviewed(&installers, &roots, permanent)
            } else {
                crate::installer::execute(&installers, permanent)
            }
        },
        |log, outcome| {
            crate::history::write::log_clean_session(
                log,
                crate::clean::execute::RemovalMode::from_permanent(permanent),
                outcome,
            )
        },
    );

    let data = crate::installer::outcome_to_json(&outcome, &installers);
    let code = if outcome.errors.is_empty() { 0 } else { 1 };
    (
        envelope::envelope(VERSION, "installer", ENGINE, &data),
        code,
    )
}

fn sweep_plan_paths(args: &[String]) -> Result<Vec<String>, String> {
    let file = args
        .iter()
        .position(|a| a == "--plan")
        .and_then(|index| args.get(index + 1))
        .ok_or_else(|| "--plan needs a file path".to_string())?;
    crate::reviewed_plan::read_paths(file)
}

/// `uninstall <name>… [--apply] [--permanent]` — resolve every named app against the installed
/// inventory, then find each one's leftover files under ~/Library. Without `--apply`, list them
/// (paths + sizes), deleting nothing. With `--apply`, remove them — recoverably (the real macOS
/// Trash) by default, or immediately via `--permanent`, matching the MCP tool's documented "Trash
/// (recoverable) unless `permanent` is true" contract.
///
/// # Every positional is an app, and every one of them is resolved first
///
/// This used to read ONE positional and interpolate it straight into `~/Library/Containers/{arg}`.
/// Both halves of that were wrong against the oracle, which collects an unbounded `app_name_args`
/// array and hands the whole thing to `match_apps_by_name` (`bin/uninstall.sh:1392`) before acting:
///
///  - A Software-tab multi-select really does arrive as several positionals (`MoActions.argv` →
///    `BurrowConductor.engineArgv` → `["uninstall", app1, app2, app3, "--apply"]`). Three apps in,
///    one uninstalled, three reported as done.
///  - An argument that matches no installed app answered `ok:true` with an empty `items` list, which
///    a caller cannot tell from "installed, and it has no leftovers". The oracle exits 1 with
///    `No matching applications found.`
///
/// Resolution lives in [`crate::uninstall::resolve`] and is fed the same inventory `--list` prints,
/// so `uninstall` accepts exactly what `--list` advertises under `UNINSTALL NAME` — plus bundle ids,
/// which is what this engine's own callers send. See that module for the ported algorithm.
///
/// # What this command removes
///
/// The APPLICATION BUNDLE and the per-app support files under `~/Library` — containers, caches,
/// preferences, logs, saved state (see [`crate::uninstall::leftover_paths`]). The bundle half is
/// [`crate::uninstall::bundle`]; read its module docs before changing anything here, because the
/// ORDER is load-bearing and not obvious. The oracle removes the bundle FIRST and gates the whole
/// leftover sweep on that having worked (`batch.sh:840`'s `if [[ -z "$reason" ]]`), so an app whose
/// bundle could not be removed keeps its support files too rather than being half-uninstalled.
///
/// Every entry in `items[]` (dry run) and `removed[]` (apply) carries a `kind` of `"application"` or
/// `"leftover"`, so a caller can tell "we removed 3 support directories" from "we removed the
/// application and 3 support directories". Per-app, `apps[].status` is `removed` / `partial` /
/// `refused`, and `apps[].application` carries the bundle's own state — because leftovers going
/// while the bundle stays is not a success, and used to report as one.
///
/// Runs the shared executor under [`ProtectionMode::Uninstall`], the port of the
/// `MOLE_UNINSTALL_MODE=1` that `lib/uninstall/batch.sh:667` exports around its whole removal phase.
/// Without it this command removed NOTHING for every bundle ID `should_protect_data` covers —
/// JetBrains, Microsoft, Adobe, Docker, 1Password, Slack, Dropbox, Firefox — while still reporting
/// success, because the cleanup-mode rail is designed to protect exactly the data an uninstall
/// exists to remove.
fn uninstall(args: &[String]) -> (String, i32) {
    // `--list` short-circuits before any destructive code, exactly as the oracle does
    // (`bin/uninstall.sh:1364`, "short-circuits before any destructive code"): scan, resolve
    // uninstall names, print, exit 0. It wins over a positional too — the oracle sets `list_mode`
    // during flag parsing and returns before ever looking at `app_name_args`.
    if args.iter().any(|a| a == "--list") {
        return uninstall_list();
    }
    // `uninstall` needs the home to build the leftover-file candidates (`~/Library/Caches`,
    // `~/Library/Preferences`, …). Without one it would resolve an app and then report that it had
    // no leftovers to remove — the same false-clean the other five commands gave. See
    // `home_or_refuse`.
    let home = match home_or_refuse("uninstall") {
        Ok(h) => h,
        Err(refusal) => return refusal,
    };
    uninstall_resolved(args, &crate::uninstall::list::collect(), &home)
}

/// [`uninstall`] with the installed inventory and the home directory injected — the seam that makes
/// the whole command testable without a real `/Applications` scan and without touching the
/// developer's own `~/Library`.
///
/// The scan is a few seconds of `plutil`/`mdls`/`brew` per run and exists only on macOS, so a test
/// that drove the real thing would be slow on one CI runner and vacuous on the other two. `home` is
/// a parameter rather than an env read for the same reason `io_rate` avoids one: `set_var` races
/// every other test in the process. Everything that decides an outcome — argv parsing, the
/// protection gate, resolution, the removal call, the JSON — stays on the tested side.
fn uninstall_resolved(
    args: &[String],
    inventory: &[crate::uninstall::list::AppRow],
    home: &str,
) -> (String, i32) {
    uninstall_resolved_with(args, inventory, home, &default_uninstall_runner)
}

/// The subprocess runner [`uninstall_resolved`] injects. In production it is
/// [`crate::uninstall::bundle::system_runner`].
///
/// **Under `cfg(test)` it PANICS**, and that is the point. `uninstall_resolved` is the form that
/// does NOT let a caller inject a fake, so a test that hands it an inventory row with
/// `source: "Homebrew"` runs `brew uninstall --cask --zap <token>` against the developer's own
/// machine — and four of this file's tests build inventories by hand from `golden_inventory()`,
/// whose rows carry REAL cask tokens (`bitwarden`, `inkscape`, `stats`). Nothing but convention,
/// re-established by hand at each site, kept that from happening; `EPERM` would not have stopped it,
/// because `brew` needs no elevation to remove a user's own cask.
///
/// So the convention is replaced by a wall. Every brew-path test goes through
/// [`uninstall_resolved_with`] and its `Recorder`; anything that reaches this in a test is a test
/// that was about to shell out for real, and it fails loudly instead.
#[cfg(not(test))]
fn default_uninstall_runner(
    program: &str,
    args: &[&str],
    timeout: std::time::Duration,
) -> Option<String> {
    crate::uninstall::bundle::system_runner(program, args, timeout)
}

#[cfg(test)]
fn default_uninstall_runner(
    program: &str,
    args: &[&str],
    _timeout: std::time::Duration,
) -> Option<String> {
    panic!(
        "a test reached the REAL subprocess runner and was about to run `{program} {args:?}` \
         against this machine. Drive the brew path through `uninstall_resolved_with` with a fake."
    );
}

/// [`uninstall_resolved`] with the SUBPROCESS runner injected too — the second seam, and it exists
/// for one reason: this command can run `brew uninstall --cask --zap`, which deletes an application
/// and, via the cask's zap stanza, an unbounded set of other paths. Every brew decision therefore
/// has to be drivable from a fake, so that no test is one bad fixture away from running it for
/// real. Production goes through [`crate::uninstall::bundle::system_runner`].
///
/// This is the parsing + envelope half; the orchestration — resolution, the confirmation gate,
/// bundle removal, the leftover sweep, the audit log, the payload — is
/// [`crate::uninstall::apply::uninstall`], which knows nothing about argv or envelopes.
fn uninstall_resolved_with(
    args: &[String],
    inventory: &[crate::uninstall::list::AppRow],
    home: &str,
    run: crate::uninstall::bundle::Runner,
) -> (String, i32) {
    let request = crate::uninstall::apply::Request {
        terms: positionals("uninstall", args),
        apply: wants_apply("uninstall", args),
        permanent: args.iter().any(|a| a == "--permanent"),
    };
    match crate::uninstall::apply::uninstall(&request, inventory, home, run) {
        Ok((data, code)) => (
            envelope::envelope(VERSION, "uninstall", ENGINE, &data),
            code,
        ),
        Err(message) => (envelope::error_envelope(VERSION, "uninstall", &message), 1),
    }
}

/// `uninstall --list` — the read-only app inventory, and the ONE command that does not emit the
/// Burrow envelope.
///
/// The app pipes this command's stdout straight into `MoleClient.parseApps`, which does
/// `JSONSerialization.jsonObject(...) as? [[String: Any]]` and yields `[]` for anything that is not
/// a top-level array. Wrapping it would therefore blank the Software tab and report no error at
/// all. `crate::uninstall::list::to_json` is the only serializer and it never wraps; the shape is
/// pinned by `uninstall-list.golden.json`.
///
/// The oracle emits JSON whenever stdout is not a TTY (`bin/uninstall.sh:1222`) and a text table
/// otherwise; the engine is never interactive, so JSON is the only mode.
#[cfg(target_os = "macos")]
fn uninstall_list() -> (String, i32) {
    (
        crate::uninstall::list::to_json(&crate::uninstall::list::collect()),
        0,
    )
}

/// Off macOS there is no app inventory to enumerate. Reporting an empty array here would be the
/// same silent blank-pane lie the bare-array contract exists to prevent, so this is a classified
/// failure instead — the caller can tell "nothing installed" from "cannot look".
#[cfg(not(target_os = "macos"))]
fn uninstall_list() -> (String, i32) {
    (
        envelope::unsupported_envelope(VERSION, "uninstall", ENGINE, "app inventory is macOS only"),
        1,
    )
}

/// `version` / `--version` / `-V` — report the engine's own version.
///
/// The oracle accepts all three spellings and exits 0 (`mole:1080`, `"version" | "--version" |
/// "-V")`). The engine previously accepted none of them: all three fell through to `unknown
/// command` with exit 2, and the app's `MoleCLI.version()` then scraped the first semver-shaped
/// token out of that ERROR envelope — which is the envelope's own `burrow_cli` field. It returned a
/// version parsed out of a failure, and five call sites believed it.
///
/// The version reported here is the ENGINE's (`CARGO_PKG_VERSION`), on its own 0.x line. It is not
/// comparable with mo's numbering, so a consumer must not test it against an mo threshold: the
/// app's `minimumWatchVersion = "1.44.0"` gate is on a scale this program never joins. Read
/// `data.version` rather than scraping, and gate streaming on a capability, not on this number.
///
/// **This command's real decoder is a scraper, so an "extra" field here is not free.** Nothing in
/// the app reads `data.version`; `MoleCLI.version()` (`MoleCLI.swift:158-174`) takes the whole
/// stdout, splits it on every character that is not a digit or a dot, and returns the FIRST token
/// with two or more all-numeric parts. The payload used to carry `os_version` (`26.5.2`) and
/// `kernel` (`25.5.0`) — both dotted-numeric, both far past the `1.44.0` streaming gate — and the
/// only thing keeping the scrape off them was that the envelope happens to print `burrow_cli`
/// first. A field reorder, or dropping `burrow_cli`, would have returned `26.5.2`, flipped
/// `supportsWatch()` to true, and had the app wait on an NDJSON stream from a command that refuses
/// `--watch`.
///
/// So they are gone, and the invariant is structural rather than positional: with `arch` (`arm64`
/// — letters are separators, `64` is a single part) the only dotted-numeric tokens this command can
/// emit are the engine's own version, twice. No ordering can arm the gate because there is nothing
/// left to arm it with. `os_version` is not lost — `status` already reports it as
/// `hardware.os_version` (`crate::status::snapshot`), which is where a consumer that wants the OS
/// should read it. `the_version_the_app_scrapes_stays_below_the_streaming_gate` runs the Swift
/// scraper's own algorithm over this command's real stdout, so re-adding a dotted field turns red.
fn version() -> (String, i32) {
    let data = format!(
        "{{\"version\":{},\"engine\":{},\"arch\":{}}}",
        json_str(VERSION),
        json_str(ENGINE),
        json_str(&crate::platform::machine_architecture()),
    );
    (envelope::envelope(VERSION, "version", ENGINE, &data), 0)
}

/// `help` / `--help` / `-h` — the command surface, envelope-wrapped, exit 0.
///
/// The original prints a human table and exits 0 (`mole:1076-1079` → `show_help`); this engine has
/// no human mode, so the same content rides as `data`. The command list is DERIVED from
/// `allowed_flags` rather than typed out beside it, so a command whose flags change cannot leave a
/// stale help text behind — the failure mode of every hand-maintained usage string.
///
/// `--help` on a specific command (`mo uninstall --help`, `bin/uninstall.sh:1328`) is a separate
/// oracle behaviour that is NOT ported: it stays an unknown flag and is refused by name, which is
/// louder than accepting it and printing nothing.
///
/// Each row also carries `mutually_exclusive`, because a flat `flags` list is what an agent reads
/// when it composes argv and a flat list is what made `--apply --dry-run` look like a reasonable
/// belt-and-braces thing to type (see [`wants_apply`]). Derived the same way as `flags`, so a
/// command cannot advertise an exclusivity it does not enforce, or enforce one it does not
/// advertise.
fn help() -> (String, i32) {
    let rows = COMMANDS
        .iter()
        .map(|c| {
            let declared = allowed_flags(c).unwrap_or(&[]);
            let flags = declared
                .iter()
                .map(|(name, takes_value)| {
                    if *takes_value {
                        format!("\"{name} <value>\"")
                    } else {
                        format!("\"{name}\"")
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            let has = |f: &str| declared.iter().any(|(name, _)| *name == f);
            let dry: Vec<String> = ["--dry-run", "-n"]
                .into_iter()
                .filter(|f| has(f))
                .map(json_str)
                .collect();
            let exclusive = if has("--apply") && !dry.is_empty() {
                format!("[[\"--apply\"],[{}]]", dry.join(","))
            } else {
                "[]".to_string()
            };
            format!(
                "{{\"command\":{},\"flags\":[{}],\"mutually_exclusive\":{}}}",
                json_str(c),
                flags,
                exclusive
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let global = GLOBAL_FLAGS
        .iter()
        .map(|(name, _)| json_str(name))
        .collect::<Vec<_>>()
        .join(",");
    let data = format!(
        "{{\"engine\":{},\"version\":{},\"global_flags\":[{}],\"commands\":[{}]}}",
        json_str(ENGINE),
        json_str(VERSION),
        global,
        rows
    );
    (envelope::envelope(VERSION, "help", ENGINE, &data), 0)
}

/// One accepted flag: its spelling, and whether it consumes the NEXT argv token as its value.
///
/// `true` means the flag is written `--flag <value>` and the token after it BELONGS to it — the
/// distinction the positional walk in [`positionals`] runs on. There is deliberately no
/// `--flag=value` form: neither half of the oracle parses one. burrow-cli's `flag_value`
/// (`src/main.rs:937-942`) is `position(|a| a == flag)` then `get(i + 1)`, and the bash arm is an
/// exact-match `case` (`bin/uninstall.sh:1328-1358`) whose `-*)` fallback turns `--dry-run=1` into
/// `Unknown uninstall option`. Adding `=` support here would accept argv the original refuses.
type FlagSpec = (&'static str, bool);

/// Flags the CONDUCTOR contract defines for every command, not any one command.
///
/// `BurrowConductor.argv` (`Burrow-phaseb/macos/Sources/BurrowConductor.swift:63-66`) is
/// `[command] + args + ["--json"]` — unconditional, appended to EVERY capture the app makes. It is
/// global on the other side too: burrow-cli's `is_conductor_flag` (`src/engine.rs:26-28`) filters
/// `--apply | --json | --raw | --stream` out of the args before dispatch, and `--json` there means
/// `force_json` (`src/main.rs:170`) — "emit the machine shape even though stdout is a TTY".
/// Verified live against the shipping oracle, which accepts it on every command:
///
/// ```text
/// $ burrow net --json           → exit 0, {"burrow_cli":…,"command":"net",…}
/// $ burrow photos /tmp --json   → exit 0
/// $ burrow orphans /tmp --json  → exit 0
/// $ burrow slim-check /bin/ls --json → exit 0
/// ```
///
/// Listing it per-command instead demoted a global to an opt-in and then enumerated it wrong: it
/// reached only `analyze`/`status`/`history`, so `net`, `orphans`, `photos`, `slim-check` and
/// `dupes` — ten live GUI + MCP call sites — answered every capture with `unknown <cmd> option:
/// --json` and exit 2. `slim-check`'s list was `&[]`, so the one flag the app always sends was the
/// only flag it could ever receive.
///
/// The other three of the oracle's conductor set are deliberately NOT here:
///
/// - `--apply` and `--stream` name a BEHAVIOUR (mutate rather than preview; stream rather than
///   buffer). A command that has no such behaviour must not accept them — that is the `status
///   --watch` failure, where a flag that changes the output contract was accepted, ignored, and
///   answered with one non-streaming envelope. They stay per-command, on the commands that
///   implement them.
/// - `--raw` asks for the payload WITHOUT the envelope (`emit_as`, `src/main.rs:983-990`). This
///   engine has exactly one output mode and cannot honour that, so it refuses rather than wrapping
///   the answer anyway and calling it success. The oracle accepts-and-ignores it on these commands
///   (`burrow photos /tmp --raw` → exit 0, still enveloped); this is a deliberate divergence in the
///   strict direction, on a flag that appears nowhere in the app's Swift sources. `--json` gets the
///   opposite treatment because it asks for something already true of every response.
const GLOBAL_FLAGS: &[FlagSpec] = &[("--json", false)];

/// Every command `dispatch` serves, in the order `help` lists them. Kept beside the flag table
/// because both `help` and the flag-coverage tests walk it — a command added to `dispatch` and
/// forgotten here shows up as a missing help row rather than as nothing at all.
const COMMANDS: &[&str] = &[
    "analyze",
    "status",
    "clean",
    "optimize",
    "uninstall",
    "net",
    "orphans",
    "slim-check",
    "evict",
    "dupes",
    "photos",
    "history",
    "purge",
    "installer",
    "rules",
    "sentinel",
];

/// The flags each command defines, beyond [`GLOBAL_FLAGS`]. `None` means the command is not one of
/// ours (the caller reports `unknown command` instead).
///
/// This table is what makes an unrecognised flag an ERROR rather than a silent no-op. Both halves
/// of the oracle reject one: bash prints `Unknown uninstall option: $arg` and exits 1
/// (`bin/uninstall.sh:1351`), and the Go status binary's `flag` package prints `flag provided but
/// not defined` and exits 2.
///
/// It is also the ONE place that records which flags take a value, so the next flag added cannot
/// forget to declare itself and quietly re-open the bug where `photos --threshold 8 /tmp` scanned a
/// directory named `8`. Every `true` below was derived by reading the parse at each call site, not
/// from a list: `--limit` (`net_limit`, `history`), `--installed` (`orphans`), `--threshold`
/// (`photos`), `--keep` (`crate::dupes::split_keep`) — every other flag is tested with
/// `args.iter().any(|a| a == "--x")` and consumes nothing.
///
/// # This table is DERIVED, not remembered
///
/// Written down from memory it produced three outages in a row — `--json` granted to 3 of 14
/// commands while the conductor appends it to every capture; `dupes` reachable only with a
/// subcommand the app never sends; and `purge --dry-run` refused while `bin/purge.sh:322` accepts
/// it and `MoActions.swift:75` sends it. So every row below is transcribed from a `case` arm, a
/// `flag.Bool`, or a `flag_value` call, and both directions are then re-derived mechanically by
/// `every_oracle_flag_is_accepted_or_refused_on_purpose` and
/// `no_flag_is_accepted_that_no_oracle_defines`, which carry the same file:line citations. A flag
/// added here without an oracle, or dropped here while an oracle still reads it, fails a test.
///
/// The three dispositions, and the rule that picks between them:
///
/// - **Accepted-and-ignored** when the original accepts it and honouring it would change nothing
///   this engine emits on stdout. `--dry-run`/`-n` are the default whenever `--apply` is absent
///   (`bin/purge.sh:322`, `bin/clean.sh:1433`, `bin/uninstall.sh:1336`, `bin/installer.sh:821`,
///   `bin/optimize.sh:203` — note optimize's arm is `--dry-run` ALONE, no `-n`). `--debug` sets
///   `MO_DEBUG=1`, which in the original only appends to `$DEBUG_LOG_FILE` and stderr
///   (`lib/core/log.sh:101-103,253-256`) and never touches stdout, so a caller reading the
///   envelope cannot tell the difference. Refusing either would be a divergence for no gain.
/// - **Refused** when the flag names a BEHAVIOUR this engine does not have, because silently
///   ignoring one is the `status --watch` failure of old (it is implemented now, as is
///   `analyze --progress`; `--watch-interval`, `cmd/status/main.go:32`, is still refused in
///   favour of the engine's `--interval <secs>`). `--raw`
///   (`burrow-cli/src/main.rs:169`), `--whitelist`/`--paths` (interactive managers that exit 0
///   without running the command: `bin/clean.sh:1445`, `bin/optimize.sh:206`, `bin/purge.sh:310`),
///   `--external <path>` (retargets clean at another volume, `bin/clean.sh:1437` — accepting and
///   ignoring it would clean the INTERNAL disk instead), `--include-empty` (`bin/purge.sh:325`),
///   and the `--proc-cpu-*` alert tuning (`cmd/status/main.go:28-30`). Each is listed with its
///   reason in `REFUSED_ON_PURPOSE` so the refusal is visible rather than merely absent.
/// - **Engine extension** where this engine implements something the bash oracle offers only
///   elsewhere: `--permanent` on clean/purge/installer. Bash has that switch on `uninstall` only
///   (`bin/uninstall.sh:1339`), but `clean`/`purge`/`installer` here read it for real
///   (`cli.rs:77`, `:523`, `:563`) to opt out of Trash routing, so dropping it would disable
///   implemented behaviour rather than fix a divergence. Justified in `ENGINE_EXTENSIONS`.
///
/// `--help`/`-h` stays refused — see [`help`]. Adding it here would be the WRONG fix: an accepted
/// no-op flag means `clean --help` runs a real clean scan, where the oracle exits 0 having done
/// nothing. The two halves of the oracle also disagree on it (bash prints a human table and exits
/// 0; Go's `flag` prints usage and exits 2), so there is no single original behaviour to copy.
fn allowed_flags(command: &str) -> Option<&'static [FlagSpec]> {
    Some(match command {
        // `--progress` (`cmd/analyze/main.go:21`) streams the scan — see `analyze_progress_with`.
        "analyze" => &[("--progress", false)][..],
        // `--watch` (`cmd/status/main.go:31`) streams snapshots — see `status_watch`. The cadence
        // is `--interval <secs>` here, an ENGINE_EXTENSIONS spelling; the oracle's
        // `--watch-interval <duration>` stays refused, see REFUSED_ON_PURPOSE.
        "status" => &[("--watch", false), ("--interval", true)][..],
        // `--dry-run`/`-n`/`--debug`: accepted-and-ignored, see the disposition list above.
        // `--plan <file>` (BUR-142, ENGINE_EXTENSIONS): remove exactly the paths a reviewed
        // dry-run listed, without re-scanning — `clean` only, see `clean_from_plan`.
        "clean" => &[
            ("--apply", false),
            ("--permanent", false),
            ("--stream", false),
            ("--plan", true),
            ("--dry-run", false),
            ("-n", false),
            ("--debug", false),
        ][..],
        // No `-n`: `bin/optimize.sh:203` is `"--dry-run")` with no short form, and `mo optimize -n`
        // exits 1 on its `*)` arm (`:209`). It was listed here anyway — the same drift as the
        // missing flags, pointing the other way.
        "optimize" => &[
            ("--apply", false),
            ("--stream", false),
            ("--dry-run", false),
            ("--debug", false),
        ][..],
        "uninstall" => &[
            ("--list", false),
            ("--apply", false),
            ("--permanent", false),
            ("--dry-run", false),
            ("-n", false),
            ("--debug", false),
        ][..],
        "net" => &[("--limit", true)][..],
        "orphans" => &[("--installed", true)][..],
        "slim-check" => &[][..],
        "evict" => &[("--apply", false)][..],
        "dupes" => &[("--keep", true), ("--apply", false)][..],
        "photos" => &[("--threshold", true)][..],
        "history" => &[("--limit", true)][..],
        // `--dry-run`/`-n` were MISSING here and on `installer`, which is what took the decode gate
        // red: it drives the oracle's own `purge --dry-run` (transcribed into
        // `purge.golden.provenance.txt`), and `MoActions.swift:75`/`:77` build the same argv.
        "purge" => &[
            ("--apply", false),
            ("--permanent", false),
            ("--stream", false),
            ("--plan", true),
            ("--dry-run", false),
            ("-n", false),
            ("--debug", false),
        ][..],
        "installer" => &[
            ("--apply", false),
            ("--permanent", false),
            ("--plan", true),
            ("--dry-run", false),
            ("-n", false),
            ("--debug", false),
        ][..],
        // `--app <bundle-id>` narrows `dryrun` to one app's rules
        // (`burrow-cli/src/main.rs:294-298`, a `position(|a| a == "--app")` + `get(i+1)`), which is
        // why it is declared value-taking here. `MCP.swift:1276-1280` is the only caller.
        "rules" => &[("--app", true)][..],
        // The oracle's `--watch`/`--interval-ms`/`--max-ticks` daemon mode is deliberately NOT
        // here — see REFUSED_ON_PURPOSE.
        "sentinel" => &[][..],
        _ => return None,
    })
}

/// Look one argv token up in the global + per-command flag tables. `Some(true)` means it is a known
/// flag that also swallows the following token; `None` means it is not a flag of this command's.
fn flag_spec(command: &str, token: &str) -> Option<bool> {
    let per_command = allowed_flags(command).unwrap_or(&[]);
    GLOBAL_FLAGS
        .iter()
        .chain(per_command)
        .find(|(name, _)| *name == token)
        .map(|(_, takes_value)| *takes_value)
}

/// Reject the first flag `command` does not define, or `None` if every flag is known.
///
/// Only leading-dash tokens are inspected, matching the oracle's `-*)` case; a value that happens to
/// follow a flag (`--limit 15`) is an ordinary token and is left alone. A dash-SHAPED value
/// (`--limit -5`) is still refused here, which is stricter than the oracle's `flag_value` — it
/// would hand `-5` straight to `parse()` — and is left that way on purpose: no flag on this surface
/// has a legitimate value beginning with `-` (a bundle-id csv, a hash threshold, a row limit, a
/// reference directory), so a dash where a value belongs is a malformed command line and saying so
/// beats guessing which of the two tokens the caller meant.
fn reject_unknown_flag(command: &str, args: &[String]) -> Option<(String, i32)> {
    allowed_flags(command)?;
    let bad = args
        .iter()
        .find(|a| a.starts_with('-') && a.len() > 1 && flag_spec(command, a).is_none())?;
    Some((
        envelope::error_envelope(
            VERSION,
            command,
            &format!("unknown {command} option: {bad}"),
        ),
        2,
    ))
}

fn reject_missing_flag_value(command: &str, args: &[String]) -> Option<(String, i32)> {
    for (i, arg) in args.iter().enumerate() {
        if flag_spec(command, arg) == Some(true)
            && args.get(i + 1).is_none_or(|value| {
                (value.is_empty() && arg != "--installed") || value.starts_with('-')
            })
        {
            let detail = if arg == "--plan" {
                "a file path"
            } else {
                "a value"
            };
            return Some((
                envelope::error_envelope(VERSION, command, &format!("{arg} needs {detail}")),
                2,
            ));
        }
    }
    None
}

/// This command's dry-run spelling present in `args`, if any — DERIVED from [`allowed_flags`]
/// rather than remembered, for the reason that table gives: the two spellings are not universal.
/// `bin/optimize.sh:203` is `"--dry-run")` with no short form and `mo optimize -n` exits 1 on its
/// `*)` arm, so `optimize` does not declare `-n`, and this must not read one there either.
fn dry_run_flag(command: &str, args: &[String]) -> Option<&'static str> {
    let declared = allowed_flags(command)?;
    ["--dry-run", "-n"].into_iter().find(|spelling| {
        declared.iter().any(|(name, _)| name == spelling) && args.iter().any(|a| a == spelling)
    })
}

/// Whether this argv asks for the DESTRUCTIVE run. The single reader of `--apply` for every command
/// that has one.
///
/// Each of these commands used to answer this with a bare `args.iter().any(|a| a == "--apply")`,
/// and nothing anywhere read `--dry-run`. Both spellings parse (they are in `allowed_flags`, and
/// they must be — `MoActions.swift:68-77` and `bin/purge.sh:322` both use them), so
/// `uninstall <app> --dry-run --apply --permanent` reported `"dry_run": false` and deleted the
/// leftovers off disk. Reproduced against a scratch `HOME`: three planted paths, all gone.
///
/// That is worse than a no-op flag, because `--dry-run` is the ONLY safety switch the originals
/// have. `--apply` exists in NEITHER oracle's flag parser: `bin/uninstall.sh:1336-1338` maps
/// `--dry-run|-n` to `MOLE_DRY_RUN=1` and `--apply` falls to the `-*)` arm at `:1351` →
/// `Unknown uninstall option: --apply`, exit 1. So every mental model a caller can form from the
/// original says `--dry-run` is what makes this safe, and `--help` here ADVERTISES it — which is
/// what an agent composing argv reads. Belt-and-braces (`--apply --dry-run`) is the natural thing
/// to type.
///
/// The contradiction is refused before dispatch reaches any command
/// ([`reject_contradictory_flags`]), so in practice this never sees both. It checks anyway, and
/// resolves toward the dry run, because the destructive commands are also reachable through their
/// injected test seams (`uninstall_resolved`) and through any future path that does not run argv
/// validation first. Defense in depth, the same reason `clean`'s protection guard is re-checked per
/// item after the plan already applied it: a safety rail that exists in exactly one place is one
/// refactor away from existing in none.
fn wants_apply(command: &str, args: &[String]) -> bool {
    args.iter().any(|a| a == "--apply") && dry_run_flag(command, args).is_none()
}

/// The home directory, or a ready-to-return refusal for `command`.
///
/// Every command that reaches for this builds `~`-relative paths and can do nothing sensible
/// without a home. Before this existed they all read `std::env::var("HOME").unwrap_or_default()`,
/// so on Windows — where `HOME` is unset and `USERPROFILE` holds the answer — the home became `""`
/// and each of them scanned paths like `/Library/Caches/*`, found nothing (correctly: no such
/// directory exists), and returned `ok:true` with an empty result. That is the failure this refusal
/// exists to make impossible: after it, an empty successful result from these commands means the
/// scan RAN and found nothing, and the "I do not know where to look" case is `ok:false` with
/// [`crate::platform::NO_HOME`] and an `error.kind` of `not_found`. A caller can finally tell them
/// apart, which is the whole point.
///
/// Deliberately a refusal rather than a fallback: guessing a home (the current directory, `/`, a
/// constructed `/Users/$USER`) would put a destructive command — `clean --apply`, `purge --apply` —
/// to work on a tree the user never named.
fn home_or_refuse(command: &str) -> Result<String, (String, i32)> {
    crate::platform::home_dir_or_error()
        .map_err(|e| (envelope::error_envelope(VERSION, command, &e), 1))
}

/// Reject `--apply` and `--dry-run`/`-n` given together, or `None` when at most one is present.
///
/// An ERROR rather than a silent precedence, and the evidence is that no oracle can produce this
/// argv while one of them refuses it outright:
///
///  - **Bash refuses it.** `--apply` is not in any bash `case` (`bin/uninstall.sh:1326-1360`,
///    `bin/clean.sh:1425-1455`, `bin/purge.sh:305-330`, `bin/installer.sh:814-822`,
///    `bin/optimize.sh:200-210`); every one of them ends in a `-*)` arm that prints
///    `Unknown … option:` and exits 1. So the original's answer to `--apply --dry-run` is a
///    refusal with a non-zero exit, and refusing here is nearer to it than either silent reading.
///  - **Both conductors emit exactly ONE of the two, never both.**
///    `burrow-cli/src/engine.rs:36-71` reads `--apply` off the user's argv, strips it as a conductor
///    flag (`is_conductor_flag`, `:27-28`), and then pushes `--dry-run` only `if !apply`.
///    `BurrowConductor.engineArgv` (`BurrowConductor.swift:172-177`) sets `isPreview` from
///    `--dry-run`, filters it out, and appends `--apply` only when it was not a preview. Neither can
///    construct this pair, so refusing it cannot break a real caller — the only thing that reaches
///    here with both is a hand-written or model-written command line, which is exactly the case
///    that needs to be told.
///
/// And it is what this file already decided everywhere else: a flag that changes the contract must
/// not be accepted and ignored (`status --watch`, and `--help`'s refusal three tables up). Under a
/// silent precedence ONE OF THE TWO FLAGS IS ALWAYS IGNORED — the safe one gets ignored under
/// "apply wins", the requested one under "dry-run wins" — so precedence is that same failure with
/// better luck. Exit 2 matches [`reject_unknown_flag`]: both are malformed argv, not a command that
/// ran and failed.
fn reject_contradictory_flags(command: &str, args: &[String]) -> Option<(String, i32)> {
    let dry = dry_run_flag(command, args)?;
    if !args.iter().any(|a| a == "--apply") {
        return None;
    }
    Some((
        envelope::error_envelope(
            VERSION,
            command,
            &format!(
                "{command} cannot take both --apply and {dry}: --apply removes files and {dry} \
                 guarantees it will not. Pass one. ({dry} is also the default — omit --apply.)"
            ),
        ),
        2,
    ))
}

/// The command's POSITIONAL arguments, in order, with every value-taking flag's value consumed so
/// it can never be mistaken for one.
///
/// The five commands that take a positional used to resolve it with
/// `args.iter().find(|a| !a.starts_with("--"))`, which is the value of the first value-taking flag
/// whenever the flag precedes the positional. Reproduced on the release binary:
///
/// ```text
/// $ burrow-engine photos --threshold 8 /tmp
/// {"ok":true,…,"data":{"dir":"8","threshold":8,…}}
/// $ burrow-engine orphans --installed a,b /tmp
/// {"ok":true,…,"data":{…,"roots":["a,b"],"installed_count":0}}
/// ```
///
/// Both report a successful scan of a directory that does not exist, and the second one silently
/// empties the inventory that makes the word "orphan" mean anything. The same idiom also read `-n`
/// as the app-name argument of `uninstall -n com.example.App`, because `-n` does not start with
/// `--`.
///
/// A leading-dash token that is not a known flag is skipped rather than returned: `dispatch`
/// already refused it (`reject_unknown_flag`), and treating it as a path here would only re-invent
/// the bug for a caller that reaches this function directly.
fn positionals<'a>(command: &str, args: &'a [String]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let token = args[i].as_str();
        match flag_spec(command, token) {
            Some(true) => i += 2,
            Some(false) => i += 1,
            None if token.starts_with('-') && token.len() > 1 => i += 1,
            None => {
                out.push(token);
                i += 1;
            }
        }
    }
    out
}

/// The first positional, or `None` when the command was given none. See [`positionals`].
fn first_positional<'a>(command: &str, args: &'a [String]) -> Option<&'a str> {
    positionals(command, args).into_iter().next()
}

use crate::json::escape as json_str;

/// `rules [list|validate|dryrun] [dir] [--app <bundle-id>]` — the read-only `burrow.rules/v1`
/// surface. Deletes nothing; `dryrun` reports what a rule WOULD select.
///
/// The two defaults are the oracle's and both look odd on purpose (`burrow-cli/src/main.rs:240-246`):
/// with no subcommand it runs `list`, and with no directory it reads the RELATIVE path `rules`,
/// resolved against the process's cwd. That second one is meaningless from a GUI-spawned process,
/// which is exactly why `MCP.swift:1266-1281` requires an explicit `dir` and refuses the call
/// without one. It is reproduced rather than replaced because the error a caller gets from it
/// (`cannot read rules: No such file or directory`) is the oracle's, and inventing a friendlier
/// default here would make the engine and the conductor disagree about the same argv.
///
/// `validate` is the one command in this engine whose ENVELOPE and EXIT CODE disagree: problems
/// produce `ok:true` with exit 1, because the oracle's validate arm prints through the
/// hardcoded-`ok:true` wrapper (`main.rs:286`) and signals failure only through `ExitCode::FAILURE`.
/// Measured on the golden's fixture. A GUI branching on the envelope's `ok` would see "fine" — so
/// this is faithfully wrong rather than quietly improved, and the exit code is the verdict.
fn rules(args: &[String]) -> (String, i32) {
    use crate::rules as r;
    let positional = positionals("rules", args);
    let sub = positional.first().copied().unwrap_or("list");
    let dir = positional.get(1).copied().unwrap_or("rules");
    let loaded = match r::load_dir(Path::new(dir)) {
        Ok(l) => l,
        Err(e) => return (envelope::error_envelope(VERSION, "rules", &e), 1),
    };
    match sub {
        "list" => (
            envelope::envelope(VERSION, "rules", ENGINE, &r::list_json(&loaded)),
            0,
        ),
        "validate" => {
            let (data, ok) = r::validate_report(&loaded);
            (
                envelope::envelope(VERSION, "rules", ENGINE, &data),
                if ok { 0 } else { 1 },
            )
        }
        "dryrun" => {
            let app = args
                .iter()
                .position(|a| a == "--app")
                .and_then(|i| args.get(i + 1))
                .map(String::as_str);
            // `dryrun_items` expands every rule path against the home. With none, each `~/…`
            // rule resolved to an absolute `/…` path that matches nothing, and the dry run
            // reported that no rule would do anything. See `home_or_refuse`.
            let home = match home_or_refuse("rules") {
                Ok(h) => h,
                Err(refusal) => return refusal,
            };
            let items = r::dryrun_items(&loaded, app, &home);
            (
                envelope::envelope(VERSION, "rules", ENGINE, &r::dryrun_json(&items)),
                0,
            )
        }
        other => (
            envelope::error_envelope(
                VERSION,
                "rules",
                &format!("unknown subcommand '{other}' (list|validate|dryrun)"),
            ),
            1,
        ),
    }
}

/// `sentinel [trashdir]` — the `.app` bundles sitting in the Trash right now, as uninstall-leftover
/// candidates. Read-only, and over a directory it was HANDED it cannot fail: a directory that does
/// not exist, or is not a directory at all, is an empty successful scan (measured on the oracle —
/// see `sentinel.golden.provenance.txt`). That is the opposite of `rules` on the same input, and
/// the asymmetry is the oracle's.
///
/// The no-positional form is the one that can lie, and it is gated: see
/// [`crate::sentinel::default_trash_refusal`] for why the INFERENCE is refused off macOS while the
/// explicit form stays served everywhere.
fn sentinel(args: &[String]) -> (String, i32) {
    // Two conditions guard the DEFAULT trash directory only, so both are scoped to it: an
    // explicitly-named directory is scanned whether or not a home exists and whatever platform
    // this is, keeping the oracle's "a directory that isn't there is an empty successful scan"
    // exactly as it was.
    //
    // ORDER MATTERS between them, and it is the reverse of what the argument order suggests.
    // `home_or_refuse` goes first because "I do not know where your home is" is the more specific
    // and more actionable of the two answers, and because it is the one the no-home reproduction
    // (`the_home_dependent_commands_refuse_instead_of_reporting_an_empty_success`) pins for this
    // command on EVERY platform — a platform gate hoisted above it would change that command's
    // answer on Windows and Linux from `not_found` to `unsupported` while telling the caller
    // strictly less.
    let dir = match first_positional("sentinel", args) {
        Some(explicit) => explicit.to_string(),
        None => {
            let home = match home_or_refuse("sentinel") {
                Ok(home) => home,
                Err(refusal) => return refusal,
            };
            // `<home>/.Trash` is a macOS path. Building it anywhere else and reporting what it
            // does not contain is the failure class this migration exists to remove — the scan
            // succeeds, the count is 0, and nothing in the answer says the directory was never
            // there. `std::env::consts::OS` rather than `cfg!` so the decision is one testable
            // function on every host, and so the body below stays compiled and warning-clean on
            // the platforms that refuse.
            if let Some(detail) = crate::sentinel::default_trash_refusal(std::env::consts::OS) {
                return (
                    envelope::unsupported_envelope(
                        VERSION,
                        "sentinel",
                        crate::sentinel::DEFAULT_TRASH_FEATURE,
                        detail,
                    ),
                    1,
                );
            }
            format!("{home}/.Trash")
        }
    };
    let dir = dir.as_str();
    let apps = crate::sentinel::scan_trash(Path::new(dir));
    let data = crate::sentinel::report_json(dir, &apps);
    (envelope::envelope(VERSION, "sentinel", ENGINE, &data), 0)
}

/// `analyze <dir> [--progress]` — scan a directory and emit the analyze JSON contract,
/// envelope-wrapped. With `--progress` the scan is streamed instead: see [`analyze_progress_with`].
fn analyze(args: &[String]) -> (String, i32) {
    let Some(path) = first_positional("analyze", args) else {
        return (
            envelope::error_envelope(VERSION, "analyze", "analyze needs a directory to scan"),
            1,
        );
    };
    if args.iter().any(|a| a == "--progress") {
        let mut out = std::io::stdout().lock();
        let code = analyze_progress_with(path, &mut out);
        return (String::new(), code);
    }
    match scanner::scan(Path::new(path)) {
        Ok(result) => {
            let data = json::to_json(path, false, &result);
            (envelope::envelope(VERSION, "analyze", ENGINE, &data), 0)
        }
        Err(e) => (
            envelope::error_envelope(VERSION, "analyze", &format!("scan {path}: {e}")),
            1,
        ),
    }
}

/// `analyze --progress`: raw NDJSON on stdout — one
/// `{"type":"progress","files":N,"dirs":N,"bytes":B,"path":P}` line as each top-level directory
/// of the root finishes (running totals), then one `{"type":"result","data":…}` line whose `data`
/// is byte-for-byte the buffered command's payload. The keys are digger's
/// (`cmd/analyze/progress.go`) and the app's `AnalyzeProgressEvent.parse` reads exactly them. A
/// scan failure writes the buffered command's error envelope as the last line and exits 1 — it
/// carries `type`-less `ok:false`, which the app's parser skips and a stricter reader can detect.
/// The sink is injected so the frame sequence is tested against a scratch tree.
fn analyze_progress_with(path: &str, out: &mut impl std::io::Write) -> i32 {
    let scanned = scanner::scan_with(Path::new(path), |p| {
        let _ = writeln!(out, "{}", json::progress_ndjson(p));
        let _ = out.flush();
    });
    match scanned {
        Ok(result) => {
            let data = json::to_json(path, false, &result);
            let _ = writeln!(out, "{}", json::result_ndjson(&data));
            let _ = out.flush();
            0
        }
        Err(e) => {
            let _ = writeln!(
                out,
                "{}",
                envelope::error_envelope(VERSION, "analyze", &format!("scan {path}: {e}"))
            );
            let _ = out.flush();
            1
        }
    }
}

#[cfg(test)]
mod tests {

    /// Off unix the rails refuse every path, so an `--apply` must be the classified `unsupported`
    /// failure up front — not a "successful" run whose every item is `protected`.
    #[cfg(not(unix))]
    #[test]
    fn apply_off_unix_is_refused_as_unsupported_not_item_by_item() {
        for cmd in ["clean", "purge", "installer"] {
            let (out, code) = dispatch(&[cmd.to_string(), "--apply".to_string()]);
            assert_eq!(code, 1, "{cmd}: {out}");
            assert!(out.contains(r#""kind":"unsupported""#), "{cmd}: {out}");
            assert!(out.contains(&format!("{cmd} --apply")), "{cmd}: {out}");
        }
    }

    /// On unix the guard is inert: the rails speak these paths, so the run proceeds to them.
    #[cfg(unix)]
    #[test]
    fn apply_guard_is_inert_where_the_rails_speak_the_paths() {
        assert!(refuse_apply_off_unix("clean").is_none());
    }
    use super::*;
    use crate::history::write::log_clean_session;
    use std::fs;

    // Some tests in this module are `#[cfg(unix)]`. They assert POSIX-shaped filesystem
    // behaviour, which is the only shape this engine's path vocabulary has: the clean target
    // table is entirely `~/Library/...`, the protection tables are macOS paths, the glob expander
    // splits on `/`, and `clean::validate::validate_path_for_deletion` refuses OUTRIGHT off unix
    // rather than pretending otherwise. Read the guard comment in that function before ungating
    // any of them — it is the reason these are gated rather than "fixed", and the reason making
    // them pass on Windows is a protection-table port, not a test change.

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// The audit-trail half of RULEBOOK §3m, against the REAL log writer and the REAL files it
    /// produces — `SessionLog::open_at` takes injected paths, so no env var is touched and the
    /// assertion is made by reading `deletions.log` back off disk rather than by inspecting a
    /// mock's recorded calls.
    ///
    /// A `trash … ok` row is a promise that the bytes are in a Trash the user can open. Exactly one
    /// of these four items can honour it. The other three are the ones that used to produce
    /// phantom rows: a tool that unlinks permanently (`uv cache prune`), a path an ancestor in the
    /// same run already took, and a remover that claimed success without deleting.
    #[test]
    fn the_deletion_audit_log_records_only_deletions_this_run_actually_performed() {
        use crate::clean::execute::{CleanOutcome, Freed, RemovalError, RemovalMode, RemovedItem};
        let dir = std::env::temp_dir().join(format!("burrow_cli_audit_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let ops = dir.join("operations.log").to_string_lossy().to_string();
        let del = dir.join("deletions.log").to_string_lossy().to_string();

        let outcome = CleanOutcome {
            removed: vec![
                RemovedItem {
                    path: "/h/Library/Caches/real".into(),
                    label: "User caches".into(),
                    freed: Freed::Bytes(2048),
                },
                RemovedItem {
                    path: "/h/.cache/uv".into(),
                    label: "uv cache".into(),
                    freed: Freed::Delegated,
                },
                RemovedItem {
                    path: "/h/Library/Caches/real/child".into(),
                    label: "Nested cache".into(),
                    freed: Freed::AlreadyGone,
                },
                RemovedItem {
                    path: "/h/Library/Caches/stubborn".into(),
                    label: "Stubborn cache".into(),
                    freed: Freed::Unverified,
                },
            ],
            freed_bytes: 2048,
            moved_to_trash_bytes: 0,
            errors: vec![RemovalError {
                path: "/h/nope".into(),
                error: "permission denied".into(),
            }],
            protected: Vec::new(),
        };
        let log = crate::history::write::SessionLog::open_at("clean", &ops, &del, "TS", "ISO");
        // `permanent: false` — the default path, the one that writes `trash`.
        log_clean_session(&log, RemovalMode::from_permanent(false), &outcome);

        let deletions = fs::read_to_string(&del).unwrap_or_default();
        let rows: Vec<&str> = deletions.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            rows,
            vec!["ISO\ttrash\t2\tok\t/h/Library/Caches/real"],
            "only the item this run actually trashed may appear: {deletions}"
        );
        for phantom in ["/h/.cache/uv", "/h/Library/Caches/stubborn"] {
            assert!(
                !deletions.contains(phantom),
                "{phantom} was never moved to any Trash: {deletions}"
            );
        }

        // The actions are still recorded — the History view's counts must not lose them — with a
        // stated reason in place of a byte figure nobody can vouch for.
        let operations = fs::read_to_string(&ops).unwrap_or_default();
        assert_eq!(
            operations.matches("REMOVED").count(),
            4,
            "every processed item keeps its operations line: {operations}"
        );
        assert!(
            operations
                .contains("REMOVED /h/.cache/uv (cleaned by the tool itself, bytes not measured)"),
            "{operations}"
        );
        assert!(
            operations.contains("FAILED /h/nope (permission denied)"),
            "{operations}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_command_is_a_failure_envelope() {
        let (out, code) = dispatch(&args(&["frobnicate"]));
        assert_eq!(code, 2);
        assert!(out.contains("\"ok\":false"), "{out}");
        assert!(out.contains("unknown command: frobnicate"), "{out}");
    }

    #[test]
    fn no_command_is_a_failure_envelope() {
        let (out, code) = dispatch(&[]);
        assert_eq!(code, 2);
        assert!(out.contains("\"ok\":false"), "{out}");
    }

    #[test]
    fn analyze_without_a_path_fails() {
        let (out, code) = dispatch(&args(&["analyze"]));
        assert_eq!(code, 1);
        assert!(out.contains("\"ok\":false"), "{out}");
        assert!(out.contains("needs a directory"), "{out}");
    }

    #[test]
    fn analyze_a_real_directory_emits_a_success_envelope() {
        // Reproduce analyze.golden.json's own fixture (a.txt = "abc" = 3 bytes, b.txt = "defg" =
        // 4 bytes) so total_size/total_files/entries can be checked against the golden's OWN
        // recorded values instead of a hand-typed shape describing a different-sized fixture —
        // "assert that RUNNING the command over the golden's recorded fixture reproduces the
        // golden" (RULEBOOK §3e). The scan root is still a fresh per-process temp dir, not the
        // golden's pinned /tmp/burrow_judge_scan, so `path` and each entry's own `path`/
        // `last_access` are never compared to the golden's exact strings — only content that
        // must be identical given an identical fixture is.
        let golden = crate::json::Json::parse(include_str!("analyze.golden.json"))
            .expect("vendored golden must parse");

        let dir = std::env::temp_dir().join(format!("burrow_cli_analyze_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.txt"), "abc").unwrap();
        fs::write(dir.join("b.txt"), "defg").unwrap();

        let (out, code) = dispatch(&args(&["analyze", dir.to_str().unwrap()]));
        assert_eq!(code, 0, "{out}");

        let parsed = crate::json::Json::parse(&out).expect("dispatch must emit valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(true),
            "{out}"
        );
        assert_eq!(
            parsed.get("command").and_then(crate::json::Json::as_str),
            Some("analyze"),
            "{out}"
        );
        assert_eq!(
            parsed.get("engine").and_then(crate::json::Json::as_str),
            Some("burrow-engine"),
            "{out}"
        );

        let data = parsed
            .get("data")
            .expect("success envelope must carry data");
        assert_eq!(
            data.get("total_size"),
            golden.get("total_size"),
            "same fixture bytes as the golden must produce the same total_size: {out}"
        );
        assert_eq!(
            data.get("total_files"),
            golden.get("total_files"),
            "same fixture file count as the golden must produce the same total_files: {out}"
        );

        let entries = data
            .get("entries")
            .and_then(crate::json::Json::as_array)
            .expect("data must carry entries");
        let golden_entries = golden
            .get("entries")
            .and_then(crate::json::Json::as_array)
            .expect("golden must carry entries");
        assert_eq!(entries.len(), golden_entries.len(), "{out}");

        // Compare each entry's (name, size, is_dir) as an unordered set: `path` legitimately
        // differs (this run's temp dir vs. the golden's pinned /tmp/burrow_judge_scan) and
        // enumeration order across a file and a directory is not a contract (RULEBOOK §3a).
        fn shape(list: &[crate::json::Json]) -> Vec<(Option<&str>, Option<i64>, Option<bool>)> {
            let mut v: Vec<_> = list
                .iter()
                .map(|e| {
                    (
                        e.get("name").and_then(crate::json::Json::as_str),
                        e.get("size").and_then(crate::json::Json::as_i64),
                        e.get("is_dir").and_then(crate::json::Json::as_bool),
                    )
                })
                .collect();
            v.sort();
            v
        }
        assert_eq!(
            shape(entries),
            shape(golden_entries),
            "entries' (name, size, is_dir) must match the golden's, given the same fixture: {out}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn analyze_a_missing_directory_fails_cleanly() {
        let (out, code) = dispatch(&args(&["analyze", "/no/such/dir/xyz-burrow"]));
        assert_eq!(code, 1);
        assert!(out.contains("\"ok\":false"), "{out}");
        // The classified error kind is surfaced (not_found), not a panic.
        assert!(out.contains("\"kind\":"), "{out}");
    }

    /// A scratch home whose `Library/Logs/mole/operations.log` a test can read back. `MOLE_*`
    /// overrides would win over it (`history::log_paths_under`), which no test in this binary sets.
    fn scratch_home(tag: &str) -> std::path::PathBuf {
        let home =
            std::env::temp_dir().join(format!("burrow_cli_hist_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    fn operations_log(home: &std::path::Path) -> String {
        std::fs::read_to_string(home.join("Library/Logs/mole/operations.log")).unwrap_or_default()
    }

    /// The buffered `clean`/`purge`/`installer` paths opened their history session AFTER the
    /// removals had run, so `started_at` was really the end time (`cli.rs:244`, `:701`, `:745`
    /// before this). digger opens the session at the top of `main` and closes it in its EXIT trap.
    /// The property: by the time the work runs, the session-start marker is already on disk — so
    /// every op line, and the end marker, can only follow it.
    #[test]
    fn the_history_session_is_opened_before_the_work_it_records() {
        let home = scratch_home("session_order");
        let seen_at_work_time = record_session(
            "clean",
            Some(home.to_str().unwrap()),
            || operations_log(&home),
            |log, _| {
                log.operation("REMOVED", "/x", "1KB");
                log.end(1, 1);
            },
        );
        assert!(
            seen_at_work_time.contains("clean session started at"),
            "the start marker must precede the work: {seen_at_work_time:?}"
        );
        let full = operations_log(&home);
        let start = full.find("session started at").expect("start marker");
        let op = full.find("REMOVED /x").expect("op line");
        let end = full.find("session ended at").expect("end marker");
        assert!(start < op && op < end, "{full}");
        let sessions = crate::history::parse_operations(&full);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].removed, 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `bin/optimize.sh:218` opens an `optimize` session and its EXIT trap closes it with the task
    /// count and size 0 (`:181`); `history.golden.json` carries exactly such a session
    /// (`items: 22, size: "0B", operation_count: 0`). The engine's `--apply` wrote none, so a tune-up
    /// never appeared in the History view.
    #[test]
    fn optimize_apply_records_a_history_session_the_history_command_shows() {
        let home = scratch_home("optimize_session");
        let calls = std::cell::RefCell::new(0usize);
        let runner = |_p: &str, _a: &[&str]| -> Result<(), String> {
            *calls.borrow_mut() += 1;
            Ok(())
        };
        let (out, code) = optimize_with(
            &args(&["--apply"]),
            true,
            runner,
            Some(home.to_str().unwrap()),
        );
        assert_eq!(code, 0, "{out}");
        assert!(*calls.borrow() > 0, "the tasks ran");

        let sessions = crate::history::parse_operations(&operations_log(&home));
        assert_eq!(sessions.len(), 1, "{sessions:?}");
        let s = &sessions[0];
        assert_eq!(s.command, "optimize");
        assert_eq!(
            s.items,
            crate::optimize::TASKS.len() as u64,
            "OPTIMIZE_SAFE_COUNT is the task count: {s:?}"
        );
        assert_eq!(s.size, "0B", "nothing is deleted, so no bytes: {s:?}");
        assert_eq!(
            s.operation_count, 0,
            "the oracle writes no per-task op line: {s:?}"
        );
        assert!(!s.ended_at.is_empty(), "the session is closed: {s:?}");

        // …and `history` itself, reading that home, lists it.
        let (code, out) = dispatch_without_a_home("history", &[("HOME", home.to_str().unwrap())]);
        assert_eq!(code, 0, "{out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        let listed = parsed
            .get("data")
            .and_then(|d| d.get("sessions"))
            .and_then(crate::json::Json::as_array)
            .expect("sessions");
        assert_eq!(listed.len(), 1, "{out}");
        assert_eq!(
            listed[0].get("command").and_then(crate::json::Json::as_str),
            Some("optimize"),
            "{out}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A preview writes no session — `record_session` is on the apply path only, like its siblings.
    #[test]
    fn optimize_dry_run_records_no_history_session() {
        let home = scratch_home("optimize_preview");
        let (_, code) = optimize_with(
            &args(&[]),
            true,
            |_, _| panic!("a preview must run nothing"),
            Some(home.to_str().unwrap()),
        );
        assert_eq!(code, 0);
        assert!(!home.join("Library/Logs/mole").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn optimize_dry_run_lists_tasks_without_running_them() {
        let (out, code) = dispatch(&args(&["optimize"]));
        assert_eq!(code, 0);
        assert!(out.contains("\"ok\":true"), "{out}");
        assert!(out.contains("\"command\":\"optimize\""), "{out}");
        assert!(out.contains("\"dry_run\":true"), "{out}");
        assert!(out.contains("\"name\":\"flush_dns\""), "{out}");
        assert!(
            out.contains("\"name\":\"rebuild_launch_services\""),
            "{out}"
        );
        let value = crate::json::Json::parse(&out).unwrap();
        let text = value
            .get("data")
            .and_then(|data| data.get("text"))
            .and_then(crate::json::Json::as_str)
            .expect("dry-run text");
        assert!(!text.trim().is_empty());
        // Dry-run must NOT carry a results array (that's the --apply shape).
        assert!(!out.contains("\"results\":"), "{out}");
    }

    #[test]
    fn orphans_without_a_directory_errors_like_the_oracle() {
        // The oracle (burrow-cli's `run_orphans`) refuses the no-arg form outright on macOS:
        // `{"ok":false,...,"error":{"kind":"error","message":"needs a directory to scan"}}`.
        let (out, code) = dispatch(&args(&["orphans"]));
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("\"ok\":false"), "{out}");
        assert!(out.contains("\"command\":\"orphans\""), "{out}");
        assert!(
            out.contains("\"message\":\"needs a directory to scan\""),
            "must match the oracle's exact wording, no \"orphans\" prefix: {out}"
        );
        assert!(
            out.contains("\"kind\":\"error\""),
            "this message matches none of error_kind's other classifiers, so it must fall \
             through to the generic \"error\" kind, same as the oracle: {out}"
        );
        // A refusal must carry no data at all, so a naive caller can't stumble into treating an
        // empty sweep as a valid (if boring) scan.
        assert!(!out.contains("\"data\":"), "{out}");
    }

    /// The honest-degradation half of the same contract, and the only thing that exercises it:
    /// off macOS there is no installed-app inventory source at all
    /// (`orphan::enumerate_installed_apps` gates on `cfg!(target_os = "macos")`), so `orphans`
    /// must REFUSE rather than answer. What this guards is not a crash but a plausible-looking
    /// success — an inventory that came back empty makes `is_orphan` match nothing, so every
    /// app-shaped file on the machine, including apps that are installed and running, is reported
    /// as an orphan by a command whose entire job is telling the caller what is safe to delete.
    /// The classification is `unsupported` rather than `error` because the caller's argv was fine
    /// and the PLATFORM is what is missing; a GUI branches on that to grey the pane out instead
    /// of showing a red failure. Same shape, and the same reason for existing, as
    /// `net_on_unsupported_platform_is_a_classified_failure_not_an_empty_success` — `net` had
    /// this test and `orphans` did not, which is the only reason the gap lasted.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn orphans_off_macos_refuses_instead_of_reporting_everything_as_an_orphan() {
        let dir = fixture_dir("orph_unsupported");
        // Bundle-id-shaped (>=3 dot components), so an inventory that wrongly came back empty
        // would flag it — the file exists to make the silent-success failure mode visible.
        fs::write(dir.join("com.example.someapp.savedState"), "x").unwrap();

        let (out, code) = dispatch(&args(&["orphans", dir.to_str().unwrap(), "--json"]));
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("\"ok\":false"), "{out}");
        assert!(out.contains("\"command\":\"orphans\""), "{out}");
        assert!(
            out.contains("\"kind\":\"unsupported\""),
            "the platform is missing, not the caller's argv: {out}"
        );
        assert!(
            out.contains("\"feature\":\"orphans\""),
            "the envelope must name the feature a GUI greys out: {out}"
        );
        assert!(
            out.contains(
                "\"message\":\"installed-app inventory unavailable: orphans needs macOS \
                 (no installed-app inventory source on this platform)\""
            ),
            "the message must say WHICH source is missing, not just that something failed: {out}"
        );
        // The load-bearing pair: a refusal carries no data at all, and in particular does not
        // report the planted file, so nothing downstream can read "the inventory could not be
        // built" as "we scanned and these are your orphans".
        assert!(!out.contains("\"data\":"), "{out}");
        assert!(
            !out.contains("com.example.someapp"),
            "a refusal must not name the planted file as an orphan: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // `cfg(target_os = "macos")` and NOT `cfg(unix)`: the thing this asserts on is the real
    // `/Applications` inventory, and `enumerate_installed_apps` refuses whenever
    // `!cfg!(target_os = "macos")` — so Linux, which IS unix, refuses exactly like Windows does.
    // The two symlink tests upstream use `cfg(unix)` because a symlink is a unix-wide primitive;
    // an installed-app inventory is not. The refusal itself is covered by the test above.
    #[cfg(target_os = "macos")]
    #[test]
    fn orphans_scans_the_given_directory_and_not_a_hardcoded_default() {
        // Regression test for the root-handling bug: `orphans <dir>` and `orphans <other-dir>`
        // used to produce byte-identical output (both silently sweeping $HOME/Library/* instead
        // of the given argument). A hit that exists in ONE fixture directory and not the other
        // must show up in exactly the matching run, and `roots` must echo back EXACTLY the
        // directory it was given (oracle parity — see `orphan::scan`'s doc comment for why the
        // reported path is never canonicalized, only the internal protected-roots check).
        let base =
            std::env::temp_dir().join(format!("burrow_cli_orph_root_{}", std::process::id()));
        let dir_a = base.join("scan_a");
        let dir_b = base.join("scan_b");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&dir_a).unwrap();
        fs::create_dir_all(&dir_b).unwrap();
        // Bundle-id-shaped (>=3 dot components) and unmatched by any real installed app, so each
        // is flagged as an orphan only in the scan of its own directory.
        fs::write(dir_a.join("com.deadvendor.onlyinA.leftover"), "x").unwrap();
        fs::write(dir_b.join("com.deadvendor.onlyinB.leftover"), "x").unwrap();

        let (out_a, code_a) = dispatch(&args(&["orphans", dir_a.to_str().unwrap()]));
        let (out_b, code_b) = dispatch(&args(&["orphans", dir_b.to_str().unwrap()]));
        assert_eq!(code_a, 0, "{out_a}");
        assert_eq!(code_b, 0, "{out_b}");

        assert_ne!(
            out_a, out_b,
            "two different scan roots must not produce identical output"
        );

        assert!(out_a.contains("onlyinA"), "{out_a}");
        assert!(
            !out_a.contains("onlyinB"),
            "scanning dir_a must not see dir_b's file: {out_a}"
        );
        assert!(
            out_a.contains(&format!("\"roots\":[\"{}\"]", dir_a.to_str().unwrap())),
            "roots must echo the directory actually scanned: {out_a}"
        );

        assert!(out_b.contains("onlyinB"), "{out_b}");
        assert!(
            !out_b.contains("onlyinA"),
            "scanning dir_b must not see dir_a's file: {out_b}"
        );
        assert!(
            out_b.contains(&format!("\"roots\":[\"{}\"]", dir_b.to_str().unwrap())),
            "roots must echo the directory actually scanned: {out_b}"
        );

        let _ = fs::remove_dir_all(&base);
    }

    // macOS-only for the same reason as the test above, plus a second one specific to this test:
    // it calls `enumerate_installed_apps()` directly to derive `installed_count` independently,
    // and that call is itself the thing that refuses off macOS.
    #[cfg(target_os = "macos")]
    #[test]
    fn orphans_emits_installed_count_and_inventory_sources() {
        // Part B's three fields, anchored on the vendored oracle instead of hand-typed key
        // fragments (RULEBOOK §3e). Three of the five values are legitimately environment-
        // specific — `installed_count` is whatever this machine has in /Applications, and
        // `count`/`orphans` describe a fresh empty temp dir where the golden's fixture had
        // three planted leftovers — so the golden anchors the KEY SET and the types, while
        // every value that CAN be derived independently is derived rather than transcribed:
        // `installed_count` from its own enumeration call, `roots` from the directory actually
        // passed in. A re-capture that changed the shape turns this red; a re-capture that
        // merely changed the machine does not.
        let golden = crate::json::Json::parse(include_str!("orphan/orphans.golden.json"))
            .expect("vendored golden must parse");

        let dir =
            std::env::temp_dir().join(format!("burrow_cli_orph_fields_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (out, code) = dispatch(&args(&["orphans", dir.to_str().unwrap()]));
        assert_eq!(code, 0, "{out}");

        let parsed = crate::json::Json::parse(&out).expect("dispatch must emit valid JSON");
        let data = parsed
            .get("data")
            .expect("success envelope must carry data");

        // Sorted key names of a JSON object, empty for anything else. BTreeMap already orders
        // them, so this compares as a set without needing one.
        fn keys(v: &crate::json::Json) -> Vec<&str> {
            match v {
                crate::json::Json::Object(m) => m.keys().map(String::as_str).collect(),
                _ => Vec::new(),
            }
        }

        assert_eq!(
            keys(data),
            keys(&golden),
            "data's key set must match the oracle's exactly — a dropped field is a dead pane \
             and an added one is undeclared contract drift: {out}"
        );

        // The denominator that makes the word "orphan" mean anything. Derived from an
        // independent call to the same enumeration, so a placeholder cannot satisfy it.
        let expected_count = crate::orphan::enumerate_installed_apps()
            .expect("this test runs on macOS with a real /Applications")
            .len() as u64;
        assert_eq!(
            data.get("installed_count")
                .and_then(crate::json::Json::as_u64),
            Some(expected_count),
            "installed_count must be the real enumerate_installed_apps().len(): {out}"
        );

        // Auto-detect path, so the source breakdown carries the same key the oracle recorded
        // (`--installed` would report a `cli` source instead — covered by its own test), and
        // its tally must agree with the count above rather than drifting from it.
        let inventory = data
            .get("inventory_sources")
            .expect("data must carry inventory_sources");
        let golden_inventory = golden
            .get("inventory_sources")
            .expect("golden must carry inventory_sources");
        assert_eq!(
            keys(inventory),
            keys(golden_inventory),
            "inventory_sources must name the same source as the oracle: {out}"
        );
        assert_eq!(
            inventory
                .get("applications_dir")
                .and_then(crate::json::Json::as_u64),
            Some(expected_count),
            "the applications_dir tally must agree with installed_count: {out}"
        );

        // roots echoes the directory actually scanned — the check that stops the engine
        // reporting one root while sweeping another (RULEBOOK §4).
        let roots = data
            .get("roots")
            .and_then(crate::json::Json::as_array)
            .expect("data must carry a roots array");
        assert_eq!(roots.len(), 1, "{out}");
        assert_eq!(
            roots[0].as_str(),
            dir.to_str(),
            "roots must echo the directory actually scanned: {out}"
        );

        // count/orphans are this fixture's own (an empty dir finds nothing where the golden's
        // planted three), so only their types are contractual here.
        assert!(
            data.get("count")
                .and_then(crate::json::Json::as_u64)
                .is_some(),
            "count must be a number: {out}"
        );
        assert!(
            data.get("orphans")
                .and_then(crate::json::Json::as_array)
                .is_some(),
            "orphans must be an array: {out}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphans_dash_dash_installed_overrides_the_auto_detected_inventory() {
        // The serious finding: `--installed <csv>` must actually change what gets scanned
        // against, not just get silently dropped on the floor. Mirrors the reviewer-measured
        // oracle: `orphans <fixture> --installed "Ghostapp,Acme"` -> count=2, installed_count=2,
        // inventory_sources={"cli":2} (down from the real ~100+-app applications_dir inventory).
        let dir =
            std::env::temp_dir().join(format!("burrow_cli_orph_installed_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("com.example.ghostapp"), "x").unwrap();
        fs::write(dir.join("org.nonexistent.vendor.tool"), "x").unwrap();

        let (out, code) = dispatch(&args(&[
            "orphans",
            dir.to_str().unwrap(),
            "--installed",
            "Ghostapp,Acme",
        ]));
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("\"installed_count\":2"), "{out}");
        assert!(
            out.contains("\"inventory_sources\":{\"cli\":2}"),
            "must be sourced from \"cli\", not \"applications_dir\": {out}"
        );
        assert!(out.contains("\"count\":1"), "{out}");
        assert!(
            out.contains("org.nonexistent.vendor.tool"),
            "unrelated to the CSV, still an orphan: {out}"
        );
        assert!(
            !out.contains("\"name\":\"com.example.ghostapp\""),
            "strong-tier related to \"Ghostapp\" in the CSV, must not be an orphan: {out}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphans_dash_dash_installed_empty_string_is_a_legitimate_empty_inventory() {
        // "--installed ''" is the caller explicitly saying "treat nothing as installed" — that
        // must succeed (not be conflated with the enumeration-failed case, which is `unsupported`).
        let dir = std::env::temp_dir().join(format!(
            "burrow_cli_orph_installed_empty_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("com.example.ghostapp"), "x").unwrap();

        let (out, code) = dispatch(&args(&[
            "orphans",
            dir.to_str().unwrap(),
            "--installed",
            "",
        ]));
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("\"ok\":true"), "{out}");
        assert!(out.contains("\"installed_count\":0"), "{out}");
        assert!(
            out.contains("\"count\":1"),
            "everything is an orphan against an empty inventory: {out}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[test]
    fn net_on_unsupported_platform_is_a_classified_failure_not_an_empty_success() {
        // The whole point of this slice: a collection failure must surface as `ok:false`, never
        // as `ok:true` with an empty `by_total_bytes` (structurally indistinguishable from "no
        // traffic"). `crate::net::collect()` returns `Err` unconditionally on a platform with no
        // collector — Linux, since BUR-133 gave Windows a real one — so this exercises the exact
        // `Err` arm in `net()` in well under a millisecond, with no real nettop sample needed:
        // real coverage of the failure path on the Linux CI runner, where this engine cannot
        // reach the macOS-only nettop path. Windows is pinned separately, below.
        let (out, code) = dispatch(&args(&["net"]));
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("\"ok\":false"), "{out}");
        assert!(out.contains("\"command\":\"net\""), "{out}");
        assert!(out.contains("\"kind\":\"unsupported\""), "{out}");
        assert!(
            out.contains(
                "\"message\":\"per-app network unavailable: per-app network is unavailable \
                 on this platform\""
            ),
            "{out}"
        );
        assert!(out.contains("\"feature\":\"net\""), "{out}");
        // A refusal must carry no data at all — same invariant the orphans no-arg refusal
        // enforces (see `orphans_without_a_directory_errors_like_the_oracle`).
        assert!(!out.contains("\"data\":"), "{out}");
    }

    /// Windows has a real collector (IP Helper, then `netstat` — `crate::net::collect_windows`),
    /// so `net` there is never the "unsupported" envelope: it is a success whose every row names a
    /// Windows connection-count source, or — if both halves fail on this runner — a classified
    /// failure that names BOTH of them. Either way it is never `ok:true` with an unexplained
    /// empty list, which is the invariant the Linux test above pins from the other side.
    #[cfg(windows)]
    #[test]
    fn net_on_windows_is_a_real_collection_or_a_failure_that_names_both_halves() {
        let (out, code) = dispatch(&args(&["net"]));
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert!(out.contains("\"command\":\"net\""), "{out}");
        if code == 0 {
            assert_eq!(
                parsed.get("ok").and_then(crate::json::Json::as_bool),
                Some(true),
                "{out}"
            );
            let rows = parsed
                .get("data")
                .and_then(|d| d.get("by_total_bytes"))
                .and_then(crate::json::Json::as_array)
                .expect("a success carries by_total_bytes");
            for row in rows {
                let source = row.get("metric_source").and_then(crate::json::Json::as_str);
                assert!(
                    matches!(
                        source,
                        Some("windows_iphelper_connection_count")
                            | Some("windows_netstat_connection_count")
                    ),
                    "every Windows row names its connection-count source: {out}"
                );
            }
        } else {
            assert_eq!(code, 1, "{out}");
            assert!(out.contains("\"ok\":false"), "{out}");
            assert!(out.contains("\"kind\":\"unsupported\""), "{out}");
            assert!(out.contains("Windows IP Helper failed"), "{out}");
            assert!(out.contains("netstat fallback failed"), "{out}");
            assert!(!out.contains("\"data\":"), "{out}");
        }
    }

    /// `nettop` failing (missing, non-zero exit, killed) must be `ok:false` with an error object —
    /// never `ok:true` with an empty `by_total_bytes`, which reads as "this Mac has no traffic".
    /// Pinned through the injected collector so it holds on macOS too, not only where
    /// `net::collect` refuses by platform.
    #[test]
    fn a_nettop_failure_is_an_error_envelope_not_an_empty_success() {
        let (out, code) = net_with(&args(&["net"]), || Err("nettop exited 1".to_string()));
        assert_eq!(code, 1, "{out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        assert!(
            parsed.get("data").is_none(),
            "a refusal carries no data: {out}"
        );
        let err = parsed.get("error").expect("error object");
        assert!(
            err.get("message")
                .and_then(crate::json::Json::as_str)
                .is_some_and(|m| m.contains("nettop exited 1")),
            "{out}"
        );
    }

    /// Every row carries `metric_source`, and `metric_note` appears exactly when a row has one —
    /// the fields `NetModel.swift` and the former burrow-cli `net.rs` define.
    #[test]
    fn net_rows_carry_metric_source_and_metric_note_when_present() {
        let mut noted = fake_proc_net("b", 1);
        noted.metric_source = "windows_netstat_connection_count".to_string();
        noted.metric_note = Some("connection counts, not bytes".to_string());
        let rows = vec![fake_proc_net("a", 2), noted];
        let (out, code) = net_with(&args(&["net"]), move || Ok(rows));
        assert_eq!(code, 0, "{out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        let list = parsed
            .get("data")
            .and_then(|d| d.get("by_total_bytes"))
            .and_then(crate::json::Json::as_array)
            .expect("rows");
        assert_eq!(list.len(), 2, "{out}");
        assert_eq!(
            list[0]
                .get("metric_source")
                .and_then(crate::json::Json::as_str),
            Some("macos_nettop_bytes"),
            "{out}"
        );
        assert!(
            list[0].get("metric_note").is_none(),
            "omitted when absent: {out}"
        );
        assert_eq!(
            list[1]
                .get("metric_source")
                .and_then(crate::json::Json::as_str),
            Some("windows_netstat_connection_count"),
            "{out}"
        );
        assert_eq!(
            list[1]
                .get("metric_note")
                .and_then(crate::json::Json::as_str),
            Some("connection counts, not bytes"),
            "{out}"
        );
    }

    #[test]
    fn net_limit_defaults_to_15() {
        // burrow-cli's `run_net` default; the golden was captured with it (15 rows, count:15).
        assert_eq!(net_limit(&args(&["net"])), 15);
    }

    #[test]
    fn net_limit_flag_overrides_the_default() {
        assert_eq!(net_limit(&args(&["net", "--limit", "3"])), 3);
    }

    #[test]
    fn net_limit_falls_back_to_the_default_on_a_bad_value() {
        assert_eq!(
            net_limit(&args(&["net", "--limit", "not-a-number"])),
            15,
            "unparseable value"
        );
        assert_eq!(
            net_limit(&args(&["net", "--limit"])),
            15,
            "flag present with no value following it"
        );
    }

    fn fake_proc_net(name: &str, total: u64) -> crate::net::ProcNet {
        crate::net::ProcNet {
            name: name.to_string(),
            total,
            metric_source: "macos_nettop_bytes".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn net_response_truncates_then_counts_the_truncated_length_not_the_original() {
        // truncate-then-count is the one place `count` could silently drift from
        // `by_total_bytes.len()`: `to_json` always sets count to `rows.len()` of whatever it's
        // handed (see `crate::net::to_json`), so a future edit that serialized before truncating,
        // or truncated a clone instead of the real vec, would report the pre-truncation count
        // while shipping fewer rows — invisible on a real nettop sample, which rarely has more
        // than a handful of nonzero-traffic processes on a quiet dev machine.
        let rows = vec![
            fake_proc_net("a", 3),
            fake_proc_net("b", 2),
            fake_proc_net("c", 1),
        ];
        let json = net_response(rows, 2);
        assert!(json.contains("\"count\":2"), "{json}");
        assert!(json.contains("\"name\":\"a\""), "{json}");
        assert!(json.contains("\"name\":\"b\""), "{json}");
        assert!(
            !json.contains("\"name\":\"c\""),
            "row beyond the limit must not appear: {json}"
        );
    }

    #[test]
    fn net_response_default_limit_caps_at_15_matching_the_golden() {
        let rows: Vec<_> = (0..20)
            .map(|i| fake_proc_net(&format!("p{i}"), 20 - i))
            .collect();
        let json = net_response(rows, net_limit(&args(&["net"])));
        assert!(json.contains("\"count\":15"), "{json}");
        assert!(
            json.contains("\"name\":\"p14\""),
            "the 15th row (index 14) must survive: {json}"
        );
        assert!(
            !json.contains("\"name\":\"p15\""),
            "the 16th row must be truncated away: {json}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // `uninstall --list` — the one command that must NOT be envelope-wrapped
    // ---------------------------------------------------------------------------------------

    /// The golden vendored beside `crate::uninstall::list`, loaded here so this test grades the
    /// dispatch layer against the captured output of the real program rather than against a shape
    /// typed out in this file.
    ///
    /// Carries the same `target_os` gate as its ONE consumer below. Without it this is dead code on
    /// every non-macOS target, and `clippy --all-targets -- -D warnings` — which `ci.yml` runs on
    /// the ubuntu and windows legs too — turns that warning into a build failure.
    #[cfg(target_os = "macos")]
    const UNINSTALL_LIST_GOLDEN: &str = include_str!("uninstall/uninstall-list.golden.json");

    /// `--list` must reach the bare-array serializer and never the envelope. This is the whole
    /// point: `MoleClient.parseApps` does `jsonObject(...) as? [[String: Any]]` and returns `[]`
    /// for an object, so an envelope here empties the Software tab with no error anywhere.
    ///
    /// Asserted on the dispatch path (not just on `to_json`) because the regression this guards
    /// against is someone wrapping the call site, which a serializer-only test would not catch.
    #[test]
    #[cfg(target_os = "macos")]
    fn uninstall_list_emits_a_bare_array_never_an_envelope() {
        let (out, code) = dispatch(&args(&["uninstall", "--list"]));
        assert_eq!(code, 0, "--list enumerates and exits 0: {out}");
        let trimmed = out.trim_start();
        assert!(
            trimmed.starts_with('['),
            "must be a bare ARRAY — an envelope decodes to [] in parseApps. Got: {}",
            &trimmed[..trimmed.len().min(120)]
        );
        assert!(
            !trimmed.starts_with('{') && !out.contains("\"burrow_cli\""),
            "the envelope must not appear anywhere in this command's output: {}",
            &trimmed[..trimmed.len().min(120)]
        );
        let parsed = crate::json::Json::parse(&out).expect("output parses as JSON");
        let rows = parsed.as_array().expect("top level is an array");
        // Whatever this machine has installed, every row it does emit carries the golden's six
        // string keys — the contract `parseApps` reads.
        let golden = crate::json::Json::parse(UNINSTALL_LIST_GOLDEN).unwrap();
        let keys: Vec<&str> = golden
            .as_array()
            .unwrap()
            .first()
            .and_then(|r| match r {
                crate::json::Json::Object(m) => Some(m.keys().map(|k| k.as_str()).collect()),
                _ => None,
            })
            .expect("golden row is an object");
        for row in rows {
            for k in &keys {
                assert!(
                    row.get(k).and_then(|v| v.as_str()).is_some(),
                    "every row needs {k} as a STRING, per the golden"
                );
            }
        }
    }

    /// `--list` short-circuits before the destructive path, exactly as the oracle does: it must not
    /// fall through to "uninstall needs an app name", which is what it answered before.
    #[test]
    #[cfg(target_os = "macos")]
    fn uninstall_list_does_not_ask_for_a_bundle_id() {
        let (out, _) = dispatch(&args(&["uninstall", "--list"]));
        assert!(
            !out.contains("needs an app name"),
            "--list is a real command, not a missing positional: {out}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // `uninstall <name>…` — the resolution gate, and the multi-app request the app really sends
    // ---------------------------------------------------------------------------------------

    /// A root that does not exist and never will — where every defused golden row's bundle lives.
    const NOWHERE: &str = "/burrow-engine-tests/this-root-does-not-exist";

    /// The inventory tests resolve against, loaded from the anonymized `uninstall --list` fixture.
    /// Its fictional rows still use absolute `/Applications` paths and Homebrew-shaped tokens,
    /// so apply tests must never hand those values directly to a real remover or package manager.
    /// Defuse them here so every caller inherits the same filesystem and subprocess safeguards.
    ///
    /// So the raw rows never leave this function. What comes out:
    ///
    ///  - `path` re-rooted under [`NOWHERE`], **keeping the `.app` basename**, because that basename
    ///    is the resolver's second haystack (`basename $app_path .app`) and re-grading resolution
    ///    against an invented one would defeat the purpose of loading a capture at all.
    ///  - `source` forced to `"App"`, so `cli`'s `cask` lookup answers `None` and no row here can
    ///    reach `BundleAction::BrewZap` however it is later recombined. The real token stays in
    ///    `uninstall_name` — resolution tests need it, and with `source` neutralised it is inert.
    ///
    /// `scratch_inventory` and `brew_row` build on top of this, so they now re-point a row that was
    /// already harmless rather than being the only thing standing between a test and `/Applications`.
    fn golden_inventory() -> Vec<crate::uninstall::list::AppRow> {
        crate::uninstall::list::tests_support::golden_rows()
            .into_iter()
            .map(|mut r| {
                let base = r
                    .path
                    .rsplit('/')
                    .next()
                    .unwrap_or("Unknown.app")
                    .to_string();
                r.path = format!("{NOWHERE}/{base}");
                r.source = "App".to_string();
                r
            })
            .collect()
    }

    /// The defusing above is a safety property, so it is asserted rather than trusted: no row this
    /// function hands out may name a path that exists, and none may be Homebrew-sourced.
    #[test]
    fn the_golden_inventory_a_test_can_apply_points_at_no_real_application_and_no_cask() {
        let rows = golden_inventory();
        assert!(rows.len() >= 4, "the capture carries several rows");
        for r in &rows {
            assert!(
                !std::path::Path::new(&r.path).exists(),
                "{} points at something that EXISTS on this machine: {}",
                r.name,
                r.path
            );
            assert_eq!(
                r.source, "App",
                "{} is Homebrew-sourced, so an apply could run `brew uninstall --cask --zap {}`",
                r.name, r.uninstall_name
            );
        }
        // And the raw capture really does carry what the defusing exists to remove, so this is not
        // asserting a property the fixture has for free.
        let raw = crate::uninstall::list::tests_support::golden_rows();
        assert!(
            raw.iter().any(|r| r.source == "Homebrew"),
            "the capture must carry a Homebrew row or the source assertion above is vacuous"
        );
        assert!(
            raw.iter()
                .any(|r| std::path::Path::new(&r.path).starts_with("/Applications")),
            "the capture must carry a /Applications path or the path assertion above is vacuous"
        );
    }

    /// The golden rows, re-pointed at REAL fake bundles inside the scratch `home` so a test can
    /// apply and then assert against the filesystem.
    ///
    /// Measured, not theorised: the first run of the bundle-removal change against the unmodified
    /// test suite really did call `fs::remove_dir_all("/Applications/Python 3.13/IDLE.app")`, and the
    /// only reason nothing was destroyed is that the directory happens to be root-owned and the OS
    /// returned `EPERM`. A golden row pointing anywhere the test user can write — `~/Applications`, a
    /// user-installed app — would have been deleted.
    ///
    /// That is why [`golden_inventory`] now defuses the capture before anyone sees it and why
    /// [`default_uninstall_runner`] panics under `cfg(test)`. This function is no longer the thing
    /// standing between a test and `/Applications`; it is the ordinary way to get a bundle with real
    /// bytes in it. It still forces `source` to `"App"` — belt and braces, and it keeps the reader
    /// from having to check `golden_inventory` to know that a scratch inventory cannot reach brew.
    fn scratch_inventory(
        home: &std::path::Path,
        rows: &[crate::uninstall::list::AppRow],
        bytes: usize,
    ) -> Vec<crate::uninstall::list::AppRow> {
        rows.iter()
            .map(|r| {
                let app = home.join("Applications").join(format!("{}.app", r.name));
                fs::create_dir_all(app.join("Contents/MacOS")).expect("fake bundle");
                fs::write(app.join("Contents/Info.plist"), b"<plist/>").expect("fake plist");
                fs::write(app.join("Contents/MacOS/stub"), vec![b'x'; bytes]).expect("fake binary");
                let mut row = r.clone();
                row.path = app.to_string_lossy().to_string();
                row.source = "App".to_string();
                row.uninstall_name = r.name.clone();
                row
            })
            .collect()
    }

    /// The measured size of a bundle `scratch_inventory` planted — read off the filesystem rather
    /// than assumed, since the directory entries themselves contribute bytes.
    fn bundle_size(path: &str) -> u64 {
        crate::analyze::scanner::dir_size(std::path::Path::new(path)).max(0) as u64
    }

    /// Plant one leftover for `bundle_id` under `home` and return its size in bytes. Uses a location
    /// `leftover_paths` really constructs, so what the command finds is what a real install leaves.
    fn plant_leftover(home: &std::path::Path, bundle_id: &str) -> u64 {
        let cache = home.join("Library/Caches").join(bundle_id);
        fs::create_dir_all(&cache).expect("leftover dir");
        let blob = vec![b'x'; 4096];
        fs::write(cache.join("blob"), &blob).expect("leftover file");
        blob.len() as u64
    }

    /// **A planted leftover must SURVIVE `--apply --dry-run`.** The load-bearing test for the flag
    /// that used to be decorative.
    ///
    /// Reproduced on the release binary before the fix, against a scratch `HOME`:
    /// `burrow-engine uninstall org.python.IDLE --dry-run --apply --permanent` answered
    /// `"dry_run": false`, `"freed_bytes": 29`, and all three planted paths were gone from disk.
    /// `allowed_flags` declared `--dry-run`/`-n` for `uninstall` so they parsed cleanly and no error
    /// fired, while `uninstall_resolved` read exactly one flag — `--apply`. NOTHING ANYWHERE READ
    /// `--dry-run`, on any command.
    ///
    /// That is the one flag the original makes the only safety switch: `bin/uninstall.sh:1336-1338`
    /// maps `--dry-run|-n` to `MOLE_DRY_RUN=1`, and `--apply` does not exist there at all — it falls
    /// to the `-*)` arm at `:1351` and exits 1. `help` ADVERTISES both spellings, which is what an
    /// agent composing argv reads, so belt-and-braces is the natural thing to type.
    ///
    /// Both rails are exercised, because they fail differently: `dispatch` REFUSES the pair
    /// ([`reject_contradictory_flags`]), and `uninstall_resolved` — the injected seam, which does not
    /// run argv validation — still resolves toward the DRY RUN. The file is read back
    /// byte-for-byte rather than tested with `exists()`, so a truncate-and-leave would fail too.
    #[test]
    fn a_planted_leftover_survives_apply_when_dry_run_is_also_passed() {
        let home = fixture_dir("uninstall_dryrun_beats_apply");
        let target = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("the golden carries a row with a real bundle id");
        let inv = scratch_inventory(&home, &[target], 1024);
        let target = inv[0].clone();
        let planted = home
            .join("Library/Caches")
            .join(&target.bundle_id)
            .join("blob");
        plant_leftover(&home, &target.bundle_id);
        let before = fs::read(&planted).expect("the fixture really exists before the run");

        for dry in ["--dry-run", "-n"] {
            let argv = args(&[&target.name, "--apply", dry, "--permanent"]);
            let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
            assert_eq!(code, 0, "{dry}: {out}");
            let data = crate::json::Json::parse(&out)
                .expect("valid JSON")
                .get("data")
                .cloned()
                .expect("data");
            assert_eq!(
                data.get("dry_run").and_then(crate::json::Json::as_bool),
                Some(true),
                "{dry} must beat --apply — this said dry_run:false and deleted: {out}"
            );
            assert!(
                data.get("removed").is_none() && data.get("freed_bytes").is_none(),
                "a dry run reports no removals at all: {out}"
            );
            assert_eq!(
                fs::read(&planted).ok().as_ref(),
                Some(&before),
                "{dry}: the planted leftover was deleted by a DRY RUN"
            );
            // And the APPLICATION — the thing this command now removes — is still there. `--apply`
            // deleting an app because `--dry-run` was ignored is the same bug with a far larger
            // blast radius, so it gets its own assertion rather than riding on the leftover's.
            assert!(
                std::path::Path::new(&target.path).exists(),
                "{dry}: THE APPLICATION BUNDLE WAS DELETED BY A DRY RUN"
            );
        }

        // The other rail: through `dispatch`, the same argv never reaches the command. This one is
        // filesystem-free by construction — the refusal returns before `uninstall` scans anything —
        // so it is safe to run on any machine.
        let (out, code) = dispatch(&args(&[
            "uninstall",
            &target.name,
            "--apply",
            "--dry-run",
            "--permanent",
        ]));
        assert_eq!(code, 2, "malformed argv, like an unknown flag: {out}");
        assert_eq!(
            crate::json::Json::parse(&out)
                .expect("valid JSON")
                .get("ok")
                .and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        assert!(
            out.contains("--apply") && out.contains("--dry-run"),
            "the refusal names both flags so the caller can tell which to drop: {out}"
        );
        assert_eq!(
            fs::read(&planted).ok().as_ref(),
            Some(&before),
            "the refused run touched nothing"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// The same hole, on every command that has one — derived from [`allowed_flags`] rather than
    /// listed here, so a command that gains `--apply` tomorrow is covered without anyone remembering
    /// to add it. `clean`, `optimize`, `purge`, `installer` and `uninstall` all read `--apply` and
    /// declared a dry-run spelling; all five read only the first.
    ///
    /// `evict` and `dupes` also read `--apply` and are deliberately NOT expected here: neither
    /// declares `--dry-run`, so `reject_unknown_flag` already refuses the pair by the flag's own
    /// name. Asserted below rather than assumed, because "the hole does not exist there" is a claim
    /// about today's table.
    //
    // check_tests: no-golden — this grades argv parsing against the flag table itself. There is no
    // capture of "what the engine accepts"; the oracle side is cited per command in `allowed_flags`
    // and re-derived by the two flag-parity tests above.
    #[test]
    fn no_command_lets_apply_and_dry_run_through_together() {
        let mut checked = 0;
        for command in COMMANDS {
            let declared = allowed_flags(command).unwrap_or(&[]);
            if !declared.iter().any(|(n, _)| *n == "--apply") {
                continue;
            }
            let dry: Vec<&str> = ["--dry-run", "-n"]
                .into_iter()
                .filter(|f| declared.iter().any(|(n, _)| n == f))
                .collect();
            if dry.is_empty() {
                // The pair is unreachable: the dry-run spelling is not this command's flag.
                for f in ["--dry-run", "-n"] {
                    assert!(
                        reject_unknown_flag(command, &args(&["--apply", f])).is_some(),
                        "`{command} --apply {f}` must be refused by name"
                    );
                }
                continue;
            }
            for f in dry {
                checked += 1;
                let argv = args(&["--apply", f]);
                assert!(
                    !wants_apply(command, &argv),
                    "`{command} --apply {f}` still asked for the destructive run"
                );
                let (out, code) = reject_contradictory_flags(command, &argv)
                    .unwrap_or_else(|| panic!("`{command} --apply {f}` must be refused"));
                assert_eq!(code, 2, "{out}");
                assert!(out.contains(f) && out.contains("--apply"), "{out}");
                // Either flag ALONE stays perfectly legal — the point is the contradiction, not the
                // flags. `MoActions.swift:68-77` sends the dry-run form on its own.
                assert!(reject_contradictory_flags(command, &args(&[f])).is_none());
                assert!(reject_contradictory_flags(command, &args(&["--apply"])).is_none());
                assert!(wants_apply(command, &args(&["--apply"])));
            }
        }
        assert!(
            checked >= 8,
            "five commands take --apply and four of them take both spellings; only {checked} pairs \
             were reachable, so the table moved"
        );
    }

    /// THE regression this slice exists for. Three app names — the shape
    /// `MoActions.argv` builds from a Software-tab multi-select — go in, and every one of them must
    /// come back with its own outcome. The engine used to read `positionals()[0]` and act on that
    /// alone, so apps two and three were dropped while the report said the run succeeded.
    ///
    /// Driven through `uninstall_resolved`, which is `dispatch`'s uninstall path with only the
    /// inventory source and `$HOME` injected — argv parsing, resolution, leftover discovery and the
    /// JSON are all the production code.
    #[cfg(unix)]
    #[test]
    fn every_app_in_a_multi_app_request_gets_its_own_outcome() {
        let inv = golden_inventory();
        assert!(inv.len() >= 3, "the golden must carry three rows to select");
        let picked: Vec<_> = inv
            .iter()
            .filter(|r| r.bundle_id != "unknown")
            .take(3)
            .cloned()
            .collect();
        assert_eq!(picked.len(), 3, "three golden rows with real bundle ids");

        let home = fixture_dir("uninstall_multi");
        let inv = scratch_inventory(&home, &picked, 2048);
        let picked = inv.clone();
        // Two of the three have leftovers, the third has none — so "acted on all three" cannot be
        // faked by a run that only looked at the first, and "found nothing" is distinguishable from
        // "was never asked".
        let planted_a = plant_leftover(&home, &picked[0].bundle_id);
        let planted_c = plant_leftover(&home, &picked[2].bundle_id);
        let bundles: u64 = picked.iter().map(|r| bundle_size(&r.path)).sum();

        let argv = args(&[
            &picked[0].name,
            &picked[1].name,
            &picked[2].name,
            "--dry-run",
        ]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");

        let apps = data.get("apps").and_then(|a| a.as_array()).expect("apps");
        assert_eq!(
            apps.len(),
            3,
            "three names in, three apps reported — one-of-three was the bug: {out}"
        );
        for (i, want) in picked.iter().enumerate() {
            let got = &apps[i];
            let f = |k: &str| got.get(k).and_then(crate::json::Json::as_str);
            assert_eq!(f("query"), Some(want.name.as_str()), "app {i} query: {out}");
            assert_eq!(f("name"), Some(want.name.as_str()), "app {i} name: {out}");
            assert_eq!(
                f("bundle_id"),
                Some(want.bundle_id.as_str()),
                "app {i} resolved to the inventory's bundle id, not to the string typed: {out}"
            );
            assert_eq!(f("path"), Some(want.path.as_str()), "app {i} path: {out}");
        }
        let count = |i: usize| {
            apps[i]
                .get("item_count")
                .and_then(crate::json::Json::as_i64)
        };
        // `item_count` is the SUPPORT-FILE count and keeps that meaning — the bundle lives in the
        // per-app `application` object, not folded into this.
        assert_eq!(count(0), Some(1), "app 0 has the planted leftover: {out}");
        assert_eq!(count(1), Some(0), "app 1 genuinely has none: {out}");
        assert_eq!(
            count(2),
            Some(1),
            "app 2 was really acted on — this is the assertion the old code could not pass: {out}"
        );
        assert_eq!(
            data.get("total_bytes").and_then(crate::json::Json::as_i64),
            Some((planted_a + planted_c + bundles) as i64),
            "the total spans every app AND every app's bundle — the oracle's total_kb is \
             app_size_kb + related_size_kb (batch.sh:521): {out}"
        );

        // Every flattened item is attributable to the app it came from. Five now, not two: three
        // application bundles plus the two planted leftovers.
        let items = data.get("items").and_then(|i| i.as_array()).expect("items");
        assert_eq!(items.len(), 5, "{out}");
        let kinds: Vec<&str> = items
            .iter()
            .filter_map(|i| i.get("kind").and_then(crate::json::Json::as_str))
            .collect();
        assert_eq!(
            kinds.iter().filter(|k| **k == "application").count(),
            3,
            "every resolved app's bundle is named in the preview: {out}"
        );
        assert_eq!(
            kinds.iter().filter(|k| **k == "leftover").count(),
            2,
            "{out}"
        );
        let owners: Vec<&str> = items
            .iter()
            .filter_map(|i| i.get("bundle_id").and_then(crate::json::Json::as_str))
            .collect();
        assert!(
            owners.contains(&picked[0].bundle_id.as_str())
                && owners.contains(&picked[2].bundle_id.as_str()),
            "each item names the app it belongs to: {out}"
        );
        assert!(
            data.get("unmatched")
                .and_then(|u| u.as_array())
                .is_some_and(<[crate::json::Json]>::is_empty),
            "nothing went unmatched: {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// **One character must not be able to uninstall the machine.** `uninstall e` against this
    /// Mac's real inventory resolved 66 apps — IDLE, Pages, Numbers, Keynote, Microsoft Excel — and
    /// the only gate on acting was `--apply`.
    ///
    /// The substring sweep that does it is FAITHFUL (`bin/uninstall.sh:1153-1178`: no `break`, no
    /// cap, and `tests/uninstall.bats:1439` pins multi-match as intended), so this is not about
    /// narrowing resolution. It is about the half the port dropped: bash prints
    /// `Matched 66 app(s):` as a numbered list and blocks on `Proceed with uninstallation? [y/N]`
    /// (`:1400-1420`), where anything but `y` — INCLUDING EOF on a non-interactive stdin — reaches
    /// `Aborted.` and removes nothing. A one-shot JSON engine cannot ask, so it does not act.
    ///
    /// The dry run still enumerates everything, exactly as the oracle prints the list before asking,
    /// and now says so in two fields a caller cannot miss. A term that names ONE app is untouched,
    /// which is every argv the app sends.
    #[cfg(unix)]
    #[test]
    fn a_term_that_resolves_to_many_apps_refuses_to_apply_and_says_so_in_the_dry_run() {
        let home = fixture_dir("uninstall_ambiguous");
        // The golden's rows, with their bundles rebuilt inside the scratch tree — the tail of this
        // test really applies, and the golden's own `path` fields use `/Applications`.
        // See `scratch_inventory`.
        let inv = scratch_inventory(&home, &golden_inventory(), 512);
        // A substring shared by several golden rows — found in the capture rather than typed, so
        // this cannot rot into a term that matches one app and asserts nothing.
        let broad = ('a'..='z')
            .map(|c| c.to_string())
            .find(|c| {
                crate::uninstall::resolve::match_apps_by_name(&inv, &[c])
                    .matched
                    .len()
                    > 1
            })
            .expect("the golden has a letter that several app names share");
        let hits = crate::uninstall::resolve::match_apps_by_name(&inv, &[&broad])
            .matched
            .len();

        let (out, code) =
            uninstall_resolved(&args(&[&broad, "--apply"]), &inv, home.to_str().unwrap());
        assert_eq!(
            code, 1,
            "an unconfirmable multi-app apply is a refusal: {out}"
        );
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        assert!(
            out.contains(&format!("matched {hits} apps")) && out.contains(&broad),
            "the refusal names the term and the count, the way bash prints `Matched N app(s):`: \
             {out}"
        );

        // The dry run is unchanged in what it enumerates, and now carries the signal.
        let (out, code) = uninstall_resolved(&args(&[&broad]), &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("matched_count")
                .and_then(crate::json::Json::as_i64),
            Some(hits as i64),
            "{out}"
        );
        assert_eq!(
            data.get("requires_confirmation")
                .and_then(crate::json::Json::as_bool),
            Some(true),
            "{out}"
        );
        let ambiguous = data
            .get("ambiguous")
            .and_then(|a| a.as_array())
            .expect("ambiguous");
        assert_eq!(ambiguous.len(), 1, "{out}");
        assert_eq!(
            ambiguous[0]
                .get("matched")
                .and_then(crate::json::Json::as_i64),
            Some(hits as i64),
            "the caller can render the oracle's numbered list from this: {out}"
        );
        assert_eq!(
            ambiguous[0]
                .get("names")
                .and_then(|n| n.as_array())
                .map(<[_]>::len),
            Some(hits),
            "{out}"
        );
        assert!(
            data.get("items").is_some() && data.get("total_human").is_some(),
            "the two fields UninstallPreview decodes are untouched: {out}"
        );

        // A precise term is unaffected, in both directions: no confirmation demanded, and --apply
        // goes through. This is the argv `SoftwareModel.previewSource` and `removeSelected` build.
        let exact = &inv[0];
        plant_leftover(&home, &exact.bundle_id);
        let (out, code) =
            uninstall_resolved(&args(&[&exact.bundle_id]), &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("matched_count")
                .and_then(crate::json::Json::as_i64),
            Some(1),
            "{out}"
        );
        assert_eq!(
            data.get("requires_confirmation")
                .and_then(crate::json::Json::as_bool),
            Some(false),
            "a 1:1 resolution needs no confirmation the oracle would not have asked for: {out}"
        );
        let exact_path = exact.path.clone();
        let (out, code) = uninstall_resolved(
            &args(&[&exact.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "the precise apply still runs: {out}");
        assert!(
            out.contains("\"dry_run\":false"),
            "and it really applied: {out}"
        );
        assert!(
            !std::path::Path::new(&exact_path).exists(),
            "and applying now removes the APPLICATION, not only its leftovers: {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// **Naming one app beside a broad term must not smuggle the rest of the sweep through.**
    ///
    /// The gate used to group `resolution.matched` by `query` and refuse a group of more than one.
    /// `matched` is deduplicated by inventory POSITION, so a group counted what its term newly
    /// CONTRIBUTED, not what it SWEPT — and an app the broad term reached but an earlier term had
    /// already taken vanished from its group. Name k apps explicitly, add a term whose sweep hits
    /// those k plus one more, and every group has length 1.
    ///
    /// Reproduced on the release binary against a scratch `HOME` holding two apps sharing the prefix
    /// `Qxzy`:
    ///
    /// ```text
    /// uninstall qxzy --dry-run                       matched_count 2, requires_confirmation TRUE
    /// uninstall "Qxzy One" qxzy --dry-run            matched_count 2, requires_confirmation FALSE
    /// uninstall "Qxzy One" qxzy --apply --permanent  exit 0, ok:true, BOTH bundles deleted
    /// ```
    ///
    /// Bash has no such hole because it never groups per term: `bin/uninstall.sh:1400-1420` prints
    /// the FINAL SELECTED LIST — `Matched ${#selected_apps[@]} app(s):` — and blocks on
    /// `Proceed with uninstallation? [y/N]` over that list. The gate now reads
    /// `Resolution::swept`, which counts a term's hits before the dedup can hide one.
    ///
    /// The apply half asserts against the FILESYSTEM: both bundles have to still be there.
    #[cfg(unix)]
    #[test]
    fn naming_one_app_beside_a_broad_term_does_not_defeat_the_confirmation_gate() {
        let home = fixture_dir("uninstall_sweep_gate");
        // Two golden rows renamed to share a prefix, so the ambiguity is deterministic; everything
        // else about them is the capture's, and `scratch_inventory` plants real bundles for them.
        let mut rows = golden_inventory();
        assert!(rows.len() >= 2);
        rows[0].name = "Qxzy One".to_string();
        rows[1].name = "Qxzy Two".to_string();
        rows.truncate(2);
        let inv = scratch_inventory(&home, &rows, 1024);
        let paths: Vec<String> = inv.iter().map(|r| r.path.clone()).collect();

        // The bare broad term was always caught. Kept so a regression that breaks the gate outright
        // is not mistaken for this one being fixed.
        let (out, code) =
            uninstall_resolved(&args(&["qxzy", "--apply"]), &inv, home.to_str().unwrap());
        assert_eq!(code, 1, "the bare sweep is refused: {out}");

        // THE HOLE. One app named exactly, plus the term that sweeps both.
        let argv = args(&["Qxzy One", "qxzy", "--apply", "--permanent"]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(
            code, 1,
            "'qxzy' still reaches TWO apps; naming one of them does not make it precise: {out}"
        );
        assert_eq!(
            crate::json::Json::parse(&out)
                .expect("valid JSON")
                .get("ok")
                .and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        assert!(
            out.contains("matched 2 apps") && out.contains("Qxzy One") && out.contains("Qxzy Two"),
            "the refusal names the sweep and every app in it, the way bash prints `Matched N \
             app(s):`: {out}"
        );
        for p in &paths {
            assert!(
                std::path::Path::new(p).exists(),
                "A BUNDLE WAS DELETED BY AN UNCONFIRMED SWEEP: {p}"
            );
        }

        // And the dry run says so too, so a caller can see it before committing.
        let (out, code) =
            uninstall_resolved(&args(&["Qxzy One", "qxzy"]), &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("requires_confirmation")
                .and_then(crate::json::Json::as_bool),
            Some(true),
            "the preview reported FALSE here, which is what an agent would have acted on: {out}"
        );
        let ambiguous = data
            .get("ambiguous")
            .and_then(|a| a.as_array())
            .expect("ambiguous");
        assert_eq!(ambiguous.len(), 1, "{out}");
        assert_eq!(
            ambiguous[0]
                .get("matched")
                .and_then(crate::json::Json::as_i64),
            Some(2),
            "the sweep counts the app the earlier term already took: {out}"
        );
        // And each app says how it was reached, so a caller can see which of the two was named and
        // which was swept without re-deriving it.
        let by: Vec<&str> = data
            .get("apps")
            .and_then(|a| a.as_array())
            .expect("apps")
            .iter()
            .filter_map(|a| a.get("matched_by").and_then(crate::json::Json::as_str))
            .collect();
        assert_eq!(by, vec!["exact", "substring"], "{out}");

        // Naming BOTH apps is precise, and still goes through — the gate must not have become a
        // blanket refusal of multi-app requests, which is the argv the Software tab really sends.
        let (out, code) = uninstall_resolved(
            &args(&["Qxzy One", "Qxzy Two", "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "two exactly-named apps still apply: {out}");
        for p in &paths {
            assert!(
                !std::path::Path::new(p).exists(),
                "{p} should be gone: {out}"
            );
        }
        let _ = fs::remove_dir_all(&home);
    }

    /// **`uninstall unknown` must not resolve to an arbitrary application.**
    ///
    /// `list::build_row` writes the literal `UNKNOWN_BUNDLE_ID` for a bundle with no
    /// `CFBundleIdentifier`, `dedupe_by_bundle_id` deliberately skips those rows so all of them
    /// survive, and `uninstall --list` PUBLISHES it in the `bundle_id` column — so an agent reading
    /// the listing and passing the value back is the natural caller. The identifier pass matched it
    /// with `position()`: first hit, `found = true`, substring pass never runs, ambiguity sees one
    /// match. Measured on the release binary: `uninstall unknown --dry-run` answered
    /// `matched_count 1, requires_confirmation false` and `--apply` deleted that bundle.
    ///
    /// The oracle has no bundle-id matching at all, so this is the port's own extension misfiring in
    /// exactly the case its doc calls safe.
    #[cfg(unix)]
    #[test]
    fn the_unknown_bundle_id_sentinel_resolves_to_nothing_rather_than_to_whichever_app_sorts_first()
    {
        let home = fixture_dir("uninstall_unknown_sentinel");
        let mut rows = golden_inventory();
        assert!(rows.len() >= 2);
        // Two rows with no bundle identifier — the shape `dedupe_by_bundle_id` leaves intact.
        for r in rows.iter_mut().take(2) {
            r.bundle_id = crate::uninstall::list::UNKNOWN_BUNDLE_ID.to_string();
        }
        rows.truncate(2);
        let inv = scratch_inventory(&home, &rows, 1024);
        let paths: Vec<String> = inv.iter().map(|r| r.path.clone()).collect();

        for argv in [
            args(&[crate::uninstall::list::UNKNOWN_BUNDLE_ID, "--dry-run"]),
            args(&[
                crate::uninstall::list::UNKNOWN_BUNDLE_ID,
                "--apply",
                "--permanent",
            ]),
        ] {
            let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
            assert_eq!(code, 1, "the sentinel identifies no app: {out}");
            assert!(
                out.contains("No matching applications found."),
                "and it says so in the oracle's own words rather than picking one: {out}"
            );
        }
        for p in &paths {
            assert!(
                std::path::Path::new(p).exists(),
                "AN APPLICATION WITH NO BUNDLE ID WAS DELETED BY THE WORD 'unknown': {p}"
            );
        }

        // A REAL bundle id still resolves — the exclusion is of the sentinel, not of the pass.
        let mut real = golden_inventory();
        real.truncate(1);
        real[0].bundle_id = "com.example.real".to_string();
        let inv = scratch_inventory(&home, &real, 512);
        let (out, code) = uninstall_resolved(
            &args(&["com.example.real", "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let _ = fs::remove_dir_all(&home);
    }

    /// A name that resolves to no installed app is a FAILURE, not an empty success. The oracle
    /// prints `No matching applications found.` and returns 1 (`bin/uninstall.sh:1393-1397`); the
    /// engine used to answer `ok:true` with `items:[]`, which a caller cannot tell from an installed
    /// app that happens to have no leftovers.
    ///
    /// The wording is kept verbatim because `UninstallGuard.matchedApps` treats that exact sentence
    /// as "matched nothing" and returns `[]`, which is what makes the app's uninstall preflight fail
    /// closed instead of proceeding on an unparseable answer.
    #[test]
    fn a_name_that_matches_nothing_fails_instead_of_reporting_an_empty_success() {
        let inv = golden_inventory();
        let home = fixture_dir("uninstall_nomatch");
        let argv = args(&["com.nonexistent.Nothing", "--dry-run"]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(code, 1, "the oracle exits 1 here: {out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        assert!(
            out.contains("No matching applications found."),
            "the oracle's wording, which UninstallGuard reads: {out}"
        );
        assert!(
            out.contains("com.nonexistent.Nothing"),
            "the failure names what could not be resolved: {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// A typo alongside real apps: the oracle warns per unmatched term and carries on with the rest
    /// (`bin/uninstall.sh:1185`). The two that resolved are still acted on, and the one that did not
    /// is reported rather than dropped — so a caller can tell "removed 2" from "removed 2 of 3".
    #[test]
    fn an_unmatched_name_alongside_real_ones_is_reported_not_dropped() {
        let inv = golden_inventory();
        let picked: Vec<_> = inv
            .iter()
            .filter(|r| r.bundle_id != "unknown")
            .take(2)
            .cloned()
            .collect();
        let home = fixture_dir("uninstall_partial");
        let argv = args(&[
            &picked[0].name,
            "totally-not-installed-zzz",
            &picked[1].name,
            "--dry-run",
        ]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "a partial match still runs: {out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("apps").and_then(|a| a.as_array()).map(<[_]>::len),
            Some(2),
            "{out}"
        );
        let unmatched: Vec<&str> = data
            .get("unmatched")
            .and_then(|u| u.as_array())
            .expect("unmatched")
            .iter()
            .filter_map(crate::json::Json::as_str)
            .collect();
        assert_eq!(unmatched, vec!["totally-not-installed-zzz"], "{out}");
        let _ = fs::remove_dir_all(&home);
    }

    /// The two fields the GUI's leftover review really decodes. `UninstallPreview.fromEngineEnvelope`
    /// (`UninstallPreview.swift:137-152`) reads `data.items[].path` and `data.total_human` and
    /// nothing else, returning an EMPTY preview when `items` is absent — so restructuring the dry run
    /// into a purely per-app shape would blank that pane with no error anywhere. They stay top-level
    /// and flattened for exactly that reason.
    #[cfg(unix)]
    /// `leftover_paths` interpolates the inventory's `CFBundleIdentifier` straight into
    /// `~/Library/<subdir>/<id>`. An id of `a/../b` therefore named `~/Library/Caches/b` — a
    /// directory belonging to some other app entirely — as this app's cache. The oracle gates every
    /// such interpolation on `mole_is_reverse_dns_bundle_id` (`lib/core/base.sh:513`); this pins that
    /// the gate is wired through the command, not only present in the module.
    #[cfg(unix)]
    #[test]
    fn a_bundle_id_that_is_not_reverse_dns_yields_no_leftovers_and_a_refusal_in_warnings() {
        let home = fixture_dir("uninstall_bad_bundle_id");
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        row.bundle_id = "a/../b".to_string();
        let inv = scratch_inventory(&home, &[row], 64);
        let row = inv[0].clone();
        // What the unvalidated interpolation would have reached.
        let victim = home.join("Library/Caches/b");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("blob"), vec![b'x'; 2048]).unwrap();

        let (out, code) = uninstall_resolved(
            &args(&[&row.name, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let items = data.get("items").and_then(|i| i.as_array()).expect("items");
        assert_eq!(items.len(), 1, "only the application, no leftovers: {out}");
        // The id is still ECHOED as this app's identity (`bundle_id` fields) — what must never
        // appear is a PATH built from it.
        assert!(
            !out.contains("Library/Caches/b")
                && items.iter().all(|i| i
                    .get("path")
                    .and_then(crate::json::Json::as_str)
                    .is_some_and(|p| !p.contains("a/../b"))),
            "no path may be built from the refused id: {out}"
        );
        let warnings = data
            .get("warnings")
            .and_then(crate::json::Json::as_array)
            .expect("warnings");
        assert!(
            warnings.iter().any(|w| w
                .as_str()
                .is_some_and(|w| w.contains("refused") && w.contains("a/../b"))),
            "the refusal is reported with its reason: {out}"
        );
        assert!(victim.join("blob").exists());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn the_dry_run_keeps_the_flat_items_list_the_gui_preview_decodes() {
        let home = fixture_dir("uninstall_preview");
        let row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        let inv = scratch_inventory(&home, &[row], 4096);
        let row = inv[0].clone();
        let size = plant_leftover(&home, &row.bundle_id);
        let bundle = bundle_size(&row.path);
        let argv = args(&[&row.name, "--dry-run"]);
        let (out, _) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let items = data.get("items").and_then(|i| i.as_array()).expect("items");
        // TWO now: the application bundle FIRST, then the support file. The bundle being in this
        // list is what makes the preview name every byte the apply removes.
        assert_eq!(items.len(), 2, "{out}");
        let path_of = |i: usize| items[i].get("path").and_then(crate::json::Json::as_str);
        let kind_of = |i: usize| items[i].get("kind").and_then(crate::json::Json::as_str);
        assert_eq!(path_of(0), Some(row.path.as_str()), "bundle first: {out}");
        assert_eq!(kind_of(0), Some("application"), "{out}");
        assert!(
            path_of(1).is_some_and(|p| p.contains(&row.bundle_id)),
            "the preview decodes items[].path: {out}"
        );
        assert_eq!(kind_of(1), Some("leftover"), "{out}");
        assert!(
            data.get("total_human")
                .and_then(crate::json::Json::as_str)
                .is_some(),
            "the preview decodes total_human: {out}"
        );
        // `preview_bytes` promises nothing for a bundle a rail refuses (`bundle.rs`), and off unix
        // the rails' platform guard (`clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS`) refuses
        // every path — so there the honest total is 0, and the items above are still listed so
        // the GUI preview decodes the same shape.
        let expected_total = if crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            (size + bundle) as i64
        } else {
            0
        };
        assert_eq!(
            data.get("total_bytes").and_then(crate::json::Json::as_i64),
            Some(expected_total),
            "the total is the oracle's app_size_kb + related_size_kb (batch.sh:521), or 0 for a \
             bundle the rails refuse: {out}"
        );
        // And the caller is told, in one field, that this apply removes an application — counted
        // only for a bundle no rail refuses, so it follows the same platform guard as the total.
        let expected_removes = i64::from(crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS);
        assert_eq!(
            data.get("removes_applications")
                .and_then(crate::json::Json::as_i64),
            Some(expected_removes),
            "{out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// `--apply` over a multi-app request removes each app's leftovers and accounts for them per
    /// app. Run against a scratch `$HOME` with `--permanent`, so nothing outside the fixture is
    /// touched and the removal is a plain `remove_dir_all` rather than a real Trash call.
    #[cfg(unix)]
    #[test]
    fn apply_removes_every_resolved_app_and_accounts_per_app() {
        let home = fixture_dir("uninstall_apply");
        let picked: Vec<_> = golden_inventory()
            .into_iter()
            .filter(|r| r.bundle_id != "unknown")
            .take(2)
            .collect();
        let inv = scratch_inventory(&home, &picked, 4096);
        let picked = inv.clone();
        let a = plant_leftover(&home, &picked[0].bundle_id);
        let b = plant_leftover(&home, &picked[1].bundle_id);
        let bundles: u64 = picked.iter().map(|r| bundle_size(&r.path)).sum();

        let argv = args(&[&picked[0].name, &picked[1].name, "--apply", "--permanent"]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("freed_bytes").and_then(crate::json::Json::as_i64),
            Some((a + b + bundles) as i64),
            "both apps' bundles AND leftovers were freed, not just the first, and not only the \
             leftovers: {out}"
        );
        assert_eq!(
            data.get("applications_removed")
                .and_then(crate::json::Json::as_i64),
            Some(2),
            "{out}"
        );
        let apps = data.get("apps").and_then(|x| x.as_array()).expect("apps");
        assert_eq!(apps.len(), 2, "{out}");
        for (i, want) in picked.iter().enumerate() {
            assert_eq!(
                apps[i].get("bundle_id").and_then(crate::json::Json::as_str),
                Some(want.bundle_id.as_str()),
                "{out}"
            );
            assert_eq!(
                apps[i]
                    .get("removed_count")
                    .and_then(crate::json::Json::as_i64),
                Some(1),
                "app {i} really had its leftover removed: {out}"
            );
            assert_eq!(
                apps[i].get("status").and_then(crate::json::Json::as_str),
                Some("removed"),
                "app {i} is fully removed, bundle included: {out}"
            );
            let application = apps[i].get("application").expect("application");
            assert_eq!(
                application.get("state").and_then(crate::json::Json::as_str),
                Some("removed"),
                "{out}"
            );
            assert_eq!(
                application.get("via").and_then(crate::json::Json::as_str),
                Some("permanent"),
                "--permanent is an irreversible delete and the report says so: {out}"
            );
            // The accounting decomposes exactly — no caller has to infer which half is which.
            let n = |o: &crate::json::Json, k: &str| {
                o.get(k).and_then(crate::json::Json::as_i64).unwrap_or(-1)
            };
            assert_eq!(
                n(&apps[i], "freed_bytes"),
                n(application, "bytes") + n(&apps[i], "leftover_freed_bytes"),
                "freed_bytes == application.bytes + leftover_freed_bytes: {out}"
            );
        }
        // THE FILESYSTEM, not just the report — the load-bearing assertion.
        for r in &picked {
            assert!(
                !std::path::Path::new(&r.path).exists(),
                "{} bundle is gone from disk",
                r.path
            );
            assert!(
                !home.join("Library/Caches").join(&r.bundle_id).exists(),
                "{} leftover is gone from disk",
                r.bundle_id
            );
        }
        // `removed[]` distinguishes the two kinds, so a caller can say "the application and 1
        // support file" rather than "2 items".
        let removed = data
            .get("removed")
            .and_then(|r| r.as_array())
            .expect("removed");
        let kinds: Vec<&str> = removed
            .iter()
            .filter_map(|r| r.get("kind").and_then(crate::json::Json::as_str))
            .collect();
        assert_eq!(
            kinds.iter().filter(|k| **k == "application").count(),
            2,
            "{out}"
        );
        assert_eq!(
            kinds.iter().filter(|k| **k == "leftover").count(),
            2,
            "{out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// **THE load-bearing test for this slice.** The dry run enumerates the application bundle and
    /// leaves it on disk; the apply removes it. Both halves asserted against the FILESYSTEM, not
    /// against the report — a report is what said "removed" while `/Applications` was untouched, and
    /// is exactly the evidence that cannot be trusted here.
    ///
    /// The bundle is a fake one built inside the scratch tree (`scratch_inventory`); the golden's own
    /// `path` fields use `/Applications` and must never be passed directly to apply.
    #[cfg(unix)]
    #[test]
    fn a_dry_run_enumerates_the_bundle_and_an_apply_removes_it_from_disk() {
        let home = fixture_dir("uninstall_bundle_e2e");
        let row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        let inv = scratch_inventory(&home, &[row], 8192);
        let row = inv[0].clone();
        let bundle = std::path::PathBuf::from(&row.path);
        let stub = bundle.join("Contents/MacOS/stub");
        assert!(
            stub.exists(),
            "the fixture bundle really exists to begin with"
        );

        // 1. The dry run NAMES it and TOUCHES NOTHING.
        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let named: Vec<&str> = data
            .get("items")
            .and_then(|i| i.as_array())
            .expect("items")
            .iter()
            .filter_map(|i| i.get("path").and_then(crate::json::Json::as_str))
            .collect();
        assert!(
            named.contains(&row.path.as_str()),
            "the preview must name the bundle the apply will remove: {out}"
        );
        assert!(
            stub.exists(),
            "a dry run must not touch the bundle: {}",
            row.path
        );

        // 2. The apply REMOVES it. `--permanent`, so this is a plain `remove_dir_all` in the scratch
        //    tree rather than a real Trash move into whoever is running the suite (see
        //    `crate::trash`'s docs: Trash is per-volume and a scratch HOME cannot redirect it).
        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        assert!(
            !bundle.exists() && bundle.symlink_metadata().is_err(),
            "THE APPLICATION BUNDLE IS STILL ON DISK after --apply: {}",
            row.path
        );
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("applications_removed")
                .and_then(crate::json::Json::as_i64),
            Some(1),
            "{out}"
        );
    }

    /// The oracle's surprising ordering, reproduced: the bundle goes FIRST and the leftover sweep is
    /// gated on it having worked (`batch.sh:840`'s `if [[ -z "$reason" ]]`). An app whose bundle
    /// cannot be removed keeps its support files, because half-uninstalling an app you could not
    /// uninstall leaves it broken rather than merely present.
    ///
    /// The refusal is produced hermetically: a bundle whose name embeds a newline, which
    /// `validate_path_for_deletion` refuses on control-character grounds (`file_ops.sh:129-134`) —
    /// the same rail, exercised without pointing a test at a real critical system path.
    #[cfg(unix)]
    #[test]
    fn a_bundle_the_third_rail_refuses_leaves_the_leftovers_untouched_too() {
        let home = fixture_dir("uninstall_gate");
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        let bundle = home.join("Applications").join("Bad\nName.app");
        fs::create_dir_all(bundle.join("Contents/MacOS")).expect("fake bundle");
        fs::write(bundle.join("Contents/MacOS/stub"), vec![b'x'; 512]).expect("fake binary");
        row.path = bundle.to_string_lossy().to_string();
        row.source = "App".to_string();
        let inv = vec![row.clone()];
        plant_leftover(&home, &row.bundle_id);
        let leftover = home.join("Library/Caches").join(&row.bundle_id);

        // The preview already says it will be refused, rather than promising a removal it will decline.
        let (out, _) = uninstall_resolved(
            &args(&[&row.bundle_id, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
        );
        let app = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .and_then(|d| d.get("apps"))
            .and_then(|a| a.as_array())
            .map(|a| a[0].clone())
            .expect("apps[0]");
        assert!(
            app.get("application")
                .and_then(|b| b.get("refusal"))
                .and_then(crate::json::Json::as_str)
                .is_some(),
            "the preview must not promise to remove a bundle the rail refuses: {out}"
        );
        // …and it promises NO BYTES AT ALL, not merely none of the bundle's own. The leftovers are
        // gated behind the bundle (`batch.sh:840`), so a refused bundle frees nothing — the preview
        // used to answer `total_bytes 9000` for a run whose apply freed 0 and left the leftover on
        // disk.
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("total_bytes").and_then(crate::json::Json::as_i64),
            Some(0),
            "the dry run promised bytes the apply cannot free: {out}"
        );
        assert!(
            data.get("items")
                .and_then(|i| i.as_array())
                .is_some_and(|i| i.len() >= 2),
            "both the bundle and its leftover are still NAMED — only the total changed: {out}"
        );

        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(
            code, 1,
            "a refused application is not a successful run: {out}"
        );
        assert!(
            bundle.exists(),
            "the bundle was refused, so it is still there"
        );
        assert!(
            leftover.exists(),
            "AND THE LEFTOVERS MUST STILL BE THERE — batch.sh:840 gates the whole sweep on the \
             bundle having come away: {out}"
        );
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        assert_eq!(
            app.get("status").and_then(crate::json::Json::as_str),
            Some("refused"),
            "{out}"
        );
        assert_eq!(
            app.get("leftovers_attempted")
                .and_then(crate::json::Json::as_bool),
            Some(false),
            "the report says the sweep never ran, rather than reporting zero removals: {out}"
        );
        assert_eq!(
            data.get("freed_bytes").and_then(crate::json::Json::as_i64),
            Some(0),
            "nothing may be claimed: {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// A bundle that is already gone is a SUCCESS in the oracle — `mole_delete` returns 0 for a path
    /// that is not there (`file_ops.sh:511-513`), so `reason` stays empty and the leftover sweep
    /// still runs. Surprising (you would expect "app not found") and reproduced, because it is what
    /// makes "the user dragged the app to the Trash last week, now clean up after it" work.
    #[cfg(unix)]
    #[test]
    fn an_already_absent_bundle_is_a_success_and_the_leftovers_still_go() {
        let home = fixture_dir("uninstall_absent");
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        row.path = home
            .join("Applications/NeverInstalled.app")
            .to_string_lossy()
            .to_string();
        row.source = "App".to_string();
        let inv = vec![row.clone()];
        let planted = plant_leftover(&home, &row.bundle_id);

        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "an absent bundle is not a failure: {out}");
        assert!(
            !home.join("Library/Caches").join(&row.bundle_id).exists(),
            "the leftovers were still swept"
        );
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        assert_eq!(
            app.get("status").and_then(crate::json::Json::as_str),
            Some("removed"),
            "{out}"
        );
        assert_eq!(
            app.get("application")
                .and_then(|b| b.get("state"))
                .and_then(crate::json::Json::as_str),
            Some("absent"),
            "and the caller can tell 'we removed it' from 'it was not there': {out}"
        );
        assert_eq!(
            data.get("applications_removed")
                .and_then(crate::json::Json::as_i64),
            Some(0),
            "an absent bundle is not one this run removed: {out}"
        );
        assert_eq!(
            data.get("freed_bytes").and_then(crate::json::Json::as_i64),
            Some(planted as i64),
            "{out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// A Homebrew row for the brew tests below. Built by hand from a golden row rather than through
    /// `scratch_inventory` (which deliberately forces `source: "App"` so no test wanders onto the
    /// brew path by accident) — these tests want that path, with the subprocess runner faked.
    fn brew_row(
        home: &std::path::Path,
        token: &str,
    ) -> (crate::uninstall::list::AppRow, std::path::PathBuf) {
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("a row with a real bundle id");
        let bundle = home.join("Applications").join(format!("{token}.app"));
        fs::create_dir_all(bundle.join("Contents/MacOS")).expect("fake bundle");
        fs::write(bundle.join("Contents/MacOS/stub"), vec![b'x'; 2048]).expect("fake binary");
        row.path = bundle.to_string_lossy().to_string();
        row.source = "Homebrew".to_string();
        row.uninstall_name = token.to_string();
        (row, bundle)
    }

    /// `brew uninstall --cask --zap` removes bytes the preview cannot enumerate, so the preview has
    /// to NAME THE COMMAND. The oracle does the same thing in prose (`batch.sh:585`, "Homebrew apps
    /// will be fully cleaned, --zap removes configs and data").
    ///
    /// And a dry run must not run brew at all — `brew.sh:201-204` returns success immediately under
    /// `MOLE_DRY_RUN=1` without invoking anything. Proven by an injected runner that PANICS if
    /// called.
    #[test]
    fn a_homebrew_cask_declares_its_zap_in_the_preview_and_never_invokes_brew_in_a_dry_run() {
        let home = fixture_dir("uninstall_brew_preview");
        let (row, bundle) = brew_row(&home, "somecask");
        let inv = vec![row.clone()];

        let (out, code) = uninstall_resolved_with(
            &args(&[&row.bundle_id, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
            &|program, argv, _| {
                panic!("a dry run must not shell out: {program} {argv:?}");
            },
        );
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let external = data
            .get("external_commands")
            .and_then(|e| e.as_array())
            .expect("external_commands");
        assert_eq!(external.len(), 1, "{out}");
        assert_eq!(
            external[0]
                .get("command")
                .and_then(crate::json::Json::as_str),
            Some("brew uninstall --cask --zap somecask"),
            "the exact command, --zap included, so the preview does not silently omit an \
             unbounded delete: {out}"
        );
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        assert_eq!(
            app.get("application")
                .and_then(|b| b.get("action"))
                .and_then(crate::json::Json::as_str),
            Some("brew_zap"),
            "{out}"
        );
        assert_eq!(
            app.get("application")
                .and_then(|b| b.get("cask"))
                .and_then(crate::json::Json::as_str),
            Some("somecask"),
            "{out}"
        );
        assert!(bundle.exists(), "and nothing was removed");
        let _ = fs::remove_dir_all(&home);
    }

    /// The brew ladder's refusal, end to end: `brew uninstall` fails and `brew list --cask` still
    /// reports the cask installed, so the oracle will NOT delete the bundle by hand — doing so
    /// "would recreate the mismatch where brew still reports the app as installed after Mole removes
    /// the bundle manually" (`batch.sh:762-766`). The leftover sweep is gated behind that too.
    #[cfg(unix)]
    #[test]
    fn a_brew_cask_whose_uninstall_fails_removes_nothing_and_hands_back_the_zap_command() {
        let home = fixture_dir("uninstall_brew_fail");
        let (row, bundle) = brew_row(&home, "stubborn");
        let inv = vec![row.clone()];
        plant_leftover(&home, &row.bundle_id);

        let (out, code) = uninstall_resolved_with(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
            // `brew uninstall` fails; `brew list --cask` still lists the token.
            &|_, argv, _| {
                argv.contains(&"list")
                    .then(|| "stubborn\nother\n".to_string())
            },
        );
        assert_eq!(code, 1, "{out}");
        assert!(bundle.exists(), "the bundle must NOT be hand-deleted here");
        assert!(
            home.join("Library/Caches").join(&row.bundle_id).exists(),
            "and the leftovers are gated behind it: {out}"
        );
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        assert_eq!(
            app.get("status").and_then(crate::json::Json::as_str),
            Some("failed"),
            "brew TRIED and could not; `refused` is the word for a rail declining, and handing the \
             GUI that one makes it print `the engine refused to remove the application` about a \
             Homebrew failure: {out}"
        );
        assert_eq!(
            data.get("applications_failed")
                .and_then(crate::json::Json::as_i64),
            Some(1),
            "and it is counted as a failure, not as a refusal: {out}"
        );
        assert_eq!(
            data.get("applications_refused")
                .and_then(crate::json::Json::as_i64),
            Some(0),
            "{out}"
        );
        let application = app.get("application").expect("application");
        assert_eq!(
            application
                .get("reason")
                .and_then(crate::json::Json::as_str),
            Some("brew uninstall failed, package still installed"),
            "{out}"
        );
        assert_eq!(
            application
                .get("suggestion")
                .and_then(crate::json::Json::as_str),
            Some("Run brew uninstall --cask --zap stubborn"),
            "the oracle's own remediation text (batch.sh:782): {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// **A refusal the preview published binds the HOMEBREW arm too.**
    ///
    /// `remove_bundle` checked `plan.bundle.present` and nothing else. Its `Delete` arm goes through
    /// `execute_clean`, which re-runs the rail per item; its `BrewZap` arm went straight to
    /// `brew uninstall --cask --zap <token>`, which checks nothing. So a dry run could report
    /// `refusal: "path validation failed…"`, `removes_applications: 0` and `total_bytes: 0`, and the
    /// apply would zap the cask anyway — plus everything the cask's zap stanza declares, which no
    /// enumeration here can predict.
    ///
    /// bash's brew arm skips `validate_path_for_deletion` too and that rail skip is faithful; what
    /// was not faithful is the CONTRADICTION, since bash never computes a refusal for that path and
    /// so its preview promises nothing.
    ///
    /// The runner PANICS if called: the assertion is that brew is never reached, and a fake that
    /// merely returned nothing would let a regression pass by luck.
    #[cfg(unix)]
    #[test]
    fn a_refused_bundle_is_not_zapped_by_the_homebrew_arm_either() {
        let home = fixture_dir("uninstall_brew_refused");
        // A control-character path — the rail refuses it (`file_ops.sh:129-134`) — on a row the
        // inventory reports as Homebrew-managed, which is what routes it to the zap.
        let (mut row, bundle) = brew_row(&home, "refusedcask");
        let bad = home.join("Applications").join("Bad\nCask.app");
        fs::create_dir_all(bad.join("Contents/MacOS")).expect("fake bundle");
        fs::write(bad.join("Contents/MacOS/stub"), vec![b'x'; 512]).expect("fake binary");
        let _ = fs::remove_dir_all(&bundle);
        row.path = bad.to_string_lossy().to_string();
        let inv = vec![row.clone()];

        // The preview refuses it and promises nothing.
        let (out, code) = uninstall_resolved_with(
            &args(&[&row.bundle_id, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
            &|p, a, _| panic!("a dry run must not shell out: {p} {a:?}"),
        );
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        assert!(
            app.get("application")
                .and_then(|b| b.get("refusal"))
                .and_then(crate::json::Json::as_str)
                .is_some(),
            "the preview must state the refusal: {out}"
        );
        assert_eq!(
            data.get("removes_applications")
                .and_then(crate::json::Json::as_i64),
            Some(0),
            "{out}"
        );

        // And the APPLY honours what the preview just said, instead of zapping the cask.
        let (out, code) = uninstall_resolved_with(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
            &|p, a, _| {
                panic!("THE APPLY RAN `{p} {a:?}` FOR A BUNDLE THE PREVIEW REFUSED");
            },
        );
        assert_eq!(
            code, 1,
            "a refused application is not a successful run: {out}"
        );
        assert!(bad.exists(), "and nothing was removed");
        let app = &crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .and_then(|d| d.get("apps"))
            .and_then(|a| a.as_array())
            .expect("apps")[0]
            .clone();
        assert_eq!(
            app.get("status").and_then(crate::json::Json::as_str),
            Some("refused"),
            "{out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// **A symlinked `.app` must not report a removal it did not perform, or bytes it did not free.**
    ///
    /// `remove_dir_all` correctly removes only the link — verified, the target survives — but
    /// `inspect` sized through the link with `is_dir()`/`dir_size()`, both of which follow symlinks,
    /// and `execute_clean` then claimed the planned size once the directory entry was gone. Scaled to
    /// a `/Applications/Foo.app` symlinked at a 4 GB bundle, the engine reported freeing 4 GB while
    /// the application was still installed and launchable.
    // cfg(unix): the body creates a real symlink, and `std::os::unix::fs::symlink` does not
    // exist on Windows — where the equivalent needs a privilege an unelevated CI runner does
    // not have. The BEHAVIOUR under test (a symlinked bundle must be sized by the link, not by
    // the application it points at) is unix-only in the same way, so this is scoping the test
    // to where the case exists rather than hiding a failure.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_bundle_reports_the_links_bytes_and_says_the_application_is_still_installed() {
        let home = fixture_dir("uninstall_symlink");
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != crate::uninstall::list::UNKNOWN_BUNDLE_ID)
            .expect("a row with a real bundle id");
        // The real application, well away from the search path, and a link to it where the inventory
        // says the app lives.
        let real = home.join("Elsewhere/Real.app");
        fs::create_dir_all(real.join("Contents/MacOS")).expect("real bundle");
        fs::write(real.join("Contents/MacOS/big"), vec![b'x'; 200_000]).expect("real binary");
        let link = home.join("Applications/Linked.app");
        fs::create_dir_all(home.join("Applications")).expect("apps dir");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        row.path = link.to_string_lossy().to_string();
        row.source = "App".to_string();
        let inv = vec![row.clone()];

        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--dry-run"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        let app = &data.get("apps").and_then(|a| a.as_array()).expect("apps")[0];
        let application = app.get("application").expect("application");
        assert_eq!(
            application
                .get("symlink")
                .and_then(crate::json::Json::as_bool),
            Some(true),
            "the report has to carry that this is a link: {out}"
        );
        assert_eq!(
            application
                .get("symlink_target")
                .and_then(crate::json::Json::as_str),
            Some(real.to_string_lossy().as_ref()),
            "{out}"
        );
        assert!(
            data.get("total_bytes")
                .and_then(crate::json::Json::as_i64)
                .is_some_and(|n| n < 1024),
            "the preview promised the TARGET's 200 KB: {out}"
        );
        assert!(
            data.get("warnings")
                .and_then(|w| w.as_array())
                .is_some_and(|w| w
                    .iter()
                    .any(|s| s.as_str().is_some_and(|s| s.contains("symbolic link")))),
            "and a caller is told in words, not only in a flag: {out}"
        );

        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let freed = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .and_then(|d| d.get("freed_bytes"))
            .and_then(crate::json::Json::as_i64)
            .expect("freed_bytes");
        assert!(
            freed < 1024,
            "THE RUN CLAIMED THE TARGET'S BYTES: freed_bytes {freed}, {out}"
        );
        assert!(
            real.join("Contents/MacOS/big").exists(),
            "the application itself is untouched, which is why claiming its bytes was a lie"
        );
        assert!(link.symlink_metadata().is_err(), "the link really went");
        let _ = fs::remove_dir_all(&home);
    }

    /// **The apply leaves an audit record.** `clean` (`cli.rs:212`, `:244`), `purge` and `installer`
    /// each open a `SessionLog`; the command that deletes APPLICATIONS opened none, so a
    /// `--permanent` or a `--zap` left nothing anywhere saying what it removed.
    ///
    /// The oracle has no such gap and it is not incidental: `mole_delete` appends
    /// `<ts>\t<mode>\t<size_kb>\t<status>\t<path>` for every path it touches (`file_ops.sh:491-596`),
    /// including the ones it REFUSES — `rejected` at `:523` exists so an audit trail can tell
    /// refused-by-policy from never-attempted. Both are asserted here, by reading the log back
    /// through the module's own parser rather than by grepping text.
    #[cfg(unix)]
    #[test]
    fn an_apply_writes_the_deletion_audit_record_the_oracle_writes_including_for_a_refusal() {
        let home = fixture_dir("uninstall_audit");
        let del = home.join("Library/Logs/mole/deletions.log");

        // 1. A removal.
        let row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != crate::uninstall::list::UNKNOWN_BUNDLE_ID)
            .expect("a row with a real bundle id");
        let inv = scratch_inventory(&home, &[row], 4096);
        let row = inv[0].clone();
        plant_leftover(&home, &row.bundle_id);
        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        let text = fs::read_to_string(&del).unwrap_or_else(|e| {
            panic!(
                "NO DELETION LOG AFTER A --permanent UNINSTALL ({e}): {}",
                del.display()
            )
        });
        let records = crate::history::parse_deletions(&text);
        let bundle_record = records
            .iter()
            .find(|d| d.path == row.path)
            .unwrap_or_else(|| panic!("the APPLICATION is missing from the audit log: {text}"));
        assert_eq!(bundle_record.mode, "permanent", "{text}");
        assert!(
            records.iter().any(|d| d.path.contains("Library/Caches")),
            "and its leftovers are recorded too: {text}"
        );

        // 2. A refusal, which bash records as `rejected` rather than omitting.
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != crate::uninstall::list::UNKNOWN_BUNDLE_ID)
            .expect("a row with a real bundle id");
        let bad = home.join("Applications").join("Bad\nAudit.app");
        fs::create_dir_all(bad.join("Contents/MacOS")).expect("fake bundle");
        fs::write(bad.join("Contents/MacOS/stub"), vec![b'x'; 256]).expect("fake binary");
        row.path = bad.to_string_lossy().to_string();
        row.bundle_id = "com.example.audit".to_string();
        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &[row.clone()],
            home.to_str().unwrap(),
        );
        assert_eq!(code, 1, "{out}");
        let text = fs::read_to_string(&del).expect("deletion log");
        // Asserted against the raw text rather than through `parse_deletions`: the only refusal a
        // test can provoke hermetically is a control-character path, and a path carrying a newline
        // spans two lines of a line-oriented TSV. bash's log has the identical property — its
        // `_mole_delete_log` printf takes the raw path too — so this is the record's real shape, not
        // a shortcut around a broken one.
        assert!(
            text.contains(&format!("\tpermanent\t0\trejected\t{}", row.path)),
            "A REFUSED APPLICATION LEFT NO RECORD — `rejected` (file_ops.sh:523) is what tells an \
             audit trail refused-by-policy from never-attempted: {text}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// The exit code is not visible through a stdout pipe, so the payload carries it. `ok` stays
    /// TRUE deliberately — see the comment at the envelope, and `UninstallGuard.readOutcome`, which
    /// requires it before it will decode the per-app account that is the whole point of the report.
    #[cfg(unix)]
    #[test]
    fn a_run_that_did_not_finish_says_so_in_the_payload_as_well_as_in_the_exit_code() {
        let home = fixture_dir("uninstall_failed_field");
        let mut row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != crate::uninstall::list::UNKNOWN_BUNDLE_ID)
            .expect("a row with a real bundle id");
        let bad = home.join("Applications").join("Bad\nFlag.app");
        fs::create_dir_all(bad.join("Contents/MacOS")).expect("fake bundle");
        fs::write(bad.join("Contents/MacOS/stub"), vec![b'x'; 128]).expect("fake binary");
        row.path = bad.to_string_lossy().to_string();
        let (out, code) = uninstall_resolved(
            &args(&[&row.bundle_id, "--apply", "--permanent"]),
            &[row.clone()],
            home.to_str().unwrap(),
        );
        assert_eq!(code, 1, "{out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        let data = parsed.get("data").cloned().expect("data");
        assert_eq!(
            data.get("failed").and_then(crate::json::Json::as_bool),
            Some(true),
            "a reader that cannot see the exit code has to be able to read it here: {out}"
        );
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(true),
            "and `ok` stays true — UninstallGuard.readOutcome requires it before it will decode \
             apps[], which is the only place the per-app reason exists: {out}"
        );

        // A clean run says the opposite.
        let ok_row = golden_inventory()
            .into_iter()
            .find(|r| r.bundle_id != crate::uninstall::list::UNKNOWN_BUNDLE_ID)
            .expect("a row with a real bundle id");
        let inv = scratch_inventory(&home, &[ok_row], 256);
        let (out, code) = uninstall_resolved(
            &args(&[&inv[0].bundle_id, "--apply", "--permanent"]),
            &inv,
            home.to_str().unwrap(),
        );
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            crate::json::Json::parse(&out)
                .expect("valid JSON")
                .get("data")
                .and_then(|d| d.get("failed"))
                .and_then(crate::json::Json::as_bool),
            Some(false),
            "{out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// The wall from [`default_uninstall_runner`], asserted rather than trusted. `uninstall_resolved`
    /// is the form that injects no fake, and the thing it used to inject really would have run
    /// `brew uninstall --cask --zap <token>` against the developer's machine.
    #[test]
    #[should_panic(expected = "REAL subprocess runner")]
    fn the_seam_that_injects_no_fake_cannot_shell_out_from_a_test() {
        default_uninstall_runner("brew", &["uninstall", "--cask", "--zap", "x"], TEN_SECONDS);
    }

    const TEN_SECONDS: std::time::Duration = std::time::Duration::from_secs(10);

    /// A protected system component is refused by name, before the inventory is consulted at all —
    /// `list::build_row` drops protected bundles, so resolving first would answer "no matching
    /// applications", which tells a caller the app is not installed rather than that the engine
    /// refuses to touch it.
    #[test]
    fn a_protected_component_is_refused_by_name_not_reported_as_missing() {
        let inv = golden_inventory();
        let home = fixture_dir("uninstall_protected");
        let argv = args(&["com.apple.finder", "--dry-run"]);
        let (out, code) = uninstall_resolved(&argv, &inv, home.to_str().unwrap());
        assert_eq!(code, 1, "{out}");
        assert!(
            out.contains("com.apple.finder is a protected system component"),
            "{out}"
        );
        assert!(
            !out.contains("No matching applications found"),
            "the refusal must not masquerade as 'not installed': {out}"
        );
        let _ = fs::remove_dir_all(&home);
    }

    // ---------------------------------------------------------------------------------------
    // `version`, and unknown flags
    // ---------------------------------------------------------------------------------------

    /// All three spellings the oracle accepts (`mole:1080`) now answer with a SUCCESS envelope and
    /// exit 0. They used to answer `unknown command` with exit 2, and `MoleCLI.version()` scraped a
    /// semver out of that failure.
    #[test]
    fn version_is_a_real_command_in_all_three_spellings() {
        for spelling in ["version", "--version", "-V"] {
            let (out, code) = dispatch(&args(&[spelling]));
            assert_eq!(code, 0, "{spelling} exits 0 like the oracle: {out}");
            assert!(out.contains("\"ok\":true"), "{spelling}: {out}");
            assert!(
                !out.contains("unknown command"),
                "{spelling} is not an unknown command: {out}"
            );
            let parsed = crate::json::Json::parse(&out).expect("parses");
            assert_eq!(
                parsed.get("command").and_then(|v| v.as_str()),
                Some("version")
            );
            assert_eq!(
                parsed
                    .get("data")
                    .and_then(|d| d.get("version"))
                    .and_then(|v| v.as_str()),
                Some(VERSION),
                "data.version is the field a consumer should READ instead of scraping: {out}"
            );
        }
    }

    /// The engine's version is its own 0.x line and must never be comparable with mo's. The app
    /// gates NDJSON streaming on `versionAtLeast(version(), "1.44.0")`; if this program ever
    /// reported a number that passed that gate while `status --watch` is still rejected, the app
    /// would ask for a stream nothing serves.
    #[test]
    fn the_engine_version_cannot_pass_an_mo_era_threshold() {
        let major: u32 = VERSION
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("version starts with a numeric major");
        assert!(
            major < 1,
            "engine {VERSION} would satisfy an mo 1.4x gate; keep the version below mo's \
             numbering until the whole mo surface is served"
        );
    }

    /// An unrecognised flag is an ERROR. Both halves of the oracle reject one — bash prints
    /// `Unknown uninstall option:` and exits 1, Go's `flag` package prints `flag provided but not
    /// defined` and exits 2 — and silently ignoring one is how `status --watch` came to accept a
    /// flag that changes the output contract and then emit a single non-streaming envelope.
    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        for (cmd, flag) in [
            ("status", "--watch-interval"),
            ("status", "--frobnicate"),
            ("clean", "--yolo"),
            ("history", "--watch"),
        ] {
            let (out, code) = dispatch(&args(&[cmd, flag]));
            assert_eq!(code, 2, "{cmd} {flag} must fail: {out}");
            assert!(out.contains("\"ok\":false"), "{cmd} {flag}: {out}");
            assert!(
                out.contains(flag),
                "the message must name the offending flag: {out}"
            );
        }
    }

    /// `status --watch`: every frame is the buffered `status` `data` object, one per line, at the
    /// injected cadence, and the loop stops at the frame bound — driven through a fake collector
    /// and a byte sink so no machine is sampled and no interval is waited out.
    #[test]
    fn status_watch_streams_the_buffered_data_object_once_per_tick() {
        use crate::status::snapshot::{to_json, Snapshot};
        let snap = crate::status::snapshot::Snapshot::sample_for_tests();
        let expected = to_json(&snap);
        let mut out: Vec<u8> = Vec::new();
        let slept = std::cell::RefCell::new(Vec::new());
        let ticks = std::cell::Cell::new(0u32);
        let code = status_watch_with(
            std::time::Duration::from_millis(250),
            Some(3),
            || {
                ticks.set(ticks.get() + 1);
                Snapshot::clone(&snap)
            },
            &mut out,
            |d| slept.borrow_mut().push(d),
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        for line in &lines {
            assert_eq!(*line, expected, "a frame IS the buffered data object");
            let parsed = crate::json::Json::parse(line).expect("each frame is one JSON object");
            assert!(parsed.get("health_score").is_some());
            assert!(parsed.get("cpu").is_some());
            assert!(parsed.get("ok").is_none(), "no envelope around a frame");
        }
        assert_eq!(ticks.get(), 3);
        assert_eq!(
            slept.borrow().as_slice(),
            [
                std::time::Duration::from_millis(250),
                std::time::Duration::from_millis(250)
            ],
            "sleeps BETWEEN frames only"
        );
        assert!(text.ends_with('\n'));
    }

    /// The reader going away is how a watch normally ends: a sink that refuses the write stops
    /// the loop with exit 0, without another collection or sleep.
    #[test]
    fn status_watch_stops_cleanly_when_stdout_closes() {
        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let ticks = std::cell::Cell::new(0u32);
        let code = status_watch_with(
            std::time::Duration::from_secs(2),
            None,
            || {
                ticks.set(ticks.get() + 1);
                crate::status::snapshot::Snapshot::sample_for_tests()
            },
            &mut Closed,
            |_| panic!("no sleep after the pipe closed"),
        );
        assert_eq!(code, 0);
        assert_eq!(ticks.get(), 1);
    }

    /// A tick with nothing measured is the one-shot's refusal, written as the line, exit 1.
    #[test]
    fn status_watch_refuses_like_the_one_shot_when_nothing_is_measured() {
        let mut out: Vec<u8> = Vec::new();
        let code = status_watch_with(
            std::time::Duration::from_secs(2),
            None,
            crate::status::snapshot::Snapshot::unmeasured_for_tests,
            &mut out,
            |_| panic!("no sleep after a refusal"),
        );
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"ok\":false"), "{text}");
        assert!(text.contains("\"kind\":\"unsupported\""), "{text}");
    }

    #[test]
    fn watch_interval_defaults_to_two_seconds_and_refuses_nonsense() {
        assert_eq!(
            watch_interval(&args(&["--watch"])).unwrap(),
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            watch_interval(&args(&["--watch", "--interval", "0.5"])).unwrap(),
            std::time::Duration::from_millis(500)
        );
        assert!(watch_interval(&args(&["--watch", "--interval"])).is_err());
        assert!(watch_interval(&args(&["--watch", "--interval", "0"])).is_err());
        assert!(watch_interval(&args(&["--watch", "--interval", "two"])).is_err());
        // The gate refuses a dash-shaped value before `watch_interval` ever sees it.
        let (out, code) = dispatch(&args(&["status", "--watch", "--interval", "-1"]));
        assert_eq!(code, 2, "{out}");
        // `--interval` without `--watch` names a cadence for a stream that is not running.
        let (out, code) = dispatch(&args(&["status", "--interval", "5"]));
        assert_eq!(code, 2, "{out}");
        assert!(out.contains("--watch"), "{out}");
        assert_eq!(frames_from_env(Some("3")), Some(3));
        assert_eq!(frames_from_env(Some(" 12 ")), Some(12));
        assert_eq!(frames_from_env(Some("0")), None);
        assert_eq!(frames_from_env(Some("lots")), None);
        assert_eq!(frames_from_env(None), None);
    }

    /// `analyze --progress` over a scratch tree: a `progress` line per top-level directory with
    /// running totals, then one `result` whose `data` is the buffered payload byte for byte.
    #[test]
    fn analyze_progress_streams_ticks_then_the_buffered_payload() {
        use crate::json::Json;
        let dir = fixture_dir("analyze_progress");
        fs::create_dir_all(dir.join("a/deep")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        fs::write(dir.join("a/one.bin"), vec![1u8; 4096]).unwrap();
        fs::write(dir.join("a/deep/two.bin"), vec![2u8; 4096]).unwrap();
        fs::write(dir.join("b/three.bin"), vec![3u8; 4096]).unwrap();
        fs::write(dir.join("top.bin"), vec![4u8; 4096]).unwrap();
        let path = dir.to_str().unwrap();

        let mut out: Vec<u8> = Vec::new();
        let code = analyze_progress_with(path, &mut out);
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<Json> = text
            .lines()
            .map(|l| Json::parse(l).expect("every line is one JSON object"))
            .collect();
        assert_eq!(lines.len(), 3, "{text}");
        let (ticks, last) = lines.split_at(2);
        let mut seen_paths = Vec::new();
        let mut prev_files = 0;
        for t in ticks {
            assert_eq!(t.get("type").and_then(Json::as_str), Some("progress"));
            let files = t.get("files").and_then(Json::as_i64).unwrap();
            assert!(files >= prev_files, "running totals never go down: {text}");
            prev_files = files;
            assert!(t.get("dirs").and_then(Json::as_i64).unwrap() >= 1);
            assert!(t.get("bytes").and_then(Json::as_i64).unwrap() > 0);
            seen_paths.push(t.get("path").and_then(Json::as_str).unwrap().to_string());
        }
        seen_paths.sort();
        assert_eq!(
            seen_paths,
            vec![
                dir.join("a").to_string_lossy().to_string(),
                dir.join("b").to_string_lossy().to_string()
            ]
        );
        // Running totals: the three files under `a/` and `b/`, plus `top.bin` if readdir handed
        // it out before the last directory (the order is the filesystem's, not ours).
        let final_tick = &ticks[1];
        let files = final_tick.get("files").and_then(Json::as_i64).unwrap();
        assert!((3..=4).contains(&files), "{text}");
        assert_eq!(final_tick.get("dirs").and_then(Json::as_i64), Some(3));

        let result = &last[0];
        assert_eq!(result.get("type").and_then(Json::as_str), Some("result"));
        let (buffered, code) = dispatch(&args(&["analyze", path]));
        assert_eq!(code, 0);
        let buffered = Json::parse(&buffered).unwrap();
        assert_eq!(
            result.get("data").map(Json::to_json_string),
            buffered.get("data").map(Json::to_json_string),
            "the result IS the buffered data"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn analyze_progress_on_a_missing_directory_ends_with_the_error_envelope() {
        let mut out: Vec<u8> = Vec::new();
        let code = analyze_progress_with("/nonexistent/burrow/analyze", &mut out);
        assert_eq!(code, 1);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"ok\":false"), "{text}");
    }

    /// A scratch directory for one test, removed and recreated so a previous run cannot leak into
    /// it. `tag` disambiguates concurrently-running tests, which share this process's pid.
    fn fixture_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("burrow_cli_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("fixture dir");
        dir
    }

    /// The app appends `--json` to EVERY capture: `BurrowConductor.argv(command:args:)` is
    /// `[command] + args + ["--json"]` (`Burrow-phaseb/macos/Sources/BurrowConductor.swift:63-66`),
    /// unconditional and always last. Tests that build argv by hand miss this, which is how five
    /// commands came to refuse the one flag the app always sends while 493 tests stayed green.
    fn as_the_app_sends_it(command: &str, argv: &[&str]) -> Vec<String> {
        let mut v = vec![command.to_string()];
        v.extend(argv.iter().map(|s| s.to_string()));
        v.push("--json".to_string());
        v
    }

    // ---------------------------------------------------------------------------------------
    // The flag table, re-derived from its SOURCES in both directions
    //
    // `allowed_flags` drifted from its callers three times because it was a hand-maintained list
    // with nothing checking it against anything. These four constants are the derivation, written
    // down once with file:line citations a reviewer can open, and the two tests below walk them
    // mechanically: a flag an oracle reads but this engine refuses fails one test, and a flag this
    // engine accepts that no oracle defines fails the other. Neither list can rot quietly.
    // ---------------------------------------------------------------------------------------

    /// Every flag the ORIGINAL's own argument parser reads, per command, transcribed arm by arm.
    /// Paths are relative to the two oracle checkouts, `burrow-engine/` and `burrow-cli/`.
    ///
    /// **bash** — the `case` arms ARE the contract, including the `-*)`/`*)` fallback that defines
    /// what is refused. Note the asymmetries, each of which is real and was checked by opening the
    /// file: optimize has `--dry-run` with NO `-n` (`:203`), and purge has `--help` with NO `-h`
    /// (`:315`).
    ///
    /// ```text
    /// clean      bin/clean.sh:1426-1451      --help -h --debug --dry-run -n --external <p> --whitelist
    /// optimize   bin/optimize.sh:196-207     --help -h --debug --dry-run    --whitelist
    /// uninstall  bin/uninstall.sh:1329-1346  --help -h --debug --dry-run -n --permanent --list
    /// purge      bin/purge.sh:310-326        --help    --debug --dry-run -n --paths --include-empty
    /// installer  bin/installer.sh:814-822    --help -h --debug --dry-run -n
    /// history    bin/history.sh:28-43        --help -h --json  --limit <n>
    /// ```
    ///
    /// `clean`'s `--select`/`--categories`/`--exclude` arm (`:1450`) is NOT listed: it matches and
    /// then exits 1 with "was removed in this release", so the original refuses them too and this
    /// engine refusing them is parity, not divergence. Same for `uninstall --whitelist` (`:1345`).
    ///
    /// **Go** — `flag.Bool`/`Float64`/`Duration` declarations; `bin/analyze.sh:11` and
    /// `bin/status.sh:11` are one-line `exec`s into these binaries.
    ///
    /// ```text
    /// analyze    cmd/analyze/main.go:20-21   --json --progress
    /// status     cmd/status/main.go:27-32    --json --proc-cpu-threshold <f> --proc-cpu-window <d>
    ///                                        --proc-cpu-alerts --watch --watch-interval <d>
    /// ```
    ///
    /// **burrow-cli** — the only oracle for the six commands bash never had. It is a FLOOR, not a
    /// ceiling: `run_net`/`run_photos`/… parse with `any(|a| a == "--x")` and have no `-*` arm at
    /// all, so they silently IGNORE anything unknown rather than refusing it. What is listed is
    /// what they read.
    ///
    /// ```text
    /// net        src/main.rs:505-507         --limit <n>
    /// orphans    src/main.rs:346-350         --installed <csv>
    /// photos     src/main.rs:581-587         --threshold <n>
    /// dupes      src/main.rs:202-203         --keep <dir> --apply
    /// evict      src/main.rs:793-794         --apply
    /// slim-check src/main.rs:399-401         (none — read-only. `--apply`/`--output` belong to the
    ///                                        separate `slim` command at :437-439, which this
    ///                                        engine does not serve.)
    /// ```
    const ORACLE_FLAGS: &[(&str, &[&str])] = &[
        ("analyze", &["--json", "--progress"]),
        (
            "status",
            &[
                "--json",
                "--watch",
                "--watch-interval",
                "--proc-cpu-threshold",
                "--proc-cpu-window",
                "--proc-cpu-alerts",
            ],
        ),
        (
            "clean",
            &[
                "--help",
                "-h",
                "--debug",
                "--dry-run",
                "-n",
                "--external",
                "--whitelist",
            ],
        ),
        (
            "optimize",
            &["--help", "-h", "--debug", "--dry-run", "--whitelist"],
        ),
        (
            "uninstall",
            &[
                "--help",
                "-h",
                "--debug",
                "--dry-run",
                "-n",
                "--permanent",
                "--list",
            ],
        ),
        (
            "purge",
            &[
                "--help",
                "--debug",
                "--dry-run",
                "-n",
                "--paths",
                "--include-empty",
            ],
        ),
        ("installer", &["--help", "-h", "--debug", "--dry-run", "-n"]),
        ("history", &["--help", "-h", "--json", "--limit"]),
        ("net", &["--limit"]),
        ("orphans", &["--installed"]),
        ("photos", &["--threshold"]),
        ("dupes", &["--keep", "--apply"]),
        ("evict", &["--apply"]),
        ("slim-check", &[]),
        // `rules` and `sentinel` are CONDUCTOR-NATIVE (burrow-cli's `engine_for` returns "native",
        // src/main.rs:968-977), so their oracle is burrow-cli's Rust, not a bash `case` arm:
        // `--app` is read at src/main.rs:294-298, and the sentinel three at :545-553.
        ("rules", &["--app"]),
        ("sentinel", &["--watch", "--interval-ms", "--max-ticks"]),
    ];

    /// The conductor's flag set, which burrow-cli strips before dispatch on EVERY command
    /// (`is_conductor_flag`, `burrow-cli/src/engine.rs:27-28`) — so the oracle takes all four
    /// anywhere. Kept separate from [`ORACLE_FLAGS`] because it is cross-cutting: listing it
    /// per-command is exactly the mistake that demoted `--json` to an opt-in for 3 of 14 commands.
    const ORACLE_GLOBAL_FLAGS: &[&str] = &["--apply", "--json", "--raw", "--stream"];

    /// Flags an oracle reads that this engine deliberately REFUSES, each with the reason it is
    /// refused rather than accepted-and-ignored. `"*"` means "on every command that does not list
    /// it in `allowed_flags`".
    ///
    /// The test below asserts each of these is REALLY refused, so this list cannot decay into a
    /// stale excuse for a flag that has since been quietly accepted.
    const REFUSED_ON_PURPOSE: &[(&str, &str, &str)] = &[
        ("*", "--raw",
         "asks for the payload WITHOUT the envelope (burrow-cli/src/main.rs:169 → emit_as at \
          :983-990). This engine has exactly one output mode, so it refuses rather than wrapping \
          the answer anyway and calling that success."),
        ("*", "--stream",
         "names a TRANSPORT the command does not implement: one NDJSON line per item instead of \
          one buffered envelope. Only clean, optimize and purge stream (the first two are what \
          BurrowConductor.streamableCommands lists, BurrowConductor.swift:159; purge joined for \
          the GUI's streamed purge, BUR-132)."),
        ("*", "--apply",
         "names a MUTATION the command does not have. Accepting it on a read-only command would \
          tell a caller a write was requested and honoured when nothing could ever be written."),
        ("*", "--help",
         "the oracle prints a per-command human table and exits 0 WITHOUT running the command \
          (bin/uninstall.sh:1329-1331). Listing it in allowed_flags would make it an accepted \
          no-op, so `clean --help` would run a real clean scan — worse than refusing. The two \
          halves of the oracle also disagree (bash exits 0, Go's flag package exits 2), so there \
          is no single original behaviour to port. See `help`."),
        ("*", "-h", "the short form of --help; same reasoning."),
        ("status", "--watch-interval",
         "the oracle's cadence flag takes a Go duration string (cmd/status/main.go:32: `2s`, \
          `500ms`). This engine paces --watch with `--interval <secs>` instead (a plain number, \
          see ENGINE_EXTENSIONS); accepting the oracle's spelling and parsing it differently \
          would silently change the cadence a caller asked for."),
        ("status", "--proc-cpu-threshold",
         "tunes the Go binary's persistent high-CPU alerting (cmd/status/main.go:28). No such \
          subsystem here, so the number would be read and discarded."),
        ("status", "--proc-cpu-window", "same alerting subsystem (cmd/status/main.go:29)."),
        ("status", "--proc-cpu-alerts",
         "defaults to TRUE in the original (cmd/status/main.go:30), so the only reason to pass it \
          is `--proc-cpu-alerts=false` to turn alerting OFF. Accepting and ignoring that would \
          leave a caller believing it had disabled something."),
        ("clean", "--external",
         "retargets the whole clean at another volume (bin/clean.sh:1437-1443). This engine scans \
          fixed roots, so accepting and ignoring it would clean the INTERNAL disk while the \
          caller asked for an external one — the most dangerous shape of a silent no-op here."),
        ("clean", "--whitelist",
         "short-circuits into an interactive whitelist manager and exits 0 without cleaning \
          (bin/clean.sh:1445-1449). This engine has no interactive mode; ignoring it would run \
          the clean the caller was trying to avoid."),
        ("optimize", "--whitelist", "same interactive manager (bin/optimize.sh:206-209)."),
        ("purge", "--paths",
         "same shape: an interactive purge-path manager that exits 0 without purging \
          (bin/purge.sh:310-314)."),
        ("purge", "--include-empty",
         "widens the scan to empty directories (bin/purge.sh:325). Not implemented here, and \
          ignoring it would report a narrower result as if it were the wider one."),
        ("sentinel", "--watch",
         "turns the one-shot scan into a poll-based daemon that streams one NDJSON `trashed_app` \
          event per newly-arrived bundle and loops forever by default \
          (burrow-cli/src/main.rs:540-575). Same disposition as `status --watch`: a flag that \
          replaces the output contract must not be accepted and ignored. Nothing sends it here — \
          MCP.swift:1283-1288 builds `sentinel [trashdir]` and the app has no other caller, and \
          burrow-cli's own watch consumer is a launchd template that runs the CONDUCTOR."),
        ("sentinel", "--interval-ms",
         "paces the --watch poll loop (main.rs:546-550); alone it would imply a cadence for a \
          stream this engine does not emit."),
        ("sentinel", "--max-ticks",
         "bounds the --watch loop for tests and cron (main.rs:551-553); meaningless without it."),
    ];

    /// Flags this engine accepts that no oracle defines FOR THAT COMMAND, and why each is a real
    /// capability rather than the drift these tests exist to catch.
    const ENGINE_EXTENSIONS: &[(&str, &str, &str)] = &[
        ("clean", "--permanent",
         "bash offers --permanent on uninstall only (bin/uninstall.sh:1339), but this engine reads \
          it for real on clean (cli.rs:77) to opt out of Trash routing. Dropping it would disable \
          implemented, safety-relevant behaviour rather than close a divergence."),
        ("purge", "--permanent", "same switch, read at cli.rs:523."),
        ("installer", "--permanent", "same switch, read at cli.rs:563."),
        ("clean", "--plan",
         "BUR-142: remove exactly the paths a reviewed dry run listed, without re-scanning \
          (`clean_from_plan`). The oracle has no such mode — it re-scans on every apply, which \
          is the defect the GUI's review screen needed closed."),
        ("purge", "--plan", "Apply only the artifact paths reviewed by Sweep, repeating scan policy without enumerating new candidates."),
        ("installer", "--plan", "Apply only the installer paths reviewed by Sweep, repeating classification and namespace checks."),
        ("status", "--interval",
         "the cadence of --watch in seconds (`status_watch`). The oracle spells it \
          --watch-interval with a Go duration string; the engine takes a number so the app and \
          the CLI can pass what their own settings hold without formatting a duration."),
    ];

    /// Whether `REFUSED_ON_PURPOSE` covers this (command, flag) pair. A `"*"` row means "wherever
    /// `allowed_flags` does not list it", so it can only ever explain a flag that IS refused; an
    /// exact-command row is a claim about that one command and is checked in both directions.
    fn refusal_reason(command: &str, flag: &str) -> Option<&'static str> {
        REFUSED_ON_PURPOSE
            .iter()
            .find(|(c, f, _)| *f == flag && (*c == command || *c == "*"))
            .map(|(_, _, why)| *why)
    }

    /// A refusal claimed for ONE named command, as opposed to the cross-cutting `"*"` rows.
    fn names_this_command(command: &str, flag: &str) -> bool {
        REFUSED_ON_PURPOSE
            .iter()
            .any(|(c, f, _)| *c == command && *f == flag)
    }

    /// Every flag an oracle reads must be ACCEPTED here, or listed in [`REFUSED_ON_PURPOSE`] with
    /// a reason — and then actually refused, so the excuse list cannot outlive the refusal.
    ///
    /// This is the direction that was broken: `bin/purge.sh:322` is `"--dry-run" | "-n")` and
    /// `bin/installer.sh:821` is the same arm, while `allowed_flags` listed neither. The decode
    /// gate found purge; nothing would have found installer, because judge.py drives bare
    /// `installer`.
    //
    // check_tests: no-golden — the oracle here is bash/Go SOURCE, not a captured artifact, so
    // there is no golden JSON to load. Every row cites the file and line of the `case` arm or
    // `flag.Bool` it was transcribed from; that citation is checkable by opening the file, which
    // is the honest form of provenance for a parser contract (RULEBOOK §3e).
    #[test]
    fn every_oracle_flag_is_accepted_or_refused_on_purpose() {
        let mut pairs: Vec<(&str, &str)> = Vec::new();
        for (command, flags) in ORACLE_FLAGS {
            pairs.extend(flags.iter().map(|f| (*command, *f)));
        }
        // The conductor set applies to every command, so it is walked against every command
        // rather than spot-checked — the shape of the --json outage.
        for command in COMMANDS {
            pairs.extend(ORACLE_GLOBAL_FLAGS.iter().map(|f| (*command, *f)));
        }

        for (command, flag) in pairs {
            if reject_unknown_flag(command, &args(&[flag])).is_none() {
                // Accepted. A cross-cutting `"*"` row says nothing about a command that DOES list
                // the flag, but a row naming this command is now a lie and has to go.
                assert!(
                    !names_this_command(command, flag),
                    "`{command} {flag}` is listed in REFUSED_ON_PURPOSE for {command} \
                     specifically, but it is now ACCEPTED. Drop the entry, or stop accepting it."
                );
                continue;
            }
            assert!(
                refusal_reason(command, flag).is_some(),
                "`{command} {flag}` is read by the ORIGINAL but refused here, and no reason is \
                 recorded. Either add it to `allowed_flags`, or add it to REFUSED_ON_PURPOSE \
                 saying which behaviour this engine does not have."
            );
            // The refusal has to be real and has to name the flag — `dispatch` refuses at the
            // gate before the command runs (cli.rs:29-31), so this costs nothing but the parse.
            let (out, code) = dispatch(&args(&[command, flag]));
            assert_eq!(code, 2, "`{command} {flag}` must be a usage failure: {out}");
            assert!(
                out.contains(flag),
                "the refusal must name the flag it refused: {out}"
            );
        }
    }

    /// The other direction: nothing is accepted here that no oracle defines. This is what catches
    /// a flag invented at the keyboard — `optimize -n` was accepted for exactly that reason, while
    /// `bin/optimize.sh:203` is `"--dry-run")` alone and `mo optimize -n` exits 1 on its `*)` arm.
    //
    // check_tests: no-golden — see the sibling test; the source of truth is the oracle's parser
    // source, cited per row in ORACLE_FLAGS, not a captured JSON document.
    #[test]
    fn no_flag_is_accepted_that_no_oracle_defines() {
        for command in COMMANDS {
            let oracle: &[&str] = ORACLE_FLAGS
                .iter()
                .find(|(c, _)| c == command)
                .map(|(_, f)| *f)
                .unwrap_or_else(|| panic!("{command} has no ORACLE_FLAGS row; add one"));

            for (flag, _) in GLOBAL_FLAGS.iter().chain(
                allowed_flags(command).unwrap_or_else(|| panic!("{command} is not dispatchable")),
            ) {
                let justified = oracle.contains(flag)
                    || ORACLE_GLOBAL_FLAGS.contains(flag)
                    || ENGINE_EXTENSIONS
                        .iter()
                        .any(|(c, f, _)| c == command && f == flag);
                assert!(
                    justified,
                    "`{command} {flag}` is accepted here but no oracle reads it on {command}. \
                     Either it was invented at the keyboard and should go, or it is a real engine \
                     capability and belongs in ENGINE_EXTENSIONS with the reason."
                );
            }
        }
    }

    /// The argv the APP actually sends, driven through the real `dispatch` with the global `--json`
    /// suffix the conductor appends — the two things the previous version of this test skipped, and
    /// each of them independently hid the outage it was supposed to catch.
    ///
    /// Every row cites the Swift call site it was transcribed from, so a reviewer can open the file
    /// and check the claim rather than trusting this list. The third field says whether the row is
    /// driven through the real `dispatch` or checked at the flag gate only, and each `false` has a
    /// reason:
    ///
    /// - **`--apply` rows** delete real files and open a `SessionLog` against the developer's own
    ///   history log (`cli.rs:143`, `:534`, `:572`). A unit test may not do that to prove a flag
    ///   parses, so they stop at the gate. This is the load-bearing exclusion.
    /// - **`clean`/`optimize`/`purge`/`installer` PREVIEWS** write nothing — each returns before
    ///   its `SessionLog::start` (`cli.rs:528-529`, `:566-568`) — but they walk the developer's
    ///   real `$HOME` and take multiple seconds with machine-dependent results, so they stop at the
    ///   gate for cost, not for safety.
    /// - **`net`, `status`, `dupes`** spawn external tools (`nettop`, the system probes, the
    ///   `fclones` sidecar) that may not exist on a build machine.
    ///
    /// The gate is where the flag table lives, so a missing flag fails these rows either way; what
    /// dispatch adds is everything downstream of parsing, which is how `dupes <path>` with no
    /// subcommand was caught.
    #[test]
    fn the_argv_the_app_sends_is_accepted_by_dispatch() {
        let dir = fixture_dir("appargv");
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        let path = dir.to_str().unwrap();

        // (command, args-before-the-global-suffix, dispatch-it?)  — Swift provenance beside each.
        let rows: Vec<(&str, Vec<&str>, bool)> = vec![
            ("analyze", vec![path], true), // DiskScanner.swift:115 (capture)
            ("analyze", vec!["--json", path], true), // DiskScanner.swift:98, MCP.swift:1052/1142
            ("orphans", vec![path], true), // OrphansView.swift:390
            (
                "orphans",
                vec![path, "--installed", "com.example.Kept"],
                true,
            ), // MCP.swift:1249-1254
            ("photos", vec![path], true),  // PhotosView.swift:423, MCP.swift:1263
            ("slim-check", vec!["/bin/ls"], true), // MCP.swift:1296
            ("net", vec![], false),        // NetView.swift:243, MCP.swift:598 (nettop)
            ("history", vec![], true),     // MoleHistory.swift:56/61
            ("history", vec!["--json", "--limit", "20"], true), // MCP.swift:866
            ("status", vec![], false),     // SnapshotProducer.swift:488/494
            (
                "uninstall",
                vec!["--dry-run", "com.example.NotInstalled"],
                true,
            ), // SoftwareView.swift:755, :761
            ("uninstall", vec!["--list"], true), // MoleClient.swift:37, MCP.swift:1165
            (
                "uninstall",
                vec!["--permanent", "App One", "--apply"],
                false,
            ), // MoActions.swift:73
            ("clean", vec![], false),      // MoActions.swift:68 preview, via engineArgv
            ("clean", vec!["--apply", "--stream"], false), // CleanView.swift:278/314, TuneUpView.swift:421
            ("clean", vec!["--stream"], false),            // CleanView.swift:416 via streamOverride
            ("optimize", vec![], false), // MoActions.swift:70 preview, via engineArgv
            ("optimize", vec!["--apply", "--stream"], false), // OptimizeView.swift:172, TuneUpView.swift:425
            ("optimize", vec!["--stream"], false), // OptimizeView.swift:179 via streamOverride
            ("purge", vec!["--apply"], false),     // MoActions.swift:75 real
            ("installer", vec!["--apply"], false), // MoActions.swift:77 real
            // The UNTRANSLATED paths. `BurrowConductor.engineArgv` (BurrowConductor.swift:174-175)
            // strips `--dry-run` before the engine ever sees it, which is why these stayed hidden
            // — but `MoEngine.capture` passes `command.args` verbatim (MoEngine.swift:168-175) and
            // four call sites reach it with mo-style argv that still carries the flag. They land
            // on the SAME bundled engine (MoleCLI.discover → bundledExecutable, :85-92).
            ("clean", vec!["--dry-run"], false), // TuneUpModel.swift:151, CleanView.swift:416
            ("optimize", vec!["--dry-run"], false), // TuneUpModel.swift:160, OptimizeView.swift:179
            ("purge", vec!["--dry-run"], false), // MoActions.swift:75 preview (mo-style)
            ("installer", vec!["--dry-run"], false), // MoActions.swift:77 preview (mo-style)
            ("dupes", vec!["group", path], false), // DupesView.swift:544 (spawns fclones)
            ("dupes", vec!["dedupe", path], false), // DupesView.swift:587
            ("dupes", vec!["dedupe", path, "--apply"], false), // DupesView.swift:617
            ("dupes", vec![path], false),        // MCP.swift:1239 — no subcommand
            // The two MCP tools that were ADVERTISED and answered `unknown command` until the
            // commands landed. Both are read-only and cheap enough to drive for real: `rules`
            // reads the fixture dir (which holds no *.json, so an empty items list), and
            // `sentinel` is one read_dir. The bare `sentinel` row is the app's real default —
            // MCP.swift:1285-1287 sends no positional when `trashdir` is absent, so the engine
            // scans $HOME/.Trash; it is listed here BECAUSE that default is the argv the app
            // sends, and reading a directory listing is not a side effect.
            ("rules", vec!["dryrun", path], true), // MCP.swift:1278
            (
                "rules",
                vec!["dryrun", path, "--app", "com.example.App"],
                true,
            ), // MCP.swift:1279-1281 — dir FIRST, then the flag
            ("sentinel", vec![], true),            // MCP.swift:1285-1287, no trashdir
            ("sentinel", vec![path], true),        // MCP.swift:1285-1287, trashdir given
        ];

        for (command, argv, dispatchable) in rows {
            let full = as_the_app_sends_it(command, &argv);
            let joined = full.join(" ");
            assert!(
                reject_unknown_flag(command, &full[1..]).is_none(),
                "`{joined}` is sent by the app and must not be rejected at the flag gate"
            );
            if !dispatchable {
                continue;
            }
            let (out, code) = dispatch(&full);
            assert!(
                !out.contains(&format!("unknown {command} option")),
                "`{joined}` came back as an unknown-option failure: {out}"
            );
            assert!(
                !out.contains("unknown command"),
                "`{joined}` came back as an unknown command: {out}"
            );
            assert_ne!(code, 2, "`{joined}` must not be a usage failure: {out}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// `--json` is GLOBAL, not a per-command opt-in. Walking every command rather than a
    /// hand-picked few is the point: the outage this replaces was an enumeration that listed
    /// `--json` for three of fourteen commands, and any list short enough to type is short enough
    /// to get wrong the same way.
    #[test]
    fn every_command_accepts_the_global_json_flag() {
        for command in COMMANDS {
            assert!(
                reject_unknown_flag(command, &args(&["--json"])).is_none(),
                "the app appends --json to every capture; `{command} --json` must be accepted"
            );
        }
    }

    /// `--raw` asks for the payload WITHOUT the envelope, which this engine cannot produce. It is
    /// refused rather than accepted-and-ignored — the `status --watch` rule — so a caller learns
    /// its request was not honoured instead of parsing an envelope it did not ask for.
    #[test]
    fn raw_is_refused_because_the_engine_has_only_one_output_mode() {
        for command in ["photos", "net", "orphans", "analyze"] {
            let (out, code) = dispatch(&args(&[command, "--raw"]));
            assert_eq!(code, 2, "{command} --raw must fail: {out}");
            assert!(
                out.contains("--raw"),
                "the message must name the flag: {out}"
            );
        }
    }

    /// A value that follows a flag is an ordinary token, not a flag — `--limit 20` must not read
    /// `20` as an unknown option.
    #[test]
    fn flag_values_and_positionals_are_not_mistaken_for_flags() {
        assert!(reject_unknown_flag("net", &args(&["--limit", "15"])).is_none());
        assert!(reject_unknown_flag("photos", &args(&["/tmp", "--threshold", "8"])).is_none());
        assert!(reject_unknown_flag("slim-check", &args(&["/bin/ls"])).is_none());
    }

    // ---------------------------------------------------------------------------------------
    // A flag's VALUE is never the positional
    // ---------------------------------------------------------------------------------------

    /// `photos --threshold 8 <dir>` must scan `<dir>`, not a directory named `8`.
    ///
    /// Graded on a REAL fixture rather than on the echoed `dir` string, because the string is the
    /// symptom and the wrong scan is the defect: two `.heic` files are planted, so
    /// `skipped_unsupported` is 2 when the scan landed on the fixture and 0 when it landed
    /// anywhere else. Asserting only `data.dir` would still pass if the path were echoed correctly
    /// and the scan ran elsewhere.
    #[test]
    fn photos_scans_the_positional_not_the_threshold_value() {
        let dir = fixture_dir("photos_pos");
        fs::write(dir.join("one.heic"), b"not really an image").unwrap();
        fs::write(dir.join("two.heic"), b"nor is this").unwrap();
        let path = dir.to_str().unwrap();

        let (out, code) = dispatch(&args(&["photos", "--threshold", "8", path, "--json"]));
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("success envelope carries data");

        assert_eq!(
            data.get("dir").and_then(crate::json::Json::as_str),
            Some(path),
            "the positional is the scan directory; `8` is the threshold's value: {out}"
        );
        assert_eq!(
            data.get("threshold").and_then(crate::json::Json::as_i64),
            Some(8),
            "the flag still has to take effect: {out}"
        );
        assert_eq!(
            data.get("skipped_unsupported")
                .and_then(crate::json::Json::as_i64),
            Some(2),
            "the scan must have really walked the fixture, not just echoed its name: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `orphans --installed <csv> <dir>` must scan `<dir>`, not a directory named after the csv.
    ///
    /// The planted leftover has to come back for this to pass, so a scan of the wrong path fails
    /// on an empty `orphans` list rather than on a string comparison. `installed_count` is checked
    /// too: the flag's value must still reach the inventory it names.
    #[test]
    fn orphans_scans_the_positional_not_the_installed_value() {
        let dir = fixture_dir("orphans_pos");
        fs::write(dir.join("com.deadvendor.oldapp.savedState"), "x").unwrap();
        let path = dir.to_str().unwrap();

        let (out, code) = dispatch(&args(&[
            "orphans",
            "--installed",
            "com.example.Kept,com.example.Other",
            path,
            "--json",
        ]));
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("success envelope carries data");

        let roots: Vec<&str> = data
            .get("roots")
            .and_then(crate::json::Json::as_array)
            .expect("data.roots")
            .iter()
            .filter_map(crate::json::Json::as_str)
            .collect();
        assert_eq!(
            roots,
            vec![path],
            "the positional is the scan root, not the --installed csv: {out}"
        );
        assert_eq!(
            data.get("installed_count")
                .and_then(crate::json::Json::as_i64),
            Some(2),
            "the csv must still reach the inventory it names: {out}"
        );
        let names: Vec<&str> = data
            .get("orphans")
            .and_then(crate::json::Json::as_array)
            .expect("data.orphans")
            .iter()
            .filter_map(|h| h.get("name").and_then(crate::json::Json::as_str))
            .collect();
        assert!(
            names.contains(&"com.deadvendor.oldapp.savedState"),
            "the planted leftover proves the fixture was really scanned: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The three commands whose positional was reachable past a SWITCH flag. `-n` is the sharp one:
    /// it does not start with `--`, so the old `find(|a| !a.starts_with("--"))` returned `-n`
    /// itself and `uninstall -n com.example.App` dry-ran a bundle id of `-n` and reported success.
    #[test]
    fn a_switch_flag_before_the_positional_is_not_the_positional() {
        let dir = fixture_dir("switch_pos");
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        let path = dir.to_str().unwrap();

        let (out, code) = dispatch(&args(&["analyze", "--json", path]));
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("path").and_then(crate::json::Json::as_str),
            Some(path),
            "{out}"
        );
        assert_eq!(
            data.get("total_files").and_then(crate::json::Json::as_i64),
            Some(1),
            "the fixture's one file proves the scan hit the fixture: {out}"
        );

        // `uninstall` now resolves its positionals against the installed inventory, so the old
        // "dry-runs a made-up bundle id and reports success" assertion no longer describes correct
        // behaviour — that IS the bug fixed alongside this one. A PROTECTED bundle id proves the
        // same property more sharply and without a `/Applications` scan: it is refused by name
        // before the inventory is ever touched, and `-n` is not protected, so if the old
        // `find(|a| !a.starts_with("--"))` idiom came back this would not be the message.
        let (out, code) = dispatch(&args(&["uninstall", "-n", "com.apple.finder"]));
        assert_eq!(code, 1, "a protected component is refused: {out}");
        assert!(
            out.contains("com.apple.finder is a protected system component"),
            "`-n` is uninstall's dry-run switch, never the app it uninstalls: {out}"
        );
        assert!(
            !out.contains("\"-n\""),
            "the switch must never be reported as the app: {out}"
        );

        // A fat Mach-O this test BUILDS, where `/bin/ls` used to play the part. The property here
        // is pure argv handling and holds on every platform, but `/bin/ls` is a fat Mach-O only on
        // macOS: on Linux it is an ELF and comes back "not a fat Mach-O (thin binary or
        // non-Mach-O)", on Windows it does not exist at all and comes back "cannot read /bin/ls",
        // so the VEHICLE failed on two platforms where the property itself was fine.
        // `macho::parse_fat` is pure big-endian byte reading with no OS call in it, so these bytes
        // parse identically everywhere, and the assertions stay a real read of a real file — a
        // wrong positional (`--json`) cannot produce arch slices, so this still fails as a bad
        // read rather than as a string mismatch. That a GENUINE system binary parses is a
        // different fact, kept by `slim_check_reads_a_real_system_fat_binary`.
        let mut fat = Vec::new();
        fat.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // FAT_MAGIC — 32-bit fat
        fat.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch
        for (i, (cputype, size)) in [
            (crate::macho::CPU_ARM64, 5000u32),
            (crate::macho::CPU_X86_64, 3000u32),
        ]
        .into_iter()
        .enumerate()
        {
            fat.extend_from_slice(&(cputype as u32).to_be_bytes());
            fat.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            fat.extend_from_slice(&(0x1000u32 * (i as u32 + 1)).to_be_bytes()); // offset
            fat.extend_from_slice(&size.to_be_bytes());
            fat.extend_from_slice(&14u32.to_be_bytes()); // align
        }
        let fat_file = dir.join("universal.bin");
        fs::write(&fat_file, &fat).unwrap();
        let fat_path = fat_file.to_str().unwrap();

        let (out, code) = dispatch(&args(&["slim-check", "--json", fat_path]));
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("path").and_then(crate::json::Json::as_str),
            Some(fat_path),
            "{out}"
        );
        // Both slices, at the sizes this fixture planted — a sharper check than the old `>= 1`,
        // and unreachable unless the positional resolved past `--json` to this exact file.
        assert_eq!(
            data.get("arch_count").and_then(crate::json::Json::as_i64),
            Some(2),
            "the planted fat header was really parsed: {out}"
        );
        let sizes: Vec<i64> = data
            .get("slices")
            .and_then(crate::json::Json::as_array)
            .expect("data.slices")
            .iter()
            .filter_map(|s| s.get("size").and_then(crate::json::Json::as_i64))
            .collect();
        assert_eq!(
            sizes,
            vec![5000, 3000],
            "the slice sizes are this fixture's own: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The fact the argv test above used to carry as a side effect, kept as a test of its own:
    /// a REAL system universal binary parses end to end. `/bin/ls` is fat (arm64 + x86_64) on
    /// every supported macOS, and no synthetic header can prove that the layout Apple actually
    /// ships still matches what `parse_fat` expects — which is the only thing this adds over the
    /// hand-built fixture, and the reason it is worth a macOS-gated test rather than deletion.
    #[cfg(target_os = "macos")]
    #[test]
    fn slim_check_reads_a_real_system_fat_binary() {
        let (out, code) = dispatch(&args(&["slim-check", "--json", "/bin/ls"]));
        assert_eq!(code, 0, "{out}");
        let data = crate::json::Json::parse(&out)
            .expect("valid JSON")
            .get("data")
            .cloned()
            .expect("data");
        assert_eq!(
            data.get("path").and_then(crate::json::Json::as_str),
            Some("/bin/ls"),
            "{out}"
        );
        assert!(
            data.get("arch_count")
                .and_then(crate::json::Json::as_i64)
                .is_some_and(|n| n >= 1),
            "a real Mach-O was really parsed: {out}"
        );
    }

    /// The walk itself, at the unit level: values are consumed, switches are not, and the order of
    /// flags and positionals does not matter. `uninstall` legitimately has more than one positional
    /// (`MoActions.swift:72-73` splats a multi-select of app names into one argv), so the walk
    /// returns all of them even though `fn uninstall` currently acts on the first.
    #[test]
    fn positionals_skips_flag_values_in_any_order() {
        assert_eq!(
            positionals("photos", &args(&["--threshold", "8", "/fix", "--json"])),
            vec!["/fix"]
        );
        assert_eq!(
            positionals("photos", &args(&["/fix", "--threshold", "8"])),
            vec!["/fix"]
        );
        assert_eq!(
            positionals("orphans", &args(&["--installed", "a,b", "/fix"])),
            vec!["/fix"]
        );
        assert_eq!(
            positionals("net", &args(&["--limit", "15"])),
            Vec::<&str>::new()
        );
        assert_eq!(
            positionals("history", &args(&["--json", "--limit", "20"])),
            Vec::<&str>::new(),
            "history takes no positional; `20` belongs to --limit"
        );
        assert_eq!(
            positionals("uninstall", &args(&["-n", "App One", "App Two", "--apply"])),
            vec!["App One", "App Two"]
        );
        assert_eq!(
            positionals("dupes", &args(&["group", "--keep", "/ref", "/scan"])),
            vec!["group", "/scan"]
        );
    }

    // ---------------------------------------------------------------------------------------
    // `help`, and the version string the app actually reads
    // ---------------------------------------------------------------------------------------

    /// `mole:1076-1079` takes all three spellings and exits 0. The list is derived from the flag
    /// table, so it cannot drift from what `dispatch` really accepts.
    #[test]
    fn help_is_a_real_command_in_all_three_spellings() {
        for spelling in ["help", "--help", "-h"] {
            let (out, code) = dispatch(&args(&[spelling]));
            assert_eq!(code, 0, "`{spelling}` exits 0 like the original: {out}");
            let parsed = crate::json::Json::parse(&out).expect("valid JSON");
            assert_eq!(
                parsed.get("ok").and_then(crate::json::Json::as_bool),
                Some(true),
                "{out}"
            );
            let listed: Vec<&str> = parsed
                .get("data")
                .and_then(|d| d.get("commands"))
                .and_then(crate::json::Json::as_array)
                .expect("data.commands")
                .iter()
                .filter_map(|c| c.get("command").and_then(crate::json::Json::as_str))
                .collect();
            for command in COMMANDS {
                assert!(
                    listed.contains(command),
                    "`{command}` missing from help: {out}"
                );
            }
        }
    }

    /// `MoleCLI.parseVersion` (`Burrow-phaseb/macos/Sources/MoleCLI.swift:166-174`), ported
    /// character-for-character: split the WHOLE stdout on every character that is not a digit or a
    /// dot, and take the first token with two or more all-numeric parts.
    fn scrape_version_like_the_app(output: &str) -> Option<String> {
        for token in output.split(|c: char| !(c.is_numeric() || c == '.')) {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() >= 2 && parts.iter().all(|p| p.parse::<i64>().is_ok()) {
                return Some(token.to_string());
            }
        }
        None
    }

    /// The app never reads `data.version`; it scrapes the whole stdout and compares the result
    /// against `minimumWatchVersion = "1.44.0"` (`MoleCLI.swift:184-191`). So the guarantee that
    /// matters is about STDOUT, not about a field — and
    /// `the_engine_version_cannot_pass_an_mo_era_threshold` cannot see it, because it grades
    /// `data.version`.
    ///
    /// This runs the real command through the real scraper. It went red on the payload that
    /// carried `os_version` and `kernel` only if the envelope's field order changed; asserting
    /// that NO token in the output can pass the gate makes the ordering irrelevant.
    #[test]
    fn the_version_the_app_scrapes_stays_below_the_streaming_gate() {
        for spelling in ["version", "--version", "-V"] {
            let (out, code) = dispatch(&args(&[spelling]));
            assert_eq!(code, 0, "{out}");
            let scraped =
                scrape_version_like_the_app(&out).expect("the app must find SOME version token");
            assert_eq!(
                scraped, VERSION,
                "the first scrapeable token must be the engine's own version: {out}"
            );

            // Nothing anywhere in the output may pass the 1.44.0 streaming gate — not just the
            // first token. `os_version` (26.5.2) and `kernel` (25.5.0) both did.
            for token in out.split(|c: char| !(c.is_numeric() || c == '.')) {
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() < 2 || !parts.iter().all(|p| p.parse::<i64>().is_ok()) {
                    continue;
                }
                let major: i64 = parts[0].parse().unwrap();
                let minor: i64 = parts[1].parse().unwrap();
                assert!(
                    major < 1 || (major == 1 && minor < 44),
                    "`{token}` in `{spelling}` output would flip supportsWatch() to true and have \
                     the app wait on an NDJSON stream this engine refuses to serve: {out}"
                );
            }
        }
    }

    /// `dupes` without a subcommand means `group`, exactly as `run_dupes` resolves it
    /// (`burrow-cli/src/main.rs:205-208`). `MCP.swift:1239` sends `["dupes", <path>, "--json"]`,
    /// so requiring the subcommand made `burrow_dupes` fail for every agent call.
    ///
    /// Asserted as "not a usage failure" rather than "ok:true": whether fclones resolves is an
    /// environment fact (`BURROW_FCLONES`, a sidecar next to the binary), and a missing sidecar is
    /// a legitimate different error. The regression being guarded is the argv one.
    #[test]
    fn dupes_without_a_subcommand_means_group() {
        let dir = fixture_dir("dupes_sub");
        fs::write(dir.join("a.txt"), b"same bytes").unwrap();
        fs::write(dir.join("b.txt"), b"same bytes").unwrap();
        let path = dir.to_str().unwrap();

        let (out, _) = dispatch(&args(&["dupes", path, "--json"]));
        assert!(
            !out.contains("unknown subcommand") && !out.contains("needs a subcommand"),
            "a bare path is the `group` form, not a bad subcommand: {out}"
        );
        assert!(
            !out.contains("needs at least one path"),
            "the path must not have been eaten as the subcommand: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------------------
    // Three commands that answered confidently about a platform they cannot serve
    // ---------------------------------------------------------------------------------------

    /// Read a failure envelope's `error.kind` and top-level `feature`, or panic saying what it got
    /// instead. Shared by the three refusal tests below so each asserts the same envelope shape a
    /// GUI actually branches on rather than substring-matching the JSON text.
    fn refusal_of(out: &str) -> (String, String) {
        let parsed = crate::json::Json::parse(out)
            .unwrap_or_else(|e| panic!("a refusal must still be valid JSON ({e}): {out}"));
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false),
            "a refusal must be top-level ok:false — that is the field a caller branches on before \
             it decodes anything: {out}"
        );
        let kind = parsed
            .get("error")
            .and_then(|e| e.get("kind"))
            .and_then(crate::json::Json::as_str)
            .unwrap_or_else(|| panic!("a refusal carries error.kind: {out}"))
            .to_string();
        let feature = parsed
            .get("feature")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_else(|| panic!("an unsupported refusal names the feature: {out}"))
            .to_string();
        (kind, feature)
    }

    /// `sentinel` used to report an empty Trash on a platform whose trash it had never looked at:
    /// it built `<home>/.Trash`, `scan_trash` swallowed the failed `read_dir` by design, and the
    /// answer came back `ok:true, count:0` — indistinguishable from a Mac with a genuinely empty
    /// Trash.
    ///
    /// The gate is on the INFERENCE, not the command, and both halves are pinned here because
    /// over-refusing is the easier mistake: `sentinel <dir>` is a `read_dir` and a suffix test,
    /// which every platform can do, and burrow-cli's own docs record it as working on Windows.
    /// The explicit half runs the real dispatch over a rebuild of the golden's own fixture on
    /// EVERY host and requires the golden's `count` back (RULEBOOK §3e — the expected value is
    /// read out of `sentinel.golden.json` at run time, never transcribed).
    #[test]
    fn the_sentinel_default_trash_is_refused_off_macos_but_an_explicit_directory_is_not() {
        let golden = crate::json::Json::parse(include_str!("sentinel/sentinel.golden.json"))
            .expect("vendored golden must parse");
        let rows = golden
            .get("trashed_apps")
            .and_then(crate::json::Json::as_array)
            .expect("golden.trashed_apps");
        assert!(
            !rows.is_empty(),
            "an empty golden spine would make the explicit half vacuous (RULEBOOK §3b)"
        );

        // Rebuild the capture's fixture: "Zeta.app" is a FILE there, which is the entry a
        // "sensible" is_dir() filter would drop, so it has to stay a file here too.
        let dir = fixture_dir("sentinel_explicit");
        for row in rows {
            let name = row
                .get("name")
                .and_then(crate::json::Json::as_str)
                .expect("row name");
            let leaf = std::path::Path::new(
                row.get("path")
                    .and_then(crate::json::Json::as_str)
                    .expect("row path"),
            )
            .file_name()
            .expect("row path leaf")
            .to_owned();
            if name == "Zeta" {
                fs::write(dir.join(&leaf), b"a file whose name ends in .app\n").unwrap();
            } else {
                fs::create_dir_all(dir.join(&leaf)).unwrap();
            }
        }
        fs::create_dir_all(dir.join("NotAnApp")).unwrap();
        fs::write(dir.join("notes.txt"), b"plain file\n").unwrap();

        let (out, code) = dispatch(&args(&["sentinel", dir.to_str().unwrap()]));
        assert_eq!(code, 0, "an explicit directory is served everywhere: {out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(true),
            "the scan needs no platform vocabulary — refusing it would cost Windows and Linux a \
             command that works: {out}"
        );
        assert_eq!(
            parsed
                .get("data")
                .and_then(|d| d.get("count"))
                .and_then(crate::json::Json::as_u64),
            golden.get("count").and_then(crate::json::Json::as_u64),
            "the golden's own fixture must reproduce the golden's count on any host: {out}"
        );
        let _ = fs::remove_dir_all(&dir);

        // The inferred half. On macOS `<home>/.Trash` is real, so the answer stays a successful
        // (read-only) scan of it; anywhere else the command must say it cannot look rather than
        // report that it looked and found nothing.
        let (out, code) = dispatch(&args(&["sentinel"]));
        if crate::sentinel::default_trash_refusal(std::env::consts::OS).is_some() {
            assert_ne!(code, 0, "a refusal's exit code must agree with it: {out}");
            let (kind, feature) = refusal_of(&out);
            assert_eq!(kind, "unsupported", "{out}");
            assert_eq!(
                feature,
                crate::sentinel::DEFAULT_TRASH_FEATURE,
                "the feature names the inference, so a caller learns `sentinel <dir>` still works"
            );
        } else {
            assert_eq!(code, 0, "macOS keeps the default scan: {out}");
            let parsed = crate::json::Json::parse(&out).expect("valid JSON");
            assert_eq!(
                parsed.get("ok").and_then(crate::json::Json::as_bool),
                Some(true),
                "{out}"
            );
            let trash = parsed
                .get("data")
                .and_then(|d| d.get("trash"))
                .and_then(crate::json::Json::as_str)
                .expect("the default scan echoes the directory it chose");
            assert!(
                trash.ends_with("/.Trash"),
                "the inference is still `<home>/.Trash` on the platform that has one: {trash}"
            );
        }
    }

    /// `evict`'s dry run answered `ok:true` while marking every item `supported:false`. The
    /// per-item flag was honest and unreachable: a GUI or agent branches on the top-level `ok`
    /// before it decodes `data`, so a refusal shaped like a preview was consumed as a preview —
    /// and then `--apply`, which already errored off macOS, contradicted it.
    ///
    /// The ordering half matters as much as the refusal and runs on every host: a missing path is
    /// still a MALFORMED ARGV, not a platform problem, because `evict.golden.provenance.txt`
    /// records that exact error as the oracle's answer and says an engine accepting the no-arg
    /// form has diverged.
    #[test]
    fn the_evict_preview_refuses_off_macos_instead_of_previewing_a_refusal() {
        let (out, code) = dispatch(&args(&["evict"]));
        assert_eq!(code, 2, "malformed argv keeps its own exit code: {out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(crate::json::Json::as_str),
            Some("evict: needs at least one path"),
            "argv is checked before the platform is, on every platform — the capture pins this \
             message and a platform refusal here would replace it: {out}"
        );

        let dir = fixture_dir("evict_platform");
        let file = dir.join("cloudish.bin");
        fs::write(&file, b"an ordinary local file\n").unwrap();
        let (out, code) = dispatch(&args(&["evict", file.to_str().unwrap()]));
        if crate::evict::platform_refusal(std::env::consts::OS).is_some() {
            assert_ne!(code, 0, "a refusal's exit code must agree with it: {out}");
            let (kind, feature) = refusal_of(&out);
            assert_eq!(kind, "unsupported", "{out}");
            assert_eq!(feature, crate::evict::EVICT_FEATURE, "{out}");
            assert!(
                !out.contains("would_evict"),
                "the refusal must not still carry a preview body — that shape is exactly what a \
                 caller mistook for a successful preview: {out}"
            );
        } else {
            assert_eq!(code, 0, "macOS previews for real: {out}");
            let parsed = crate::json::Json::parse(&out).expect("valid JSON");
            let row = parsed
                .get("data")
                .and_then(|d| d.get("would_evict"))
                .and_then(crate::json::Json::as_array)
                .and_then(|a| a.first())
                .expect("the preview reports the path it was handed");
            assert_eq!(
                row.get("supported").and_then(crate::json::Json::as_bool),
                Some(true),
                "on macOS the preview is a real preview, and `ok:true` means it: {out}"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// THE GUARD THAT WAS LOST. burrow-cli refused `dupes dedupe|remove|link --apply` on Windows
    /// outright (`src/main.rs:161-169` at `3633c19^`, deleted there) and its README turned that into a
    /// promise — "Burrow does not delete duplicate files on Windows". Nothing in this crate
    /// replaced it, and `resolve_fclones` supports `.exe` off `PATH` on purpose, so the argv
    /// reached fclones and deleted.
    ///
    /// Both directions are asserted because the guard's value is entirely in being narrow: it must
    /// refuse the MUTATION and leave discovery alone, since read-only `dupes group` genuinely
    /// works on Windows and is what every agent call sends.
    ///
    /// The `--apply` dispatch below is run against an EMPTY directory on purpose. On the platforms
    /// where the guard is correctly silent this really does execute, and an empty directory has no
    /// duplicate groups, so `execute` returns `NOTHING_ACTIONABLE` before any fclones action runs.
    /// Keep it empty.
    #[test]
    fn the_dupes_apply_guard_refuses_the_mutation_before_it_resolves_an_engine() {
        let dir = fixture_dir("dupes_apply_guard");
        let (out, code) = dispatch(&args(&[
            "dupes",
            "dedupe",
            dir.to_str().unwrap(),
            "--apply",
        ]));
        if crate::dupes::apply_refusal(std::env::consts::OS).is_some() {
            assert_ne!(code, 0, "a refusal's exit code must agree with it: {out}");
            let (kind, feature) = refusal_of(&out);
            assert_eq!(kind, "unsupported", "{out}");
            assert_eq!(
                feature,
                crate::dupes::APPLY_FEATURE,
                "burrow-cli's own feature name, so the envelope is the one callers already know"
            );
            assert!(
                out.contains("read-only"),
                "the detail is the oracle's verbatim wording: {out}"
            );
            assert!(
                !out.contains("fclones not found"),
                "the guard sits ABOVE resolve_fclones — if this is what came back, a machine with \
                 a real fclones.exe would have gone straight through it: {out}"
            );
        } else {
            let feature = crate::json::Json::parse(&out).ok().and_then(|p| {
                p.get("feature")
                    .and_then(crate::json::Json::as_str)
                    .map(str::to_string)
            });
            assert_ne!(
                feature.as_deref(),
                Some(crate::dupes::APPLY_FEATURE),
                "the oracle refused Windows and nothing else; over-refusing here would take away \
                 the APFS clone-dedupe that is the command's whole point on macOS: {out}"
            );
        }

        // Discovery is untouched on every platform — the half that keeps this a narrow guard.
        fs::write(dir.join("a.txt"), b"same bytes").unwrap();
        fs::write(dir.join("b.txt"), b"same bytes").unwrap();
        let (out, _) = dispatch(&args(&["dupes", "group", dir.to_str().unwrap()]));
        assert!(
            !out.contains(crate::dupes::APPLY_FEATURE),
            "`dupes group` is read-only and must never be refused as a duplicate MUTATION: {out}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------------------------
    // A command with no home directory must refuse, not report an empty success
    // ---------------------------------------------------------------------------------------

    /// Set on a re-executed copy of this test binary by
    /// [`the_home_dependent_commands_refuse_instead_of_reporting_an_empty_success`].
    const NO_HOME_CHILD: &str = "BURROW_ENGINE_NO_HOME_CHILD";

    /// The child half of the no-home reproduction: dispatches whatever command the parent named,
    /// with neither `HOME` nor `USERPROFILE` in the environment, and prints the result.
    ///
    /// A child for the same reason the `status` reproduction uses one — the condition under test is
    /// the absence of an environment variable, and `remove_var` is process-wide. Several modules in
    /// this crate resolve `~` from their own tests, and `io_rate`'s doc comment records that
    /// mutating the environment mid-suite races them.
    #[test]
    fn no_home_dispatch_child() {
        let Ok(command) = std::env::var(NO_HOME_CHILD) else {
            return;
        };
        let argv: Vec<String> = command.split(' ').map(String::from).collect();
        let (out, code) = dispatch(&argv);
        println!("{NO_HOME_CHILD}\t{code}\t{out}");
    }

    /// The variables a re-executed child needs just to BE a running process, carried across the
    /// `env_clear()` both reproductions rely on.
    ///
    /// None of them is a home directory or a collector path, so seeding them cannot weaken either
    /// reproduction — but on Windows a process with no `SystemRoot` and no `TEMP` is not reliably
    /// startable, and a child that fails to launch would turn both of these tests into vacuous
    /// passes on the platform they matter most on.
    const CHILD_ENV_FLOOR: [&str; 4] = ["SystemRoot", "SYSTEMROOT", "TEMP", "TMP"];

    fn seed_child_env(cmd: &mut std::process::Command) {
        cmd.env_clear();
        for key in CHILD_ENV_FLOOR {
            if let Ok(v) = std::env::var(key) {
                cmd.env(key, v);
            }
        }
    }

    /// Runs `command` in a child with no home directory in the environment, returning
    /// `(exit_code, response)`.
    fn dispatch_without_a_home(command: &str, extra_env: &[(&str, &str)]) -> (i32, String) {
        let (code, out, _) = dispatch_in_child(command, extra_env);
        (code, out)
    }

    /// [`dispatch_without_a_home`] that also hands back every OTHER stdout line the child wrote —
    /// the NDJSON a `--stream` run prints directly, which the buffered `out` cannot carry.
    fn dispatch_in_child(command: &str, extra_env: &[(&str, &str)]) -> (i32, String, Vec<String>) {
        let exe = std::env::current_exe().expect("a test binary must know its own path");
        let mut cmd = std::process::Command::new(&exe);
        cmd.args([
            "--exact",
            "--nocapture",
            "cli::tests::no_home_dispatch_child",
        ]);
        seed_child_env(&mut cmd);
        // `PATH` is left intact: the point of this reproduction is a missing HOME, and stripping
        // the collectors too would confuse it with the `status` one above.
        cmd.env("PATH", std::env::var("PATH").unwrap_or_default())
            .env(NO_HOME_CHILD, command);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd
            .output()
            .expect("re-executing the test binary must work");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.starts_with(NO_HOME_CHILD))
            .unwrap_or_else(|| {
                panic!("the child never reported for {command:?}, so this proved nothing: {stdout}")
            });
        let mut parts = line.splitn(3, '\t');
        let _marker = parts.next();
        let code = parts.next().unwrap().parse().unwrap();
        // Only the lines the engine wrote: the harness's own chatter (`running 1 test`, `test
        // result: …`) never starts with `{`.
        let rest = stdout
            .lines()
            .filter(|l| !l.starts_with(NO_HOME_CHILD) && l.starts_with('{'))
            .map(String::from)
            .collect();
        (code, parts.next().unwrap().to_string(), rest)
    }

    // ---------------------------------------------------------------------------------------
    // BUR-142: `clean --plan <file>` removes exactly what a reviewed dry run listed
    // ---------------------------------------------------------------------------------------

    /// A scratch home with `Library/Caches/{a,b,c,d,com.apple.Safari}` planted (each holding one
    /// 5-byte file) and a `Documents/keep` outside every clean root. Returns the home and a
    /// closure that writes a plan file listing whatever paths it is handed.
    #[cfg(unix)]
    fn planted_home(tag: &str) -> (std::path::PathBuf, impl Fn(&[String]) -> String) {
        let home = scratch_home(tag);
        for name in ["a", "b", "c", "d", "com.apple.Safari"] {
            let dir = home.join("Library/Caches").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("blob"), b"12345").unwrap();
        }
        std::fs::create_dir_all(home.join("Documents/keep")).unwrap();
        std::fs::write(home.join("Documents/keep/f"), b"k").unwrap();
        let plan_path = home.join("plan.txt");
        let write = move |lines: &[String]| -> String {
            let mut text = String::from("# written by a test\n\n");
            for l in lines {
                text.push_str(l);
                text.push('\n');
            }
            std::fs::write(&plan_path, text).unwrap();
            plan_path.to_str().unwrap().to_string()
        };
        (home, write)
    }

    #[cfg(unix)]
    fn cache(home: &std::path::Path, name: &str) -> String {
        home.join("Library/Caches")
            .join(name)
            .to_str()
            .unwrap()
            .to_string()
    }

    /// The child splits its command on spaces, so a scratch path with one in it would be two
    /// arguments. `temp_dir` has none on the platforms this runs on; say so if that ever changes.
    fn home_env(home: &std::path::Path) -> Vec<(&'static str, String)> {
        let h = home.to_str().unwrap().to_string();
        assert!(
            !h.contains(' '),
            "scratch home must not contain spaces: {h}"
        );
        vec![("HOME", h.clone()), (crate::platform::HOME_VAR, h)]
    }

    fn json(out: &str) -> crate::json::Json {
        crate::json::Json::parse(out).unwrap_or_else(|_| panic!("valid JSON expected: {out}"))
    }

    // check_tests: no-golden — the plan-file surface is an ENGINE_EXTENSION with no oracle; the
    // anchors are the planted filesystem and the `clean --apply` shape it must extend.
    #[cfg(unix)]
    #[test]
    fn a_plan_removes_exactly_the_listed_paths_in_file_order_and_records_one_session() {
        use crate::json::Json;
        let (home, write_plan) = planted_home("plan_exact");
        let file = write_plan(&[cache(&home, "c"), cache(&home, "a"), cache(&home, "b")]);
        let env = home_env(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (code, out) =
            dispatch_without_a_home(&format!("clean --apply --permanent --plan {file}"), &env);
        assert_eq!(code, 0, "{out}");
        let parsed = json(&out);
        let data = parsed.get("data").expect("data");
        // The three listed, in the file's order — not the scan's, not sorted.
        let removed: Vec<&str> = data
            .get("removed")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|r| r.get("path").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(
            removed,
            vec![cache(&home, "c"), cache(&home, "a"), cache(&home, "b")],
            "{out}"
        );
        for gone in ["a", "b", "c"] {
            assert!(!home.join("Library/Caches").join(gone).exists(), "{gone}");
        }
        // The unlisted sibling — which a re-scan WOULD have taken — is untouched.
        assert!(home.join("Library/Caches/d/blob").exists());
        // BUR-119 accounting: `--permanent` bills `freed_bytes`, never the Trash counter.
        assert_eq!(data.get("freed_bytes").and_then(Json::as_u64), Some(15));
        assert_eq!(
            data.get("moved_to_trash_bytes").and_then(Json::as_u64),
            Some(0)
        );
        let plan = data.get("plan").expect("plan object");
        assert_eq!(plan.get("file").and_then(Json::as_str), Some(file.as_str()));
        assert_eq!(plan.get("listed").and_then(Json::as_u64), Some(3));
        assert_eq!(plan.get("refused").and_then(Json::as_u64), Some(0));
        // One history session, items logged like a normal apply.
        let log = operations_log(&home);
        assert_eq!(log.matches("clean session started").count(), 1, "{log}");
        assert_eq!(log.matches("REMOVED").count(), 3, "{log}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn a_plan_refuses_paths_outside_the_clean_roots_protected_paths_and_traversal_untouched() {
        use crate::json::Json;
        let (home, write_plan) = planted_home("plan_refuse");
        let outside = home.join("Documents/keep").to_str().unwrap().to_string();
        let traversal = format!(
            "{}/../Documents/keep",
            home.join("Library/Caches").display()
        );
        let protected = cache(&home, "com.apple.Safari");
        let file = write_plan(&[outside.clone(), protected.clone(), traversal.clone()]);
        let env = home_env(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let (code, out) =
            dispatch_without_a_home(&format!("clean --apply --permanent --plan {file}"), &env);
        assert_eq!(code, 0, "a refusal is a verdict, not a failure: {out}");
        let parsed = json(&out);
        let data = parsed.get("data").expect("data");
        assert_eq!(
            data.get("removed").and_then(Json::as_array).map(<[_]>::len),
            Some(0),
            "{out}"
        );
        let protected_paths: Vec<&str> = data
            .get("protected")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(
            protected_paths,
            vec![outside.as_str(), protected.as_str(), traversal.as_str()],
            "{out}"
        );
        let plan = data.get("plan").expect("plan object");
        assert_eq!(plan.get("listed").and_then(Json::as_u64), Some(3));
        assert_eq!(plan.get("refused").and_then(Json::as_u64), Some(3));
        let reasons: Vec<(&str, &str)> = plan
            .get("refusals")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r.get("path").and_then(Json::as_str).unwrap(),
                    r.get("reason").and_then(Json::as_str).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            reasons,
            vec![
                (
                    outside.as_str(),
                    crate::clean::plan_file::NOT_A_CLEAN_TARGET
                ),
                (protected.as_str(), crate::clean::plan_file::PROTECTED),
                (
                    traversal.as_str(),
                    crate::clean::plan_file::NOT_A_CLEAN_TARGET
                ),
            ],
            "{out}"
        );
        // All three still on disk, and so is everything the file did not name.
        assert!(home.join("Documents/keep/f").exists());
        assert!(home.join("Library/Caches/com.apple.Safari/blob").exists());
        for kept in ["a", "b", "c", "d"] {
            assert!(home.join("Library/Caches").join(kept).join("blob").exists());
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn a_plan_without_apply_is_a_dry_run_over_the_same_list_with_the_same_refusals() {
        use crate::json::Json;
        let (home, write_plan) = planted_home("plan_dry");
        let outside = home.join("Documents/keep").to_str().unwrap().to_string();
        let file = write_plan(&[cache(&home, "a"), outside.clone(), cache(&home, "nope")]);
        let env = home_env(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        for argv in [
            format!("clean --plan {file}"),
            format!("clean --dry-run --plan {file}"),
        ] {
            let (code, out) = dispatch_without_a_home(&argv, &env);
            assert_eq!(code, 0, "{out}");
            let parsed = json(&out);
            let data = parsed.get("data").expect("data");
            assert_eq!(data.get("dry_run").and_then(Json::as_bool), Some(true));
            let items = data.get("items").and_then(Json::as_array).unwrap();
            assert_eq!(items.len(), 1, "{out}");
            assert_eq!(
                items[0].get("path").and_then(Json::as_str),
                Some(cache(&home, "a").as_str())
            );
            let plan = data.get("plan").expect("plan object");
            assert_eq!(plan.get("listed").and_then(Json::as_u64), Some(3));
            assert_eq!(plan.get("refused").and_then(Json::as_u64), Some(1));
            assert_eq!(plan.get("missing").and_then(Json::as_u64), Some(1));
            assert!(
                home.join("Library/Caches/a/blob").exists(),
                "a dry run deletes nothing"
            );
        }
        // `--apply --dry-run` is the same contradiction it is without `--plan`.
        let (code, out) =
            dispatch_without_a_home(&format!("clean --apply --dry-run --plan {file}"), &env);
        assert_eq!(code, 2, "{out}");
        assert!(home.join("Library/Caches/a/blob").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn a_streamed_plan_emits_the_same_ndjson_vocabulary_as_a_streamed_apply() {
        use crate::json::Json;
        let (home, write_plan) = planted_home("plan_stream");
        let outside = home.join("Documents/keep").to_str().unwrap().to_string();
        let file = write_plan(&[cache(&home, "a"), outside.clone(), cache(&home, "b")]);
        let env = home_env(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();

        // Preview first: `would_remove` per candidate, `protected` (with the reason) per refusal,
        // then the dry-run `done` — and nothing deleted.
        let (code, _, lines) = dispatch_in_child(&format!("clean --stream --plan {file}"), &env);
        assert_eq!(code, 0);
        let events: Vec<crate::json::Json> = lines.iter().map(|l| json(l)).collect();
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| e.get("event").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(
            kinds,
            vec!["would_remove", "protected", "would_remove", "done"],
            "{lines:?}"
        );
        assert_eq!(
            events[1].get("reason").and_then(Json::as_str),
            Some(crate::clean::plan_file::NOT_A_CLEAN_TARGET)
        );
        assert_eq!(events[3].get("dry_run").and_then(Json::as_bool), Some(true));
        assert_eq!(events[3].get("count").and_then(Json::as_u64), Some(2));
        assert!(home.join("Library/Caches/a/blob").exists());

        // Then the live run: `removed`/`protected` … `done{…}`, in file order.
        let (code, _, lines) = dispatch_in_child(
            &format!("clean --stream --apply --permanent --plan {file}"),
            &env,
        );
        assert_eq!(code, 0);
        let events: Vec<crate::json::Json> = lines.iter().map(|l| json(l)).collect();
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| e.get("event").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(
            kinds,
            vec!["removed", "protected", "removed", "done"],
            "{lines:?}"
        );
        assert_eq!(
            events[0].get("path").and_then(Json::as_str),
            Some(cache(&home, "a").as_str())
        );
        let done = &events[3];
        assert_eq!(done.get("removed").and_then(Json::as_u64), Some(2));
        assert_eq!(done.get("protected").and_then(Json::as_u64), Some(1));
        assert_eq!(done.get("freed_bytes").and_then(Json::as_u64), Some(10));
        assert!(!home.join("Library/Caches/a").exists());
        assert!(!home.join("Library/Caches/b").exists());
        assert!(home.join("Documents/keep/f").exists());
        assert!(home.join("Library/Caches/d/blob").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_missing_plan_file_is_an_error_envelope_and_a_bare_flag_is_refused() {
        let home = scratch_home("plan_missing");
        let env = home_env(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let missing = home.join("no-such-plan.txt");
        let (code, out) =
            dispatch_without_a_home(&format!("clean --apply --plan {}", missing.display()), &env);
        assert_eq!(code, 1, "{out}");
        let parsed = json(&out);
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false)
        );
        // Off unix the `--apply` guard answers before the file is looked at: a caller learns the
        // command cannot delete here before it learns its plan file is missing.
        let expected_kind = if crate::clean::validate::RAILS_SPEAK_THIS_PLATFORMS_PATHS {
            "not_found"
        } else {
            "unsupported"
        };
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("kind"))
                .and_then(crate::json::Json::as_str),
            Some(expected_kind),
            "{out}"
        );
        let (code, out) = dispatch_without_a_home("clean --plan", &env);
        assert_eq!(code, 2, "{out}");
        assert!(out.contains("--plan needs a file path"), "{out}");
        // Only filesystem sweep commands accept reviewed plans.
        for other in ["uninstall", "optimize"] {
            assert!(
                reject_unknown_flag(other, &args(&["--plan", "/x"])).is_some(),
                "{other} must not accept --plan"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Six commands answered `ok:true` with an empty result when the home directory could not be
    /// found — because `std::env::var("HOME").unwrap_or_default()` turns "not set" into `""`, which
    /// concatenates into absolute paths like `/Library/Caches/*` that exist on no machine, scan
    /// nothing, and come back clean. `HOME` is also a POSIX variable Windows does not set, so on
    /// Windows that was every run, not an edge case.
    ///
    /// The property here is the DISTINCTION, which is the whole bug: after this, an empty
    /// successful result from these commands means the scan ran and found nothing, and "I do not
    /// know where to look" is a classified failure. Both halves are asserted — a refusal that also
    /// fired on a machine WITH a home would be its own regression.
    ///
    // check_tests: no-golden — there is no capture to anchor to: the shipping oracle answers
    // ok:true here, which is the defect. The anchor is the live before/after reproduction.
    #[test]
    fn the_home_dependent_commands_refuse_instead_of_reporting_an_empty_success() {
        for command in [
            "clean",
            "purge",
            "installer",
            "history",
            "sentinel",
            "uninstall Safari",
        ] {
            let (code, out) = dispatch_without_a_home(command, &[]);
            let parsed = crate::json::Json::parse(&out)
                .unwrap_or_else(|_| panic!("{command} must emit valid JSON: {out}"));
            assert_eq!(
                parsed.get("ok").and_then(crate::json::Json::as_bool),
                Some(false),
                "{command} with no home must not report success: {out}"
            );
            assert_ne!(code, 0, "{command}: the exit code must agree: {out}");
            let err = parsed
                .get("error")
                .expect("a failure carries an error object");
            assert_eq!(
                err.get("kind").and_then(crate::json::Json::as_str),
                Some("not_found"),
                "{command} must classify as a lookup failure: {out}"
            );
            assert_eq!(
                err.get("message").and_then(crate::json::Json::as_str),
                Some(crate::platform::NO_HOME),
                "{command}: {out}"
            );
        }
    }

    /// BUR-141: under `do shell script … with administrator privileges` (and `sudo`) the engine's
    /// `HOME` is `/var/root`, and every `~`-relative command answered for root's empty library —
    /// `clean` found nothing to clean, `history` found no sessions, `purge` scanned `/var/root/dev`.
    /// Root's home is now refused with the fix named, and `BURROW_HOME` — which the app's
    /// privileged helper sets to the user's real home — is the highest-precedence source.
    #[test]
    fn roots_home_is_refused_unless_burrow_home_names_the_users() {
        for command in ["clean", "purge", "installer", "history", "sentinel"] {
            let (code, out) = dispatch_without_a_home(command, &[("HOME", "/var/root")]);
            let parsed = crate::json::Json::parse(&out)
                .unwrap_or_else(|_| panic!("{command} must emit valid JSON: {out}"));
            assert_ne!(code, 0, "{command}: {out}");
            let err = parsed
                .get("error")
                .expect("a failure carries an error object");
            assert_eq!(
                err.get("kind").and_then(crate::json::Json::as_str),
                Some("not_found"),
                "{command}: same kind as NO_HOME: {out}"
            );
            let message = err
                .get("message")
                .and_then(crate::json::Json::as_str)
                .unwrap_or_default();
            assert!(
                message.contains(crate::platform::HOME_VAR) && message.contains("/var/root"),
                "{command}: the message must say to pass BURROW_HOME: {out}"
            );
        }

        // …and with BURROW_HOME naming a home, the same HOME=/var/root run answers for THAT home.
        let home = scratch_home("burrow_home");
        let ops = home.join("Library/Logs/mole/operations.log");
        std::fs::create_dir_all(ops.parent().unwrap()).unwrap();
        std::fs::write(
            &ops,
            "# ========== clean session started at 2026-01-01 00:00:00 ==========\n\
             # ========== clean session ended at 2026-01-01 00:00:05, 1 items, 1KB ==========\n",
        )
        .unwrap();
        let (code, out) = dispatch_without_a_home(
            "history",
            &[
                ("HOME", "/var/root"),
                (crate::platform::HOME_VAR, home.to_str().unwrap()),
            ],
        );
        assert_eq!(code, 0, "{out}");
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(true),
            "{out}"
        );
        // Compared as PATHS, not strings: `history` spells the default with the oracle's `/`
        // (`{home}/Library/Logs/mole/operations.log`) while `ops` came from `Path::join`, which
        // on Windows puts a `\` between the two halves. `Path` equality is component-wise and
        // treats both as separators, so the same file compares equal however it was spelled.
        let reported = parsed
            .get("data")
            .and_then(|d| d.get("logs"))
            .and_then(|l| l.get("operations"))
            .and_then(crate::json::Json::as_str)
            .map(std::path::Path::new);
        assert_eq!(
            reported,
            Some(ops.as_path()),
            "the log under BURROW_HOME, not under /var/root: {out}"
        );
        assert_eq!(
            parsed
                .get("data")
                .and_then(|d| d.get("sessions"))
                .and_then(crate::json::Json::as_array)
                .map(<[_]>::len),
            Some(1),
            "{out}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// The other half of the distinction: the same commands, on this machine, which HAS a home.
    /// Without this the refusal above could be satisfied by refusing always, which would be a worse
    /// bug than the one it replaces.
    ///
    /// Read-only forms only — `clean`/`purge`/`installer` are dry runs without `--apply`, and
    /// `sentinel` is read-only by construction.
    #[test]
    fn the_same_commands_still_answer_normally_when_a_home_exists() {
        let home_path =
            std::env::temp_dir().join(format!("burrow_cli_home_success_{}", std::process::id()));
        std::fs::create_dir_all(&home_path).unwrap();
        let home = home_path.to_str().unwrap();
        for command in ["clean", "purge", "installer", "history", "sentinel"] {
            // The variable this machine actually answers from — `HOME` on unix, `USERPROFILE` on
            // Windows. Reading `HOME` directly would set a blank value on a Windows runner and turn
            // this into an accidental second copy of the refusal test above.
            let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
            let (code, out) = dispatch_without_a_home(command, &[(key, home)]);
            let parsed = crate::json::Json::parse(&out)
                .unwrap_or_else(|_| panic!("{command} must emit valid JSON: {out}"));
            // `sentinel` with no positional infers `<home>/.Trash`, which only exists on macOS —
            // freedesktop puts it at ~/.local/share/Trash/files, so scanning ~/.Trash off macOS
            // would report an empty trash it never looked at. Having a home does not make that
            // path real, so off macOS the answer is a DIFFERENT refusal, not a success. Assert
            // that specifically: the point of this test is that the NO_HOME refusal above went
            // away, and a blanket "it fails somehow" would satisfy the buggy always-refuse case
            // this test exists to rule out.
            if command == "sentinel" && !cfg!(target_os = "macos") {
                let err = parsed
                    .get("error")
                    .unwrap_or_else(|| panic!("a refusal carries an error object: {out}"));
                assert_eq!(
                    err.get("kind").and_then(crate::json::Json::as_str),
                    Some("unsupported"),
                    "sentinel off macOS refuses the inferred trash, not the home: {out}"
                );
                assert_eq!(
                    parsed.get("feature").and_then(crate::json::Json::as_str),
                    Some("sentinel default trash"),
                    "the refusal must name the inference, not the command: {out}"
                );
                continue;
            }
            assert_eq!(
                parsed.get("ok").and_then(crate::json::Json::as_bool),
                Some(true),
                "{command} must still succeed with a home: {out}"
            );
            assert_eq!(code, 0, "{command}: {out}");
        }
        let _ = std::fs::remove_dir_all(home_path);
    }

    /// `USERPROFILE` is the Windows spelling, and the fallback that was missing entirely. Asserted
    /// on every platform through the same child mechanism: on Windows it must be what ANSWERS, and
    /// on unix it must not be — a `home_dir` that consulted `USERPROFILE` everywhere would silently
    /// redirect a Mac user's `clean` to whatever that variable happened to hold.
    #[test]
    fn userprofile_answers_on_windows_and_is_ignored_elsewhere() {
        let real_home =
            crate::platform::home_dir().expect("this machine must have a home directory");
        let (_, out) = dispatch_without_a_home("sentinel", &[("USERPROFILE", &real_home)]);
        let parsed = crate::json::Json::parse(&out).expect("valid JSON");
        // Read the KIND, not `ok`. Since the inferred <home>/.Trash is refused off macOS,
        // `sentinel` no longer succeeds anywhere this test runs — but the two outcomes stay
        // cleanly distinguishable, and the distinction is exactly what this test is about:
        // `unsupported` can only be reached AFTER `home_or_refuse` returned a home, so on
        // Windows it proves USERPROFILE answered, while `not_found` on unix proves it did not.
        let kind = parsed
            .get("error")
            .and_then(|e| e.get("kind"))
            .and_then(crate::json::Json::as_str);
        if cfg!(windows) {
            assert_eq!(
                kind,
                Some("unsupported"),
                "USERPROFILE must be honoured on Windows — reaching the trash refusal proves \
                 a home resolved: {out}"
            );
        } else {
            assert_eq!(
                kind,
                Some("not_found"),
                "USERPROFILE must NOT stand in for HOME on unix: {out}"
            );
        }
    }

    // ---------------------------------------------------------------------------------------
    // `status` must not report a health score it did not measure
    // ---------------------------------------------------------------------------------------

    /// Set on a re-executed copy of this test binary by
    /// [`status_refuses_rather_than_reporting_a_healthy_score_when_nothing_was_measured`].
    const UNREACHABLE_CHILD: &str = "BURROW_ENGINE_STATUS_UNREACHABLE_CHILD";

    /// The child half of the reproduction. Runs `dispatch(["status"])` and prints the result on one
    /// line, prefixed so the parent can find it among libtest's own output.
    ///
    /// It is a `#[test]` because that is the only way to get libtest to run one named function in a
    /// child process, and it returns immediately under a normal run — the marker is only ever set by
    /// the parent below.
    ///
    /// Why a child process at all: the reproduction needs the collector binaries to be unreachable,
    /// which means stripping `PATH`, and `PATH` is process-wide. Six other modules in this crate
    /// spawn `sysctl` / `vm_stat` / `ps` / `date` by bare name from their own tests, so doing it in
    /// this process would trade a real check here for flakes everywhere else (`tool_delegate`'s test
    /// module documents having been bitten by exactly that). A child gets a genuinely stripped
    /// environment that cannot touch anyone else.
    #[test]
    fn status_dispatch_child_for_the_unreachable_collectors_reproduction() {
        if std::env::var(UNREACHABLE_CHILD).is_err() {
            return;
        }
        let (out, code) = dispatch(&args(&["status"]));
        println!("{UNREACHABLE_CHILD}\t{code}\t{out}");
    }

    /// The refusal shape, on the raw bytes: no score at all rather than a confident one, classified
    /// the way `net`/`orphans` classify an environment that cannot serve them, naming the probes.
    fn assert_status_refusal(json: &str, code: i32) {
        let parsed = crate::json::Json::parse(json).expect("status must emit valid JSON");
        assert_eq!(
            parsed.get("ok").and_then(crate::json::Json::as_bool),
            Some(false),
            "a snapshot in which nothing could be measured is a failure, not a success: {json}"
        );
        assert_ne!(
            code, 0,
            "the exit code must agree with the envelope: {json}"
        );
        // The crux: no score at all, rather than a confident one. Checked on the raw bytes because
        // the point is that the FIELD is absent from the response, not that it holds some
        // particular value.
        assert!(
            !json.contains("health_score"),
            "a health score computed from data that was never collected must not be reported: {json}"
        );
        assert!(
            !json.contains("Excellent"),
            "the healthy verdict this bug produced must not survive anywhere in the response: {json}"
        );
        let err = parsed
            .get("error")
            .expect("a failure carries an error object");
        assert_eq!(
            err.get("kind").and_then(crate::json::Json::as_str),
            Some("unsupported"),
            "{json}"
        );
        assert_eq!(
            parsed.get("feature").and_then(crate::json::Json::as_str),
            Some("status"),
            "{json}"
        );
        // And the reason names the probes, so the failure is actionable rather than merely honest.
        let message = err
            .get("message")
            .and_then(crate::json::Json::as_str)
            .unwrap_or_default();
        for probe in ["sysctl", "df", "ps"] {
            assert!(
                message.contains(probe),
                "the refusal must name the probe that failed ({probe}): {message}"
            );
        }
    }

    /// THE regression's shape, over the pure response: a snapshot in which none of the four
    /// health inputs was measured used to answer `exit 0, ok:true, health_score:100,
    /// health_score_msg:"Excellent"` — every collector degraded to a zero, every penalty branch in
    /// `calculate_health_score` is a `>` threshold that zero cannot trip, and the score never
    /// moved off the 100 it starts from. It is a refusal now.
    //
    // check_tests: no-golden — the shape under test is a REFUSAL, which the shipping oracle has no
    // equivalent of (it always answered ok:true here, which is the bug).
    #[test]
    fn status_refuses_rather_than_reporting_a_healthy_score_when_nothing_was_measured() {
        let (json, code) =
            status_response(&crate::status::snapshot::Snapshot::unmeasured_for_tests());
        assert_status_refusal(&json, code);
    }

    /// The live reproduction — a real process, a real `dispatch`, real spawns that really fail —
    /// rather than a constructed snapshot, because the bug lived in whether the collectors REPORT
    /// their failures, which a mocked snapshot cannot exercise.
    ///
    /// With `PATH` stripped every shell-out fails. On macOS one input survives that: CPU is read
    /// in-process through Mach `host_processor_info` (`status::cpu`, BUR-140), so the honest
    /// answer is a DEGRADED snapshot — `ok:true`, a score that is an upper bound, and a message
    /// that leads with what was not measured — never a bare healthy verdict. Everywhere else
    /// nothing at all can be measured and the answer is the refusal.
    #[test]
    fn status_reports_unreachable_collectors_instead_of_a_healthy_score() {
        let exe = std::env::current_exe().expect("a test binary must know its own path");
        let mut cmd = std::process::Command::new(&exe);
        cmd.args([
            "--exact",
            "--nocapture",
            "cli::tests::status_dispatch_child_for_the_unreachable_collectors_reproduction",
        ]);
        seed_child_env(&mut cmd);
        // The reproduction's own environment: nothing resolvable on PATH, so every collector's
        // spawn fails outright.
        cmd.env("PATH", "/nonexistent").env(UNREACHABLE_CHILD, "1");
        let out = cmd
            .output()
            .expect("re-executing the test binary must work");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout
            .lines()
            .find(|l| l.starts_with(UNREACHABLE_CHILD))
            .unwrap_or_else(|| {
                panic!(
                    "the child never reported — the reproduction did not run, so this test proved \
                     nothing. stdout: {stdout}\nstderr: {}",
                    String::from_utf8_lossy(&out.stderr)
                )
            });
        let mut parts = line.splitn(3, '\t');
        let _marker = parts.next();
        let code: i32 = parts.next().unwrap().parse().unwrap();
        let json = parts.next().unwrap();

        if !cfg!(target_os = "macos") {
            assert_status_refusal(json, code);
            return;
        }
        use crate::json::Json;
        let parsed = Json::parse(json).expect("status must emit valid JSON");
        assert_eq!(code, 0, "{json}");
        assert_eq!(
            parsed.get("ok").and_then(Json::as_bool),
            Some(true),
            "{json}"
        );
        let data = parsed.get("data").expect("data");
        let msg = data
            .get("health_score_msg")
            .and_then(Json::as_str)
            .unwrap_or_default();
        assert!(
            msg.starts_with("Degraded — not measured:"),
            "a partly-measured snapshot must lead with what is missing: {msg}"
        );
        for missing in ["memory", "disks", "uptime_seconds"] {
            assert!(msg.contains(missing), "{missing} was not measured: {msg}");
        }
        assert!(
            !msg.contains("cpu.usage"),
            "CPU is read in-process and WAS measured: {msg}"
        );
        let unavailable = data
            .get("metrics_unavailable")
            .and_then(Json::as_array)
            .expect("metrics_unavailable");
        assert_eq!(unavailable.len(), 3, "{json}");
        let cpu = data.get("cpu").expect("cpu");
        assert_eq!(
            cpu.get("per_core_estimated").and_then(Json::as_bool),
            Some(false),
            "the real per-core reading needs no PATH: {json}"
        );
        assert!(!cpu
            .get("per_core")
            .and_then(Json::as_array)
            .unwrap()
            .is_empty());
    }
}
