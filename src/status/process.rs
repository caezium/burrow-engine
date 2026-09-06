//! Process list parsing + top-N selection — ported from digger's `cmd/status/metrics_process.go`.
//! The `ps` invocation is the native collector; this is the pure parsing + ranking it feeds. (The
//! TUI label helpers aren't ported here.)

/// One process row. Subset of digger's ProcessInfo — the fields the parser/ranker populate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub name: String,
    pub command: String,
    pub cpu: f64,
    /// Percent of physical memory.
    pub memory: f64,
    pub memory_bytes: u64,
}

/// The display name for a command line: the basename of the whole string (everything after the
/// last `/`), then truncated at the first space. Matches digger — note this can pick an argument's
/// basename over the executable's for `interpreter /path/to/script` command lines.
pub fn process_name_from_command(command: &str) -> String {
    let after_slash = command.rsplit_once('/').map(|(_, n)| n).unwrap_or(command);
    after_slash
        .split_once(' ')
        .map(|(n, _)| n)
        .unwrap_or(after_slash)
        .to_string()
}

/// Parse the primary `ps` output — columns `PID PPID %CPU %MEM [RSS_KB] COMMAND…`. The optional RSS
/// column is detected by whether field 5 parses as an unsigned integer (a command path never does),
/// so both the old 5-column and new 6-column shapes are handled. Malformed lines are skipped.
pub fn parse_process_output(raw: &str) -> Vec<ProcessInfo> {
    let mut procs = Vec::new();
    for line in raw.trim().lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let Ok(pid) = fields[0].parse::<i32>() else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        let ppid = fields[1].parse::<i32>().unwrap_or(0);
        let (Ok(cpu), Ok(memory)) = (fields[2].parse::<f64>(), fields[3].parse::<f64>()) else {
            continue;
        };

        // Optional RSS (KB) column, present only when field 5 is a bare integer.
        let mut rss_bytes = 0u64;
        let mut command_start = 4;
        if fields.len() >= 6 {
            if let Ok(rss_kb) = fields[4].parse::<u64>() {
                rss_bytes = rss_kb * 1024;
                command_start = 5;
            }
        }

        let command = fields[command_start..].join(" ");
        if command.is_empty() {
            continue;
        }
        procs.push(ProcessInfo {
            pid,
            ppid,
            name: process_name_from_command(&command),
            command,
            cpu,
            memory,
            memory_bytes: rss_bytes,
        });
    }
    procs
}

/// Parse the FALLBACK `ps aux` format — columns `USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME
/// COMMAND…`, header line skipped. Ported from digger's `parsePsAuxOutput` (`metrics_process.go`);
/// see `collect::collect_processes`'s doc comment for when this is used (the primary `ps -Aceo…`
/// invocation failed). `ppid` is always 0 here — `ps aux` doesn't carry it — matching digger, which
/// leaves `PPID: 0` on this path too rather than inventing one. Malformed lines are skipped.
pub fn parse_ps_aux_output(raw: &str) -> Vec<ProcessInfo> {
    let mut procs = Vec::new();
    for (i, line) in raw.trim().lines().enumerate() {
        if i == 0 {
            continue; // header: "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND"
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 11 {
            continue;
        }
        let Ok(pid) = fields[1].parse::<i32>() else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        let (Ok(cpu), Ok(memory)) = (fields[2].parse::<f64>(), fields[3].parse::<f64>()) else {
            continue;
        };
        let rss_kb = fields[5].parse::<u64>().unwrap_or(0);
        let command = fields[10..].join(" ");
        if command.is_empty() {
            continue;
        }
        procs.push(ProcessInfo {
            pid,
            ppid: 0,
            name: process_name_from_command(&command),
            command,
            cpu,
            memory,
            memory_bytes: rss_kb * 1024,
        });
    }
    procs
}

/// Evenly distribute the sum of every process's `%CPU` (the SAME `ps` sample already collected for
/// `top_processes`) across `logical_cpu` cores. Ported from digger's `fallbackCPUUtilization`
/// (metrics_cpu.go) — the path digger ITSELF falls back to when its real per-core reading
/// (gopsutil's `cpu.Percent(0, true)`, which on Darwin is a Mach `host_processor_info` syscall, not
/// a shell command) is unavailable.
///
/// The same role here: `super::cpu` makes that Mach call in-process, and this is what
/// `snapshot::collect_with` reaches for when it fails (off macOS, or a window that accrued no
/// ticks), flagged `per_core_estimated: true`. Every element is IDENTICAL (the aggregate spread
/// evenly), unlike a genuine per-core reading, which on any multi-core machine under real load is
/// essentially never uniform; a consumer inspecting the array can tell the two apart at a glance.
/// A transparently-uniform estimate beats leaving `cpu.per_core` empty (RULEBOOK §6) or
/// fabricating a value that LOOKS like real telemetry (§3h).
///
/// Empty when `logical_cpu <= 0` (the upstream core-count probe failed — not this function's
/// problem to paper over).
pub fn estimate_per_core(processes: &[ProcessInfo], logical_cpu: i64) -> Vec<f64> {
    if logical_cpu <= 0 {
        return Vec::new();
    }
    let total: f64 = processes.iter().map(|p| p.cpu).sum();
    let max_total = logical_cpu as f64 * 100.0;
    let avg = total.clamp(0.0, max_total) / logical_cpu as f64;
    vec![avg; logical_cpu as usize]
}

/// `cpu.usage` on the FALLBACK path: the SAME average that built `per_core`, never a
/// separately-sampled figure. digger's own fallback (`fallbackCPUUtilization`, metrics_cpu.go)
/// returns `(avg, perCore, err)` from ONE shared `avg` variable, so `totalPercent` and every
/// `PerCore` element are equal by construction there; deriving `cpu.usage` from an independent
/// `top -l 2` sample instead measurably broke that (live, pre-fix: usage=9.30 beside fourteen
/// identical per_core entries of 4.39). On the REAL path (`super::cpu`) the total is tick-weighted
/// and is NOT the mean of `per_core` — that is the oracle's own change in commit a6d1a98.
/// Computes the true mean rather than reading `per_core[0]` so the fallback identity holds even if
/// `estimate_per_core`'s uniform-spread implementation ever changes. Empty `per_core` (the
/// core-count probe failed) degrades to `0.0` — the same honest-failure signal `core_count` itself
/// already uses (RULEBOOK §3h) — rather than a fabricated positive number.
pub fn cpu_usage_from_per_core(per_core: &[f64]) -> f64 {
    if per_core.is_empty() {
        return 0.0;
    }
    per_core.iter().sum::<f64>() / per_core.len() as f64
}

/// The `limit` highest-usage processes, ranked by CPU (desc), then memory (desc), then PID (asc) as
/// a stable tiebreak. Empty when `limit <= 0`.
pub fn top_processes(processes: &[ProcessInfo], limit: usize) -> Vec<ProcessInfo> {
    if limit == 0 || processes.is_empty() {
        return Vec::new();
    }
    let mut ranked = processes.to_vec();
    ranked.sort_by(|a, b| {
        use std::cmp::Ordering::Equal;
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(Equal)
            .then(b.memory.partial_cmp(&a.memory).unwrap_or(Equal))
            .then(a.pid.cmp(&b.pid))
    });
    ranked.truncate(limit);
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_from_command_takes_basename_then_first_token() {
        assert_eq!(
            process_name_from_command(
                "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
            ),
            "Electron"
        );
        assert_eq!(
            process_name_from_command("/usr/local/bin/node /tmp/server.js"),
            "server.js"
        );
        assert_eq!(process_name_from_command("Finder"), "Finder");
    }

    #[test]
    fn parse_six_column_captures_rss_and_spaced_command() {
        let raw = "123 1 145.2 10.1 7340032 /Applications/Visual Studio Code.app/Contents/MacOS/Electron\n456 1 99.5 2.2 262144 /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder\nbad line";
        let p = parse_process_output(raw);
        assert_eq!(p.len(), 2, "the malformed line is dropped");
        assert_eq!((p[0].pid, p[0].ppid), (123, 1));
        assert_eq!(p[0].name, "Electron");
        assert!(
            p[0].command.contains("Visual Studio Code.app"),
            "spaces preserved"
        );
        assert_eq!(p[0].memory_bytes, 7340032 * 1024);
    }

    #[test]
    fn parse_five_column_keeps_old_shape_without_inventing_rss() {
        let raw = "123 1 145.2 10.1 /Applications/Visual Studio Code.app/Contents/MacOS/Electron";
        let p = parse_process_output(raw);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].memory, 10.1);
        assert_eq!(p[0].memory_bytes, 0, "old shape must not invent RSS");
        assert_eq!(
            p[0].command,
            "/Applications/Visual Studio Code.app/Contents/MacOS/Electron"
        );
    }

    #[test]
    fn ps_aux_fallback_parses_header_skipped_and_ppid_zero() {
        // Real `ps aux` shape: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND.
        let raw = "USER  PID  %CPU %MEM    VSZ    RSS TT  STAT STARTED   TIME COMMAND\n\
root    1   0.0  0.1 408000   9000 ??  Ss   Mon06AM  10:00.00 /sbin/launchd\n\
alice 456  12.5  2.2 987654  71680 ??  S    12:00PM   0:05.00 /Applications/Foo.app/Contents/MacOS/Foo --flag\n\
bad line here";
        let procs = parse_ps_aux_output(raw);
        assert_eq!(procs.len(), 2, "the malformed trailing line is dropped");
        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[0].name, "launchd");
        assert_eq!(procs[0].ppid, 0, "ps aux carries no PPID column");
        assert_eq!(procs[1].pid, 456);
        assert_eq!(procs[1].cpu, 12.5);
        assert_eq!(procs[1].memory, 2.2);
        assert_eq!(procs[1].memory_bytes, 71680 * 1024);
        assert!(procs[1].command.contains("--flag"), "spaces preserved");
    }

    #[test]
    fn per_core_estimate_spreads_the_total_evenly_and_clamps() {
        let procs = vec![
            ProcessInfo {
                cpu: 150.0,
                ..Default::default()
            },
            ProcessInfo {
                cpu: 250.0,
                ..Default::default()
            },
        ]; // total 400% across 4 logical cores → 100% each.
        let per_core = estimate_per_core(&procs, 4);
        assert_eq!(per_core.len(), 4);
        assert!(per_core.iter().all(|&v| (v - 100.0).abs() < 1e-9));
    }

    #[test]
    fn per_core_estimate_clamps_above_max_total_like_digger() {
        // 5 cores × 100 = 500 max; 900% summed clamps to 500 → 100% per core, not 180%.
        let procs = vec![ProcessInfo {
            cpu: 900.0,
            ..Default::default()
        }];
        let per_core = estimate_per_core(&procs, 5);
        assert!(per_core.iter().all(|&v| (v - 100.0).abs() < 1e-9));
    }

    #[test]
    fn per_core_estimate_is_empty_when_core_count_is_not_positive() {
        let procs = vec![ProcessInfo {
            cpu: 50.0,
            ..Default::default()
        }];
        assert!(estimate_per_core(&procs, 0).is_empty());
        assert!(estimate_per_core(&procs, -1).is_empty());
    }

    #[test]
    fn cpu_usage_from_per_core_is_the_true_mean_not_a_separate_sample() {
        // FIX 2 (RULEBOOK): mirrors the oracle's own invariant — mean(per_core) == usage, exactly.
        // Computed as an actual sum/len mean (not "read element 0"), so this stays correct even if
        // `estimate_per_core`'s uniform-spread implementation ever changes.
        let procs = vec![
            ProcessInfo {
                cpu: 150.0,
                ..Default::default()
            },
            ProcessInfo {
                cpu: 250.0,
                ..Default::default()
            },
        ]; // total 400% across 4 logical cores -> 100% each.
        let per_core = estimate_per_core(&procs, 4);
        let usage = cpu_usage_from_per_core(&per_core);
        let true_mean: f64 = per_core.iter().sum::<f64>() / per_core.len() as f64;
        assert_eq!(usage, true_mean);
        assert_eq!(usage, 100.0);
    }

    #[test]
    fn cpu_usage_from_per_core_is_zero_when_per_core_is_empty() {
        // Matches `core_count`'s own honest-failure convention (RULEBOOK §3h): a probe failure
        // reports 0, never a fabricated positive number.
        assert_eq!(cpu_usage_from_per_core(&[]), 0.0);
    }

    #[test]
    fn top_processes_sorts_by_cpu_then_memory() {
        let procs = vec![
            ProcessInfo {
                pid: 3,
                name: "low".into(),
                cpu: 20.0,
                memory: 3.0,
                ..Default::default()
            },
            ProcessInfo {
                pid: 1,
                name: "high".into(),
                cpu: 120.0,
                memory: 1.0,
                ..Default::default()
            },
            ProcessInfo {
                pid: 2,
                name: "mid".into(),
                cpu: 120.0,
                memory: 8.0,
                ..Default::default()
            },
        ];
        let top = top_processes(&procs, 2);
        assert_eq!(top.len(), 2);
        // Both at CPU 120 → higher memory (pid 2) first, then pid 1; pid 3 drops out.
        assert_eq!((top[0].pid, top[1].pid), (2, 1));
        assert!(top_processes(&procs, 0).is_empty());
    }
}
