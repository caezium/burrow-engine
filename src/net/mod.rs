//! Per-process network attribution — the engine port of burrow-cli's `net` command. macOS reads
//! the built-in `nettop` byte counters from one `nettop -P -L 1 -x -J bytes_in,bytes_out` sample.
//! Windows attributes CONNECTIONS to processes: native IP Helper PID tables first
//! ([`collect_windows_iphelper`]), then a conservative `netstat -ano` + `tasklist` fallback
//! ([`collect_windows_netstat`]). The Windows sources report connection counts, not byte
//! counters, and say so on every row through `metric_source` + `metric_note`.
//!
//! Every parser is pure and unit-tested on every platform; only the IP Helper call is compiled on
//! Windows, and every subprocess goes through the injected runner ([`Runner`]).
//!
//! The JSON contract is dictated by two oracles, not invented here: `net.golden.json` (the `data`
//! payload of the real shipping program) and `NetModel.swift` on `origin/main`, which reads
//! `raw["by_total_bytes"]` and nothing else. The engine previously emitted root key `processes`,
//! which `NetModel.parse` doesn't recognize — that decodes to a *valid* report with zero rows, no
//! error, just a permanently empty pane. Root key, per-row field names, `metric_source` and
//! `metric_note` here all match `burrow-cli/src/net.rs`, the program that actually produced the
//! golden.
//!
//! # PROVENANCE
//!
//! | Capability | Source | License | Mode |
//! |---|---|---|---|
//! | Windows per-app network attribution (`collect_windows_iphelper`, `collect_windows_netstat`) | burrow-cli `src/net.rs` at `5e71023` (the version #18 deleted; burrow-cli `PROVENANCE.md` row 2026-07-10) — `windows-sys` crate, IP Helper `GetExtendedTcpTable` / `GetExtendedUdpTable`; `netstat -ano` + `tasklist` (Windows built-ins) | MIT / Apache-2.0 (`windows-sys`); OS tools | **A** — wrapped as an external dependency, target-scoped in `Cargo.toml` |
//!
//! Restored here rather than re-derived: the code is the same copyright holder's, moved between
//! two FSL-1.1-ALv2 repositories, so nothing about its licence changed — only which binary it
//! compiles into.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Where the byte counts came from on macOS. Matches `burrow-cli/src/net.rs`'s
/// `MACOS_NETTOP_BYTES` and the golden's per-row `metric_source` verbatim; the macOS path sets no
/// `metric_note` (the golden has the key on no row) — see `ProcNet::metric_note`.
const MACOS_NETTOP_BYTES: &str = "macos_nettop_bytes";
/// The Windows IP Helper source and its caveat — burrow-cli's strings verbatim. Only the Windows
/// build (and every platform's tests) can produce a row that carries them.
#[cfg(any(windows, test))]
const WINDOWS_IPHELPER_CONNECTION_COUNT: &str = "windows_iphelper_connection_count";
#[cfg(any(windows, test))]
const WINDOWS_IPHELPER_NOTE: &str =
    "Windows IP Helper reports per-process connection counts; byte counters are unavailable in this mode.";
/// The Windows `netstat` fallback source and its caveat — burrow-cli's strings verbatim.
const WINDOWS_NETSTAT_CONNECTION_COUNT: &str = "windows_netstat_connection_count";
const WINDOWS_NETSTAT_NOTE: &str =
    "Windows netstat fallback reports per-process connection counts; byte counters are unavailable in this fallback.";

/// The subprocess seam every collector here spawns through: `(program, args)` → stdout, or why
/// not. Production passes [`system_runner`]; tests pass a fake, so the netstat path is driven on
/// every platform without a `netstat` binary.
pub type Runner<'a> = &'a dyn Fn(&str, &[&str]) -> Result<String, String>;

/// The real runner: spawn, wait, and hand back stdout — a non-zero exit is an error naming the
/// program, matching burrow-cli's `run_command`.
pub fn system_runner(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} exited {}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// One process's network byte usage this sample.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcNet {
    pub name: String,
    pub pid: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub total: u64,
    /// Where the numbers came from (e.g. `"macos_nettop_bytes"`). Always populated — both the
    /// golden and `NetModel.swift` carry it on every row.
    pub metric_source: String,
    /// Caveat when the source isn't byte counters (e.g. a Windows connection-count fallback).
    /// Always `None` on the macOS byte-counter path this engine collects, matching the golden
    /// (no `metric_note` key on any of its rows) and the original, whose macOS `parse_nettop`
    /// never sets it either. `to_json` omits the key entirely when this is `None`, mirroring the
    /// original's `#[serde(skip_serializing_if = "Option::is_none")]`.
    pub metric_note: Option<String>,
}

/// Parse `nettop -P -L 1 -x -J bytes_in,bytes_out` CSV. Rows are `name.pid,bytes_in,bytes_out,` —
/// the trailing `.pid` is split off the first column when it's all digits. Header/blank/comma-lead
/// rows are skipped. Sorted by total desc, then name, then pid. Pure.
pub fn parse_nettop(output: &str) -> Vec<ProcNet> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(',') || line.contains("bytes_in") {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 3 || f[0].is_empty() {
            continue;
        }
        let (name, pid) = match f[0].rsplit_once('.') {
            Some((n, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (n.to_string(), p.parse().unwrap_or(0))
            }
            _ => (f[0].to_string(), 0),
        };
        let bytes_in: u64 = f[1].trim().parse().unwrap_or(0);
        let bytes_out: u64 = f[2].trim().parse().unwrap_or(0);
        rows.push(ProcNet {
            name,
            pid,
            bytes_in,
            bytes_out,
            total: bytes_in + bytes_out,
            metric_source: MACOS_NETTOP_BYTES.to_string(),
            metric_note: None,
        });
    }
    sort_rows(&mut rows);
    rows
}

fn sort_rows(rows: &mut [ProcNet]) {
    rows.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Resolve the `nettop` binary at its fixed macOS location. Matches burrow-cli's
/// `resolve_nettop`: a missing/relocated binary fails loudly (a classified error the caller can
/// surface) instead of silently degrading to an empty report that looks identical to "no traffic".
pub fn resolve_nettop() -> Result<PathBuf, String> {
    let p = PathBuf::from("/usr/bin/nettop");
    if p.exists() {
        Ok(p)
    } else {
        Err("nettop not found (macOS only); per-app network is unavailable".into())
    }
}

/// Run one `nettop` sample through `run`. Byte-for-byte the same argv as burrow-cli's
/// `run_nettop` — do not change these flags. Measured on the reference machine: this takes ~30s
/// regardless of `-l`/`-s` values, and the original issues the identical argv, so the engine is
/// already at latency parity with the shipping app. That is a separate (non-)issue from the JSON
/// contract this module fixes.
pub fn run_nettop(bin: &Path, run: Runner<'_>) -> Result<String, String> {
    run(
        &bin.to_string_lossy(),
        &["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"],
    )
}

/// Collect per-process network usage — [`collect_with`] over the real runner.
pub fn collect() -> Result<Vec<ProcNet>, String> {
    collect_with(&system_runner)
}

/// Collect per-process network usage through `run`. macOS runs `nettop` and returns a classified
/// error if the binary is missing or exits non-zero; Windows tries IP Helper, then the
/// `netstat`/`tasklist` fallback, and reports both errors when both fail; every other platform
/// reports "unavailable" rather than a silent empty success. An empty `by_total_bytes` with
/// `ok:true` is indistinguishable from "this machine has no network traffic" and is exactly the
/// failure class this contract migration exists to remove.
pub fn collect_with(run: Runner<'_>) -> Result<Vec<ProcNet>, String> {
    if cfg!(windows) {
        return collect_windows(run);
    }
    if !cfg!(target_os = "macos") {
        return Err("per-app network is unavailable on this platform".into());
    }
    let bin = resolve_nettop()?;
    let out = run_nettop(&bin, run)?;
    Ok(parse_nettop(&out))
}

/// IP Helper first, `netstat` second, both failures named when neither works — burrow-cli's
/// `collect_windows`: [`collect_windows_via`] over the real native half.
fn collect_windows(run: Runner<'_>) -> Result<Vec<ProcNet>, String> {
    collect_windows_via(collect_windows_iphelper, run)
}

/// The fallback order with BOTH halves injected: `iphelper` is the native step, `run` the
/// subprocess seam the `netstat`/`tasklist` half spawns through. Production passes
/// [`collect_windows_iphelper`]; the test passes a failing fake, so the fallback order is
/// exercised hermetically on every platform — including a real Windows runner, where the native
/// half would otherwise answer with the machine's live connection table and the fake `netstat`
/// would never be reached.
fn collect_windows_via(
    iphelper: impl Fn(Runner<'_>) -> Result<Vec<ProcNet>, String>,
    run: Runner<'_>,
) -> Result<Vec<ProcNet>, String> {
    match iphelper(run) {
        Ok(rows) => Ok(rows),
        Err(iphelper_error) => match collect_windows_netstat(run) {
            Ok(rows) => Ok(rows),
            Err(netstat_error) => Err(format!(
                "Windows IP Helper failed: {iphelper_error}; netstat fallback failed: {netstat_error}"
            )),
        },
    }
}

/// `netstat -ano` counted per owning PID, named through `tasklist /fo csv /nh` (a missing
/// `tasklist` degrades to `pid:N` names, never to a failure).
fn collect_windows_netstat(run: Runner<'_>) -> Result<Vec<ProcNet>, String> {
    let netstat = run("netstat", &["-ano"])?;
    let tasklist = run("tasklist", &["/fo", "csv", "/nh"]).unwrap_or_default();
    Ok(parse_netstat(&netstat, &tasklist))
}

/// Parse `netstat -ano` (one TCP/UDP row per connection, PID last) + `tasklist /fo csv /nh` into
/// per-process connection counts, ranked by count. Pure; every row carries
/// `windows_netstat_connection_count` and its note.
pub fn parse_netstat(netstat: &str, tasklist: &str) -> Vec<ProcNet> {
    let names = parse_tasklist_names(tasklist);
    let mut counts: HashMap<u32, u64> = HashMap::new();
    for line in netstat.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let proto = fields[0].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        if let Some(pid) = fields.last().and_then(|s| s.parse::<u32>().ok()) {
            increment_pid_count(&mut counts, pid);
        }
    }
    rows_from_pid_counts(
        counts,
        &names,
        WINDOWS_NETSTAT_CONNECTION_COUNT,
        Some(WINDOWS_NETSTAT_NOTE),
    )
}

/// Per-PID connection counts → rows: `total` is the count, the byte fields are 0, and the name
/// comes from `tasklist` or degrades to `pid:N`. Shared by both Windows sources.
fn rows_from_pid_counts(
    counts: HashMap<u32, u64>,
    names: &HashMap<u32, String>,
    metric_source: &str,
    metric_note: Option<&str>,
) -> Vec<ProcNet> {
    let mut rows: Vec<ProcNet> = counts
        .into_iter()
        .map(|(pid, count)| ProcNet {
            name: names
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| format!("pid:{pid}")),
            pid,
            bytes_in: 0,
            bytes_out: 0,
            total: count,
            metric_source: metric_source.to_string(),
            metric_note: metric_note.map(str::to_string),
        })
        .collect();
    sort_rows(&mut rows);
    rows
}

fn increment_pid_count(counts: &mut HashMap<u32, u64>, pid: u32) {
    *counts.entry(pid).or_insert(0) += 1;
}

/// `tasklist /fo csv /nh` → PID → image name. Quoted CSV with `""` escapes, no header.
fn parse_tasklist_names(tasklist: &str) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for line in tasklist.lines() {
        let fields = parse_csv_line(line);
        if fields.len() < 2 {
            continue;
        }
        if let Ok(pid) = fields[1].parse::<u32>() {
            out.insert(pid, fields[0].clone());
        }
    }
    out
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// Native attribution: IP Helper's owner-PID tables for TCP and UDP over IPv4 and IPv6, counted
/// per PID and named through `tasklist`. Each table is read with the size-probe → allocate →
/// re-read dance the API requires (`ERROR_INSUFFICIENT_BUFFER` carries the needed size), bounded
/// to three attempts in case the table grows between the two calls, and every row count is
/// checked against the buffer before it is read.
#[cfg(windows)]
fn collect_windows_iphelper(run: Runner<'_>) -> Result<Vec<ProcNet>, String> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    type TableGetter = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, i32, u32) -> u32;

    struct TableBuffer {
        storage: Vec<usize>,
        len: usize,
    }

    fn read_table(
        label: &str,
        getter: TableGetter,
        address_family: u32,
        table_class: i32,
    ) -> Result<TableBuffer, String> {
        let mut size = 0u32;
        let mut buffer = TableBuffer {
            storage: Vec::new(),
            len: 0,
        };
        for _ in 0..3 {
            let ptr = if buffer.storage.is_empty() {
                std::ptr::null_mut()
            } else {
                buffer.storage.as_mut_ptr().cast()
            };
            // SAFETY: `ptr` is null (a size probe) or a buffer of `size` bytes we own; the API
            // writes at most `size` bytes and reports the size it needs otherwise.
            let status = unsafe { getter(ptr, &mut size, 0, address_family, table_class, 0) };
            match status {
                NO_ERROR => {
                    buffer.len = size as usize;
                    return Ok(buffer);
                }
                ERROR_INSUFFICIENT_BUFFER if size > 0 => {
                    let requested = size as usize;
                    let words = requested.div_ceil(std::mem::size_of::<usize>());
                    buffer.storage.resize(words, 0);
                    buffer.len = requested;
                }
                ERROR_INSUFFICIENT_BUFFER => {
                    return Err(format!("{label} requested a zero-byte table buffer"));
                }
                other => return Err(format!("{label} failed with Win32 error {other}")),
            }
        }
        Err(format!("{label} table size changed too often"))
    }

    fn table_count(buffer: &TableBuffer, label: &str) -> Result<usize, String> {
        if buffer.len == 0 {
            return Ok(0);
        }
        if buffer.len < std::mem::size_of::<u32>() {
            return Err(format!("{label} buffer is too small"));
        }
        // SAFETY: every `MIB_*TABLE_OWNER_PID` starts with a `u32` entry count, and the buffer
        // holds at least that many bytes (checked just above).
        let count = unsafe { *(buffer.storage.as_ptr().cast::<u32>()) };
        Ok(count as usize)
    }

    fn ensure_table_size<Row>(
        buffer: &TableBuffer,
        count: usize,
        label: &str,
    ) -> Result<(), String> {
        let needed = std::mem::size_of::<u32>()
            .checked_add(
                count
                    .checked_mul(std::mem::size_of::<Row>())
                    .ok_or_else(|| format!("{label} row count overflowed"))?,
            )
            .ok_or_else(|| format!("{label} table size overflowed"))?;
        if buffer.len < needed {
            return Err(format!("{label} buffer is too small for {count} rows"));
        }
        Ok(())
    }

    /// Count `count` rows of a table whose header is `Table` and whose rows carry `dwOwningPid`
    /// at the offset `pid_of` reads. One body for the four table shapes.
    fn add_counts<Table, Row>(
        buffer: &TableBuffer,
        label: &str,
        rows_of: unsafe fn(*const Table) -> *const Row,
        pid_of: fn(&Row) -> u32,
        counts: &mut HashMap<u32, u64>,
    ) -> Result<(), String> {
        let count = table_count(buffer, label)?;
        ensure_table_size::<Row>(buffer, count, label)?;
        if count == 0 {
            return Ok(());
        }
        let table = buffer.storage.as_ptr().cast::<Table>();
        // SAFETY: `ensure_table_size` proved the buffer holds the header plus `count` rows, and
        // `rows_of` points at the table's inline row array.
        let rows = unsafe { std::slice::from_raw_parts(rows_of(table), count) };
        for row in rows {
            increment_pid_count(counts, pid_of(row));
        }
        Ok(())
    }

    let mut counts = HashMap::new();
    let tcp4 = read_table(
        "TCP IPv4 owner table",
        GetExtendedTcpTable,
        u32::from(AF_INET),
        TCP_TABLE_OWNER_PID_ALL,
    )?;
    add_counts::<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(
        &tcp4,
        "TCP IPv4",
        |t| unsafe { (*t).table.as_ptr() },
        |r| r.dwOwningPid,
        &mut counts,
    )?;

    let tcp6 = read_table(
        "TCP IPv6 owner table",
        GetExtendedTcpTable,
        u32::from(AF_INET6),
        TCP_TABLE_OWNER_PID_ALL,
    )?;
    add_counts::<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(
        &tcp6,
        "TCP IPv6",
        |t| unsafe { (*t).table.as_ptr() },
        |r| r.dwOwningPid,
        &mut counts,
    )?;

    let udp4 = read_table(
        "UDP IPv4 owner table",
        GetExtendedUdpTable,
        u32::from(AF_INET),
        UDP_TABLE_OWNER_PID,
    )?;
    add_counts::<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(
        &udp4,
        "UDP IPv4",
        |t| unsafe { (*t).table.as_ptr() },
        |r| r.dwOwningPid,
        &mut counts,
    )?;

    let udp6 = read_table(
        "UDP IPv6 owner table",
        GetExtendedUdpTable,
        u32::from(AF_INET6),
        UDP_TABLE_OWNER_PID,
    )?;
    add_counts::<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(
        &udp6,
        "UDP IPv6",
        |t| unsafe { (*t).table.as_ptr() },
        |r| r.dwOwningPid,
        &mut counts,
    )?;

    let tasklist = run("tasklist", &["/fo", "csv", "/nh"]).unwrap_or_default();
    let names = parse_tasklist_names(&tasklist);
    Ok(rows_from_pid_counts(
        counts,
        &names,
        WINDOWS_IPHELPER_CONNECTION_COUNT,
        Some(WINDOWS_IPHELPER_NOTE),
    ))
}

/// Off Windows the native half does not exist; `collect_windows` falls through to `netstat`,
/// which is how the fallback order is exercised on every platform.
#[cfg(not(windows))]
fn collect_windows_iphelper(_run: Runner<'_>) -> Result<Vec<ProcNet>, String> {
    Err("Windows IP Helper is unavailable on this build".into())
}

/// Serialize the process list to the `by_total_bytes` contract (zero-dep, hand-written JSON):
/// `{"count":N,"by_total_bytes":[{name,pid,bytes_in,bytes_out,total,metric_source,metric_note?}]}`.
/// Root key and field names match `net.golden.json` and `NetModel.swift` (`origin/main`) — the
/// old root key `processes` decoded to a valid, permanently empty report. `count` is simply
/// `rows.len()`: the caller (`cli.rs`'s `net` arm) truncates to the requested `--limit` before
/// calling this, matching burrow-cli's `run_net`, so `count` already reflects the emitted rows.
pub fn to_json(rows: &[ProcNet]) -> String {
    use crate::json::escape as esc;
    let items = rows
        .iter()
        .map(|r| {
            // `metric_note` is omitted entirely when absent (never emitted as `null`), mirroring
            // the original's `#[serde(skip_serializing_if = "Option::is_none")]` — the loose
            // Swift decoder tolerates either, but an omitted key is the more faithful match.
            let note = r
                .metric_note
                .as_deref()
                .map(|n| format!(",\"metric_note\":{}", esc(n)))
                .unwrap_or_default();
            format!(
                "{{\"name\":{},\"pid\":{},\"bytes_in\":{},\"bytes_out\":{},\"total\":{},\"metric_source\":{}{}}}",
                esc(&r.name),
                r.pid,
                r.bytes_in,
                r.bytes_out,
                r.total,
                esc(&r.metric_source),
                note
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"count\":{},\"by_total_bytes\":[{}]}}",
        rows.len(),
        items
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;
    use std::collections::BTreeSet;

    /// The captured process-byte report shape with anonymized identities and counters. Tests
    /// load its fields directly; `scripts/check_fixtures.py` verifies the approved public copy.
    /// See `FIXTURE_PROVENANCE.md` before changing it.
    const GOLDEN_JSON: &str = include_str!("net.golden.json");

    #[test]
    fn parses_name_dot_pid_and_sorts_by_total() {
        let out = "\
,bytes_in,bytes_out,\n\
Spotify.541,1000,2000,\n\
kernel_task,50,50,\n\
Safari.883,9000,1000,\n";
        let rows = parse_nettop(out);
        // Header + the two named rows; kernel_task has no .pid so pid=0.
        assert_eq!(rows.len(), 3);
        // Sorted by total desc: Safari(10000) > Spotify(3000) > kernel_task(100).
        assert_eq!(rows[0].name, "Safari");
        assert_eq!(rows[0].pid, 883);
        assert_eq!(rows[0].total, 10000);
        assert_eq!(rows[1].name, "Spotify");
        assert_eq!(rows[1].pid, 541);
        let kt = rows.iter().find(|r| r.name == "kernel_task").unwrap();
        assert_eq!(kt.pid, 0, "no numeric suffix → pid 0, name kept whole");
        // Every row carries the macOS byte-counter source and no note, on every row — not just
        // the first — matching the golden (`metric_source: "macos_nettop_bytes"` on all 15 rows,
        // `metric_note` on none of them).
        for r in &rows {
            assert_eq!(r.metric_source, "macos_nettop_bytes");
            assert_eq!(r.metric_note, None);
        }
    }

    #[test]
    fn skips_headers_blanks_and_short_rows() {
        assert!(parse_nettop("").is_empty());
        assert!(parse_nettop(",bytes_in,bytes_out,\n\n").is_empty());
        assert!(parse_nettop("only,two\n").is_empty()); // < 3 fields
    }

    #[test]
    fn parses_sanitized_nettop_output() {
        // Preserve the captured format's edge cases while using fictional identities
        // and counters: an idle row, a dotted name, an .exe suffix and spaced names.
        let out = "\
,bytes_in,bytes_out,\n\
fixture-idle.1,0,0,\n\
fixture-video.1001,1200000,800000,\n\
org.example.network.1002,400000,100000,\n\
Fixture Helper.1003,1000,2000,\n\
example.exe.1004,50000,40000,\n\
Fixture Sharing.1005,4000,6000,\n";
        let rows = parse_nettop(out);
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[0].name, "fixture-video");
        assert_eq!(rows[0].pid, 1001);
        assert_eq!(rows[0].total, 2_000_000);
        assert_eq!(rows[1].name, "org.example.network");
        assert_eq!(rows[1].pid, 1002);
        assert_eq!(rows[1].total, 500_000);
        let executable = rows
            .iter()
            .find(|r| r.name == "example.exe")
            .expect("split on the LAST dot only — .exe stays part of the name, not the pid");
        assert_eq!(executable.pid, 1004);
        assert_eq!(executable.total, 90_000);
        let sharing = rows.iter().find(|r| r.name == "Fixture Sharing").unwrap();
        assert_eq!(sharing.pid, 1005);
        assert_eq!(sharing.total, 10_000);
        let helper = rows.iter().find(|r| r.name == "Fixture Helper").unwrap();
        assert_eq!(helper.pid, 1003);
        assert_eq!(helper.total, 3_000);
        let idle = rows.iter().find(|r| r.name == "fixture-idle").unwrap();
        assert_eq!(
            idle.pid, 1,
            "numeric suffix is retained for a zero-byte row"
        );
        assert_eq!(idle.total, 0);
        for r in &rows {
            assert_eq!(r.metric_source, MACOS_NETTOP_BYTES);
            assert_eq!(r.metric_note, None);
        }
    }

    #[test]
    fn to_json_matches_golden_contract_shape() {
        // Load and walk the vendored oracle itself rather than retyping its keys/values as
        // literals: a transposed character duplicated into both `to_json` and a hand-written
        // expectation would pass green here exactly as it did the first time this contract
        // shipped broken.
        let golden = crate::json::Json::parse(GOLDEN_JSON).expect("vendored golden must parse");
        let Json::Object(golden_top) = &golden else {
            panic!("golden root must be a JSON object");
        };
        let golden_top_keys: BTreeSet<&str> = golden_top.keys().map(String::as_str).collect();

        let golden_rows = golden
            .get("by_total_bytes")
            .and_then(Json::as_array)
            .expect("golden must have a by_total_bytes array to anchor against");
        assert!(
            !golden_rows.is_empty(),
            "golden must carry at least one row"
        );
        let golden_row = &golden_rows[0];
        let Json::Object(golden_row_map) = golden_row else {
            panic!("golden row must be a JSON object");
        };
        let golden_row_keys: BTreeSet<&str> = golden_row_map.keys().map(String::as_str).collect();

        // Build a ProcNet from the golden's OWN row-0 values — read back through the golden's own
        // accessors, never retyped as a literal — and round-trip it through this engine's
        // `to_json` and the engine's own JSON reader.
        let row = ProcNet {
            name: golden_row
                .get("name")
                .and_then(Json::as_str)
                .expect("golden row must have name")
                .to_string(),
            pid: golden_row
                .get("pid")
                .and_then(Json::as_u64)
                .expect("golden row must have pid") as u32,
            bytes_in: golden_row
                .get("bytes_in")
                .and_then(Json::as_u64)
                .expect("golden row must have bytes_in"),
            bytes_out: golden_row
                .get("bytes_out")
                .and_then(Json::as_u64)
                .expect("golden row must have bytes_out"),
            total: golden_row
                .get("total")
                .and_then(Json::as_u64)
                .expect("golden row must have total"),
            metric_source: golden_row
                .get("metric_source")
                .and_then(Json::as_str)
                .expect("golden row must have metric_source")
                .to_string(),
            metric_note: None,
        };
        let engine_json =
            crate::json::Json::parse(&to_json(&[row])).expect("to_json must emit valid JSON");
        let Json::Object(engine_top) = &engine_json else {
            panic!("engine output root must be a JSON object");
        };
        let engine_top_keys: BTreeSet<&str> = engine_top.keys().map(String::as_str).collect();
        // The root-key check IS the regression this whole migration exists to catch: the engine
        // used to emit `processes`, which NetModel.parse (reading only `by_total_bytes`) decodes
        // to a valid report with zero rows — no error, just a permanently empty pane.
        assert_eq!(
            engine_top_keys, golden_top_keys,
            "engine's top-level keys must match the golden's exactly"
        );

        let engine_row = &engine_json
            .get("by_total_bytes")
            .and_then(Json::as_array)
            .expect("engine must emit by_total_bytes")[0];
        let Json::Object(engine_row_map) = engine_row else {
            panic!("engine row must be a JSON object");
        };
        let engine_row_keys: BTreeSet<&str> = engine_row_map.keys().map(String::as_str).collect();
        assert_eq!(
            engine_row_keys, golden_row_keys,
            "engine's row keys must match the golden's exactly (no metric_note on this path)"
        );
        // Value-for-value against the golden's OWN row, iterating its keys rather than picking
        // them by hand.
        for key in golden_row_keys.iter().copied() {
            assert_eq!(
                engine_row.get(key),
                golden_row.get(key),
                "engine's {key} must match the golden's {key} verbatim"
            );
        }
    }

    #[test]
    fn to_json_emits_metric_note_only_when_present() {
        // Re-anchored to burrow-cli/src/net.rs's ACTUAL constants (lines 13, 17-18), not an
        // invented string. This engine cannot reach this path yet — the Windows netstat fallback
        // isn't ported (see `MACOS_NETTOP_BYTES`'s doc comment) — so this test exists purely to
        // prove `to_json`'s include-when-Some logic is correct for the day it is, anchored to a
        // value that is verifiably not made up rather than to prose I wrote myself.
        const WINDOWS_NETSTAT_CONNECTION_COUNT_FROM_ORIGINAL: &str =
            "windows_netstat_connection_count";
        const WINDOWS_NETSTAT_NOTE_FROM_ORIGINAL: &str = "Windows netstat fallback reports \
             per-process connection counts; byte counters are unavailable in this fallback.";
        let rows = vec![ProcNet {
            name: "x".into(),
            pid: 1,
            bytes_in: 0,
            bytes_out: 0,
            total: 0,
            metric_source: WINDOWS_NETSTAT_CONNECTION_COUNT_FROM_ORIGINAL.into(),
            metric_note: Some(WINDOWS_NETSTAT_NOTE_FROM_ORIGINAL.into()),
        }];
        let json = to_json(&rows);
        let parsed = crate::json::Json::parse(&json).expect("to_json must emit valid JSON");
        let row = &parsed
            .get("by_total_bytes")
            .and_then(crate::json::Json::as_array)
            .unwrap()[0];
        assert_eq!(
            row.get("metric_note").and_then(crate::json::Json::as_str),
            Some(WINDOWS_NETSTAT_NOTE_FROM_ORIGINAL)
        );
        assert_eq!(
            row.get("metric_source").and_then(crate::json::Json::as_str),
            Some(WINDOWS_NETSTAT_CONNECTION_COUNT_FROM_ORIGINAL)
        );
    }

    #[test]
    fn to_json_count_reflects_row_count_not_a_separate_total() {
        // `count` is simply `rows.len()` at serialization time, not a separately-tracked total —
        // anchor the row count itself to the golden (15) by loading it rather than hand-typing
        // that number, then prove the invariant holds at other lengths derived from those same
        // golden rows (all of them, all-but-one, and none), so this isn't just re-deriving N==N.
        let golden = Json::parse(GOLDEN_JSON).expect("vendored golden must parse");
        let golden_rows = golden
            .get("by_total_bytes")
            .and_then(Json::as_array)
            .expect("golden must carry by_total_bytes");
        let golden_count = golden
            .get("count")
            .and_then(Json::as_u64)
            .expect("golden must carry count");
        assert_eq!(
            golden_count as usize,
            golden_rows.len(),
            "golden's own count must equal its own row count — the invariant this test protects"
        );

        let rows: Vec<ProcNet> = golden_rows
            .iter()
            .map(|r| ProcNet {
                name: r
                    .get("name")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_string(),
                pid: r.get("pid").and_then(Json::as_u64).unwrap_or_default() as u32,
                bytes_in: r.get("bytes_in").and_then(Json::as_u64).unwrap_or_default(),
                bytes_out: r
                    .get("bytes_out")
                    .and_then(Json::as_u64)
                    .unwrap_or_default(),
                total: r.get("total").and_then(Json::as_u64).unwrap_or_default(),
                metric_source: r
                    .get("metric_source")
                    .and_then(Json::as_str)
                    .unwrap_or_default()
                    .to_string(),
                metric_note: None,
            })
            .collect();

        assert_eq!(
            Json::parse(&to_json(&rows))
                .unwrap()
                .get("count")
                .and_then(Json::as_u64),
            Some(golden_count)
        );
        assert_eq!(
            Json::parse(&to_json(&rows[..rows.len() - 1]))
                .unwrap()
                .get("count")
                .and_then(Json::as_u64),
            Some(golden_count - 1)
        );
        assert_eq!(
            Json::parse(&to_json(&[]))
                .unwrap()
                .get("count")
                .and_then(Json::as_u64),
            Some(0)
        );
    }
    // --- The Windows half, burrow-cli `src/net.rs` @ 5e71023's own tests, verbatim fixtures. ---

    #[test]
    fn parses_windows_netstat_tcp_and_udp_with_task_names() {
        let netstat = "\
Proto  Local Address          Foreign Address        State           PID\n\
TCP    127.0.0.1:5000         127.0.0.1:5001         ESTABLISHED     42\n\
TCP    127.0.0.1:5002         127.0.0.1:5003         ESTABLISHED     42\n\
UDP    0.0.0.0:5353           *:*                                    7\n";
        let tasklist = "\"chrome.exe\",\"42\",\"Console\",\"1\",\"10,000 K\"\n\"dns.exe\",\"7\",\"Console\",\"1\",\"1,000 K\"\n";
        let rows = parse_netstat(netstat, tasklist);
        assert_eq!(rows[0].name, "chrome.exe");
        assert_eq!(rows[0].pid, 42);
        assert_eq!(rows[0].bytes_in, 0);
        assert_eq!(rows[0].bytes_out, 0);
        assert_eq!(rows[0].total, 2);
        assert_eq!(rows[0].metric_source, WINDOWS_NETSTAT_CONNECTION_COUNT);
        assert_eq!(rows[0].metric_note.as_deref(), Some(WINDOWS_NETSTAT_NOTE));
        assert_eq!(rows[1].name, "dns.exe");
        assert_eq!(rows[1].total, 1);
    }

    #[test]
    fn parses_tasklist_csv_with_quoted_names_and_escaped_quotes() {
        let tasklist = "\"odd, name.exe\",\"101\",\"Console\",\"1\",\"10,000 K\"\n\
\"say \"\"hi\"\".exe\",\"202\",\"Console\",\"1\",\"2,000 K\"\n";
        let names = parse_tasklist_names(tasklist);
        assert_eq!(names.get(&101).map(String::as_str), Some("odd, name.exe"));
        assert_eq!(names.get(&202).map(String::as_str), Some("say \"hi\".exe"));
    }

    #[test]
    fn falls_back_to_pid_name_when_tasklist_is_missing() {
        let netstat = "\
TCP    127.0.0.1:5000         127.0.0.1:5001         ESTABLISHED     404\n";
        let rows = parse_netstat(netstat, "");
        assert_eq!(rows[0].name, "pid:404");
        assert_eq!(rows[0].pid, 404);
        assert_eq!(rows[0].metric_source, WINDOWS_NETSTAT_CONNECTION_COUNT);
    }

    #[test]
    fn sorts_connection_count_rows_by_total() {
        let netstat = "\
TCP    127.0.0.1:5000         127.0.0.1:5001         ESTABLISHED     1\n\
UDP    0.0.0.0:5353           *:*                                    2\n\
TCP    127.0.0.1:5002         127.0.0.1:5003         ESTABLISHED     2\n\
TCP    127.0.0.1:5004         127.0.0.1:5005         ESTABLISHED     2\n";
        let tasklist = "\"one.exe\",\"1\",\"Console\",\"1\",\"1 K\"\n\"two.exe\",\"2\",\"Console\",\"1\",\"1 K\"\n";
        let rows = parse_netstat(netstat, tasklist);
        assert_eq!(rows[0].pid, 2);
        assert_eq!(rows[0].total, 3);
        assert_eq!(rows[1].pid, 1);
        assert_eq!(rows[1].total, 1);
    }

    #[test]
    fn aggregates_iphelper_style_pid_rows_without_windows_api() {
        let names = HashMap::from([
            (42, "browser.exe".to_string()),
            (7, "resolver.exe".to_string()),
        ]);
        let mut counts = HashMap::new();
        for pid in [42, 42, 7, 42] {
            increment_pid_count(&mut counts, pid);
        }
        let rows = rows_from_pid_counts(
            counts,
            &names,
            WINDOWS_IPHELPER_CONNECTION_COUNT,
            Some(WINDOWS_IPHELPER_NOTE),
        );
        assert_eq!(rows[0].name, "browser.exe");
        assert_eq!(rows[0].pid, 42);
        assert_eq!(rows[0].bytes_in, 0);
        assert_eq!(rows[0].bytes_out, 0);
        assert_eq!(rows[0].total, 3);
        assert_eq!(rows[0].metric_source, WINDOWS_IPHELPER_CONNECTION_COUNT);
        assert_eq!(rows[0].metric_note.as_deref(), Some(WINDOWS_IPHELPER_NOTE));
        assert_eq!(rows[1].name, "resolver.exe");
        assert_eq!(rows[1].total, 1);
    }

    /// The Windows collector over a fake runner AND a fake native half: the netstat fallback is
    /// reached with the exact argv burrow-cli spawned, a missing `tasklist` costs names only, and
    /// a failed `netstat` names BOTH failures. The IP Helper step is injected as a refusal rather
    /// than left to the build's own — on a real Windows runner the real one answers with the live
    /// connection table (27 rows on CI, once) and the fallback under test is never reached.
    #[test]
    fn windows_collector_falls_back_to_netstat_and_names_both_failures() {
        let no_iphelper =
            |_: Runner<'_>| -> Result<Vec<ProcNet>, String> { Err("IP Helper refused".into()) };
        let calls = std::cell::RefCell::new(Vec::new());
        let runner = |p: &str, a: &[&str]| -> Result<String, String> {
            calls.borrow_mut().push(format!("{p} {}", a.join(" ")));
            match p {
                "netstat" => Ok("TCP 0.0.0.0:1 0.0.0.0:2 ESTABLISHED 9\n".into()),
                _ => Err("tasklist missing".into()),
            }
        };
        let rows = collect_windows_via(no_iphelper, &runner).expect("netstat fallback");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "pid:9");
        assert_eq!(rows[0].metric_source, WINDOWS_NETSTAT_CONNECTION_COUNT);
        assert!(calls.borrow().contains(&"netstat -ano".to_string()));
        assert!(calls.borrow().contains(&"tasklist /fo csv /nh".to_string()));

        let broken = |_: &str, _: &[&str]| -> Result<String, String> { Err("no such tool".into()) };
        let err = collect_windows_via(no_iphelper, &broken).expect_err("both halves failed");
        assert!(
            err.contains("Windows IP Helper failed: IP Helper refused"),
            "{err}"
        );
        assert!(
            err.contains("netstat fallback failed: no such tool"),
            "{err}"
        );
    }

    /// `metric_note` rides only when set: the Windows rows carry it, the macOS rows omit the key
    /// exactly as the golden does.
    #[test]
    fn to_json_emits_metric_note_only_on_rows_that_carry_one() {
        let rows = parse_netstat("UDP 0.0.0.0:1 *:* 3\n", "");
        let json = to_json(&rows);
        let parsed = Json::parse(&json).unwrap();
        let row = parsed
            .get("by_total_bytes")
            .and_then(Json::as_array)
            .unwrap()[0]
            .clone();
        assert_eq!(
            row.get("metric_note").and_then(Json::as_str),
            Some(WINDOWS_NETSTAT_NOTE)
        );
        assert_eq!(
            row.get("metric_source").and_then(Json::as_str),
            Some(WINDOWS_NETSTAT_CONNECTION_COUNT)
        );
        let golden = Json::parse(include_str!("net.golden.json")).unwrap();
        let golden_row = golden.get("by_total_bytes").unwrap().at(0).unwrap();
        let mut mac_row = rows[0].clone();
        mac_row.metric_source = MACOS_NETTOP_BYTES.to_string();
        mac_row.metric_note = None;
        let mac = Json::parse(&to_json(&[mac_row])).unwrap();
        assert_eq!(
            mac.get("by_total_bytes")
                .unwrap()
                .at(0)
                .unwrap()
                .get("metric_note"),
            golden_row.get("metric_note"),
        );
    }
}
