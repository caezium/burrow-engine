//! `uninstall --list` — the read-only app inventory the GUI's Software tab is built on.
//!
//! Ported from digger's `uninstall_list_apps` (`bin/uninstall.sh:1206`) and the scanner it reuses
//! (`scan_applications` → `_scan_discover_apps` → `uninstall_print_app_search_dirs`). The oracle
//! auto-switches to JSON when stdout is not a TTY (`bin/uninstall.sh:1222`, `[[ ! -t 1 ]]`); the
//! engine is always non-interactive, so JSON is the only mode here.
//!
//! # This command emits a BARE JSON ARRAY, not the Burrow envelope
//!
//! Every other engine command emits `{ok, burrow_cli, engine, command, data}`. This one must not.
//! The app hands this command's stdout straight to `MoleClient.parseApps`, which does
//! `JSONSerialization.jsonObject(...) as? [[String: Any]]` and returns `[]` for anything that is
//! not an array at the top level. Wrapping this in an envelope therefore produces an empty Software
//! tab and *no error anywhere* — the silent blank-pane failure this migration exists to stop.
//! `uninstall-list.golden.json` pins the shape; `to_json` is the only serializer and it never wraps.
//!
//! # `uninstall_name` is the point of the command
//!
//! It is the token `mo uninstall` accepts, which is the lowercase Homebrew cask token for
//! brew-managed apps and the display name for everything else. Substituting `name` can silently
//! lose the cask token, so the fixture covers both sources and their distinct token rules.
//!
//! # Which half of the golden this module relies on — the 1.42/1.46 mismatch, stated
//!
//! The original shape capture came from **mo 1.46.0**, GPL-era upstream, while this port's source
//! reference is the historical MIT fork at **V1.42.0**. See `FIXTURE_PROVENANCE.md` for the
//! distinction and the public fixture's anonymization.
//!
//! This module relies on the SHAPE and on the `uninstall_name` RULE, and BOTH are re-derived from
//! the 1.42 fork directly rather than taken from the 1.46 capture — `local
//! uninstall_name="${cask:-$app_name}"` at `bin/uninstall.sh:1240`, and the six-key `printf` at
//! `:1247`. The capture's seven rows are used as example INPUTS: fixture bundles to run the real
//! row builder over, and a `source`/`uninstall_name` pair per row to compare its answer against.
//!
//! The seven public rows describe fictional bundles. They establish neither an installed-app
//! inventory nor real bundle sizes. Tests of those behaviors need controlled bundles and an
//! independent reference capture.
//!
//! # This read can populate Homebrew's own cache
//!
//! `brew info --cask <token>` writes `$HOME/Library/Caches/Homebrew/api/cask/<token>.json`, which
//! makes a command with no `--apply` capable of writes. A fresh home may also receive Homebrew's
//! shared API and Ruby caches. Homebrew owns those files and controls subsequent refreshes.
//!
//! Dropping `brew info` would accept casks Homebrew cannot load. Setting
//! `HOMEBREW_NO_INSTALL_FROM_API=1` can reject valid casks whose taps are not cloned locally,
//! causing their inventory rows to lose the cask token. The port retains the original lookup
//! because suppressing those writes would change its ownership and token-resolution answers.

use crate::clean::format::kb_to_human;
use crate::clean::protect::should_protect_from_uninstall;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// One row of the inventory. Every field serializes as a JSON string, including `size`.
/// What `bundle_id` says when the bundle carries no `CFBundleIdentifier` at all.
///
/// **It is a SENTINEL, never an identifier.** `dedupe_by_bundle_id` deliberately skips rows carrying
/// it, so every one of them survives into the inventory, and `uninstall --list` prints it in the
/// `bundle_id` column — which makes it the natural thing for an agent to read off a listing and pass
/// straight back. Anything that resolves a caller's argument against `bundle_id` has to exclude it
/// (`resolve::match_apps_by_name` does) or `uninstall unknown` deletes whichever of those apps
/// happens to sort first.
pub const UNKNOWN_BUNDLE_ID: &str = "unknown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    /// Display name, resolved the way the oracle resolves it (Spotlight → `CFBundleDisplayName`
    /// → `CFBundleName` → bundle basename).
    pub name: String,
    /// Reverse-DNS id from `CFBundleIdentifier`, or [`UNKNOWN_BUNDLE_ID`] when the bundle has none.
    pub bundle_id: String,
    /// `"Homebrew"` when a cask token was resolved, else `"App"` — the only two values the oracle
    /// produces (`bin/uninstall.sh:1237-1238`).
    pub source: String,
    /// The token `uninstall` accepts: the cask token when brew-managed, else `name`.
    pub uninstall_name: String,
    /// Absolute path to the `.app`. NOT always `/Applications/<name>.app` — the scanner walks three
    /// levels deep, so `/Applications/Python 3.13/IDLE.app` is a normal row.
    pub path: String,
    /// Human size string (`"187KB"`, `"58.7MB"`), never a number. `"--"` when unknown.
    pub size: String,
}

/// Sort key + row, mirroring the oracle's `sort -t'|' -k1,1n` on the last-used epoch
/// (`bin/uninstall.sh:1058` → `_scan_finalize_index`). Least-recently-used first.
struct Ranked {
    epoch: i64,
    row: AppRow,
}

// ---------------------------------------------------------------------------------------------
// Serialization — the contract surface
// ---------------------------------------------------------------------------------------------

/// The oracle's JSON string escaper (`uninstall_list_json_escape`, `bin/uninstall.sh:1192`):
/// backslash and quote get escaped, and tab/CR/LF each collapse to a single space rather than
/// becoming `\t`/`\r`/`\n`.
///
/// Collapsing newlines rather than encoding them is deliberate upstream behaviour and worth
/// keeping: a multi-line value that survives into a consumer which builds a *path* out of it is
/// exactly how four directories whose names embed a newline and a fragment of this command's own
/// output ended up under `~/Library/Logs`. The collapse happens first; the quoting and every
/// other control character (`\u`-escaped, so the output is always parseable JSON) are the crate's
/// one escaper, `crate::json::escape`.
fn json_escape(s: &str) -> String {
    crate::json::escape(&s.replace(['\t', '\r', '\n'], " "))
}

/// Render the inventory as the oracle renders it: a bare top-level array, one object per row. Never
/// an envelope — see the module docs.
///
/// # The key ORDER is a citation, not something the golden pins
///
/// `name, bundle_id, source, uninstall_name, path, size` is transcribed from the oracle's `printf`
/// format string (`bin/uninstall.sh:1247`), which is in the SHIPPING 1.42 fork and can be reread
/// there. `uninstall-list.golden.json` cannot confirm it: whatever captured it re-serialized the
/// rows with the keys sorted alphabetically (`bundle_id, name, path, size, source, uninstall_name`),
/// so a test that loaded the golden and asserted this order would go red against a CORRECT
/// serializer. The order is also not load-bearing on the consuming side — `MoleClient.parseApps`
/// goes through `JSONSerialization` and reads by key — so it is matched here because matching the
/// original is free, and is deliberately left unpinned rather than pinned against the wrong source.
/// RULEBOOK §3e says the same thing from the other direction: do not assert the serializer's key
/// order as substring fragments, because that tests serde rather than the contract.
///
/// What the golden DOES pin, and what the tests below assert against it, is the key SET (six, all
/// strings), the bare-array top level, and the `source`/`uninstall_name` relationship.
pub fn to_json(rows: &[AppRow]) -> String {
    let mut out = String::from("[");
    for (i, r) in rows.iter().enumerate() {
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str(&format!(
            "  {{\"name\": {}, \"bundle_id\": {}, \"source\": {}, \"uninstall_name\": {}, \"path\": {}, \"size\": {}}}",
            json_escape(&r.name),
            json_escape(&r.bundle_id),
            json_escape(&r.source),
            json_escape(&r.uninstall_name),
            json_escape(&r.path),
            json_escape(&r.size),
        ));
    }
    if !rows.is_empty() {
        out.push('\n');
    }
    out.push_str("]\n");
    out
}

// ---------------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------------

/// The directories the oracle scans (`uninstall_print_app_search_dirs`, `bin/uninstall.sh:311`):
/// the two Applications folders, the two Input Methods folders, and every
/// `/Volumes/*/Applications` that is not just another mount of the first two.
pub fn search_dirs(home: &str) -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Applications"),
        PathBuf::from(format!("{home}/Applications")),
        PathBuf::from("/Library/Input Methods"),
        PathBuf::from(format!("{home}/Library/Input Methods")),
    ];
    let root_apps = same_file_key("/Applications");
    let home_apps = same_file_key(&format!("{home}/Applications"));
    if let Ok(vols) = std::fs::read_dir("/Volumes") {
        let mut found: Vec<PathBuf> = vols
            .flatten()
            .map(|e| e.path().join("Applications"))
            .filter(|p| p.is_dir())
            .collect();
        // read_dir order is filesystem-dependent; the oracle's glob is sorted.
        found.sort();
        for p in found {
            let key = same_file_key(&p.to_string_lossy());
            // The oracle's `-ef` test: skip a volume path that is the very same directory as
            // /Applications or ~/Applications (a bind mount or the boot volume itself).
            if key.is_some() && (key == root_apps || key == home_apps) {
                continue;
            }
            dirs.push(p);
        }
    }
    dirs
}

/// `(device, inode)` for a path — the oracle's `-ef` comparison, without following the last symlink
/// any differently than bash does.
///
/// `None` means "cannot answer", and the ONE call site ([`search_dirs`]) already treats it that way:
/// its `key.is_some() && …` guard skips a `/Volumes/*/Applications` only on POSITIVE same-file
/// knowledge, so an unanswerable key keeps the directory rather than dropping it. That is what makes
/// the non-unix arm below safe to be honest about instead of guessing.
#[cfg(unix)]
fn same_file_key(path: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

/// Off unix there is no stable-Rust `(device, inode)`: the Windows equivalent (volume serial number
/// plus file index) is still gated behind the unstable `windows_by_handle` feature. So this reports
/// "cannot answer" rather than fabricating a key — `search_dirs` then keeps every
/// `/Volumes/*/Applications` it finds, which on Windows is the empty set anyway (`/Volumes` does not
/// exist, so the `read_dir` never yields), making this arm unreachable in practice and merely
/// permissive if it ever is reached. It is deliberately NOT `canonicalize`-based: that would be a
/// different comparison from the oracle's `-ef`, invented here rather than ported.
#[cfg(not(unix))]
fn same_file_key(_path: &str) -> Option<(u64, u64)> {
    None
}

/// The oracle's `uninstall_should_skip_app_path` (`bin/uninstall.sh:340`): drop bundles nested
/// inside another `.app`, and drop symlinks that resolve into the system trees.
pub fn should_skip_app_path(app_path: &Path) -> bool {
    if !app_path.exists() && !app_path.is_symlink() {
        return true;
    }
    // Nested inside another bundle.
    if let Some(parent) = app_path.parent() {
        let p = parent.to_string_lossy();
        if p.ends_with(".app") || p.contains(".app/") {
            return true;
        }
    }
    if app_path.is_symlink() {
        if let Ok(target) = std::fs::read_link(app_path) {
            let resolved = if target.is_absolute() {
                target
            } else {
                app_path
                    .parent()
                    .map(|d| d.join(&target))
                    .unwrap_or(target.clone())
            };
            let r = resolved.to_string_lossy().to_string();
            for prefix in [
                "/System/",
                "/usr/bin/",
                "/usr/lib/",
                "/bin/",
                "/sbin/",
                "/private/etc/",
            ] {
                if r.starts_with(prefix) {
                    return true;
                }
            }
        }
    }
    false
}

/// Every `.app` under `dir` within `max_depth` levels, matching the oracle's
/// `find "$app_dir" -maxdepth 3 -name "*.app"` (`bin/uninstall.sh:469`).
///
/// Descent stops at a `.app` boundary. That is not a shortcut around the oracle: `find` does walk
/// into bundles, but every `.app` it turns up in there has a `.app` ancestor and is therefore
/// dropped by `should_skip_app_path`, so pruning yields the identical set for a fraction of the IO.
fn find_app_bundles(dir: &Path, max_depth: usize, out: &mut Vec<PathBuf>) {
    fn walk(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
        if depth > max_depth {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut kids: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        kids.sort();
        for path in kids {
            let is_app = path
                .file_name()
                .map(|n| n.to_string_lossy().ends_with(".app"))
                .unwrap_or(false);
            if is_app {
                out.push(path);
                continue; // do not descend into a bundle
            }
            // `symlink_metadata` so a symlinked directory is not followed, matching `find`.
            let is_dir = std::fs::symlink_metadata(&path)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            if is_dir && depth < max_depth {
                walk(&path, depth + 1, max_depth, out);
            }
        }
    }
    walk(dir, 1, max_depth, out);
}

// ---------------------------------------------------------------------------------------------
// Per-bundle metadata
// ---------------------------------------------------------------------------------------------

/// Run a command and capture trimmed stdout, or `None` if it could not run or exited non-zero.
///
/// UNBOUNDED, deliberately, and only for the calls where a stall costs ONE ROW. `plutil`, `du` and
/// `date` are each called from a worker thread that shares nothing with the other seven, so a wedge
/// in one of them degrades that app the way it degrades bash — the oracle bounds none of the three
/// either (`get_path_size_kb`, `lib/core/file_ops.sh:935-975`, calls `mdls` and `du` with no
/// `run_with_timeout` at all). The two calls where a stall costs the WHOLE SCAN — the `mdls` probe
/// the oracle DOES bound, and the `brew info` that is now serialised behind the memo lock — go
/// through [`capture_bounded`] instead.
fn capture(program: &str, args: &[&str]) -> Option<String> {
    crate::platform::run_command(program, args).map(|out| out.trim().to_string())
}

/// Why a bounded call came back empty. The distinction matters for `brew info`: a non-zero exit is
/// NORMAL (an untrusted tap makes Homebrew refuse, and the oracle's `|| return 1` reads that as
/// "this cask does not own the app"), whereas a deadline means the tool itself is wedged and the
/// next call will be too.
#[derive(Debug, PartialEq, Eq)]
enum Bounded {
    Ok(String),
    /// Ran and failed, or could not be spawned — the oracle's `|| return 1`.
    Failed,
    /// Still running when the deadline passed; killed.
    TimedOut,
}

/// [`capture`] with a deadline. Delegates to the crate's own bounded runner
/// ([`crate::status::collect::run_command_with_timeout`]), which drains stdout on a dedicated thread
/// so a chatty child cannot deadlock against a full pipe, and kills the child on expiry.
///
/// `Command::output()` blocks forever — there is no deadline in it — which is exactly how one stuck
/// subprocess became a Software tab that never loads.
fn capture_bounded(program: &str, args: &[&str], timeout: std::time::Duration) -> Bounded {
    let start = std::time::Instant::now();
    match crate::status::collect::run_command_with_timeout(program, args, timeout) {
        Some(out) => Bounded::Ok(out.trim().to_string()),
        // The runner collapses "killed at the deadline" and "exited non-zero" into the same `None`,
        // so the elapsed time is what separates them. Measuring it here rather than plumbing a new
        // return type through a module this change does not own.
        None if start.elapsed() >= timeout => Bounded::TimedOut,
        None => Bounded::Failed,
    }
}

/// A bounded call with one environment variable set, spelled the way the ORACLE spells it: prefix
/// the command with `env KEY=VALUE` rather than teaching the timeout helper about environments.
/// `bin/uninstall.sh:71` is literally `run_with_timeout "$TIMEOUT" env LC_ALL="…" LANG="…" mdls …`
/// for the same reason — its `run_with_timeout` takes a command line, not an environment.
///
/// The variable is `HOMEBREW_NO_ENV_HINTS=1`, which the oracle sets on every Homebrew call
/// (`lib/uninstall/brew.sh:123`, `:159`) so hint text cannot end up parsed as output.
fn capture_env_bounded(
    program: &str,
    args: &[&str],
    key: &str,
    value: &str,
    timeout: std::time::Duration,
) -> Bounded {
    let assignment = format!("{key}={value}");
    let mut argv: Vec<&str> = vec![assignment.as_str(), program];
    argv.extend_from_slice(args);
    capture_bounded("env", &argv, timeout)
}

/// The oracle's field sanitiser: `|` becomes `-` (it is the scanner's record separator) and
/// tab/CR/LF are stripped (`uninstall_resolve_bundle_id`, `bin/uninstall.sh:379`).
fn sanitize(s: &str) -> String {
    s.replace('|', "-")
        .replace(['\t', '\r', '\n'], "")
        .trim()
        .to_string()
}

/// What `Contents/Info.plist` contributes to a row.
#[derive(Default)]
struct PlistInfo {
    bundle_id: String,
    display_name: String,
    bundle_name: String,
    background_only: bool,
}

/// Read the four keys the scanner needs out of `Info.plist` in ONE `plutil` call.
///
/// The oracle shells out to `plutil -extract <key> raw` once per key; converting the whole plist to
/// JSON once and reading it with the engine's own parser is the same source of truth for a quarter
/// of the process spawns. `plutil` is still what decodes the (usually binary) plist, so this does
/// not reimplement Apple's format.
fn read_plist(app_path: &Path) -> PlistInfo {
    let plist = app_path.join("Contents/Info.plist");
    if !plist.is_file() {
        return PlistInfo::default();
    }
    let Some(text) = capture(
        "plutil",
        &["-convert", "json", "-o", "-", &plist.to_string_lossy()],
    ) else {
        return PlistInfo::default();
    };
    let Ok(json) = crate::json::Json::parse(&text) else {
        return PlistInfo::default();
    };
    let s = |k: &str| {
        json.get(k)
            .and_then(|v| v.as_str())
            .map(sanitize)
            .unwrap_or_default()
    };
    // `LSBackgroundOnly` is written as a boolean by some apps and as "1"/"YES"/"true" by others;
    // the oracle accepts all of them (`uninstall_app_is_background_only`, `bin/uninstall.sh:400`).
    let background_only = json
        .get("LSBackgroundOnly")
        .map(|v| match v.as_bool() {
            Some(b) => b,
            None => matches!(
                v.as_str().unwrap_or("").trim(),
                "1" | "YES" | "yes" | "TRUE" | "true"
            ),
        })
        .unwrap_or(false);
    PlistInfo {
        bundle_id: s("CFBundleIdentifier"),
        display_name: s("CFBundleDisplayName"),
        bundle_name: s("CFBundleName"),
        background_only,
    }
}

/// What Spotlight contributes: the localized display name, the logical size, and the last-used
/// date. The oracle asks `mdls` for these separately; one call returns all three.
#[derive(Default)]
struct MdlsInfo {
    display_name: String,
    logical_size: u64,
    last_used_epoch: i64,
}

/// The budget for the one `mdls` call, summed from the two the oracle bounds and this call replaces:
/// 0.04 s for the display name (`bin/uninstall.sh:41`, spent at `:71-75`) and 0.2 s for the
/// last-used date (`:237`). Both exist because a cold Spotlight stalls, and the oracle would rather
/// fall back to the plist and the bundle mtime than wait per app across a whole `/Applications`.
///
/// Calibrated against a live run rather than left as arithmetic: on this machine, under the same
/// eight-way fan-out `collect_from_dirs` uses, 40 real bundles measured min 50 ms / p50 91 ms /
/// p95 115 ms / max 124 ms — so this is ~2× the worst observed healthy call.
///
/// It is TIGHTER than the oracle for the third attribute. `kMDItemLogicalSize` is asked for here
/// too, and the oracle's size probe (`get_path_size_kb`, `lib/core/file_ops.sh:946`) has no timeout
/// at all — merging three probes into one process means one budget has to cover all three, and the
/// loosest of the three is what produced the unbounded hang. The cost of being wrong is the ORACLE'S
/// OWN fallback, not a wrong answer: an empty result sends the display name to `CFBundleDisplayName`
/// (`resolve_display_name`), the epoch to the bundle mtime, and the size to `du -skP` — measured at
/// 36-102 ms for typical bundles and 2.4 s for Xcode.
const MDLS_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(240);

fn read_mdls(app_path: &Path) -> MdlsInfo {
    let Bounded::Ok(text) = capture_bounded(
        "mdls",
        &[
            "-name",
            "kMDItemDisplayName",
            "-name",
            "kMDItemLastUsedDate",
            "-name",
            "kMDItemLogicalSize",
            &app_path.to_string_lossy(),
        ],
        MDLS_TIMEOUT,
    ) else {
        return MdlsInfo::default();
    };
    let mut info = MdlsInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if value.is_empty() || value == "(null)" {
            continue;
        }
        match key {
            "kMDItemDisplayName" => info.display_name = sanitize(value),
            "kMDItemLogicalSize" => info.logical_size = value.parse().unwrap_or(0),
            "kMDItemLastUsedDate" => info.last_used_epoch = parse_mdls_date(value),
            _ => {}
        }
    }
    info
}

/// `mdls` prints dates as `2026-08-06 12:34:56 +0000`. Converted to a Unix epoch by the same
/// `date -j -f` the oracle uses (`bin/uninstall.sh:239`) — only the ordering matters here, and
/// shelling out for it keeps the calendar arithmetic in one place instead of hand-rolling it.
fn parse_mdls_date(value: &str) -> i64 {
    capture("date", &["-j", "-f", "%Y-%m-%d %H:%M:%S %z", value, "+%s"])
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The oracle's `get_path_size_kb` for a bundle (`lib/core/file_ops.sh:935`): Spotlight's logical
/// size, because `du` severely underreports APFS-cloned bundles, falling back to `du -skP`.
fn size_kb(app_path: &Path, logical_size: u64) -> u64 {
    if logical_size > 0 {
        return logical_size / 1024;
    }
    capture("du", &["-skP", &app_path.to_string_lossy()])
        .and_then(|s| {
            s.lines()
                .next()
                .and_then(|l| l.split_whitespace().next().map(str::to_string))
        })
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// The oracle's display-name precedence (`uninstall_resolve_display_name`, `bin/uninstall.sh`):
/// Spotlight's name when it exists and differs from the bundle basename, else `CFBundleDisplayName`,
/// else `CFBundleName`, else the basename — plus the rule that keeps a versioned bundle name when
/// the metadata would collapse two distinct installs onto one label.
fn resolve_display_name(app_name: &str, plist: &PlistInfo, mdls: &MdlsInfo) -> String {
    let mut display = app_name.to_string();
    let md = if mdls.display_name.starts_with('/') {
        ""
    } else {
        mdls.display_name.as_str()
    };
    if !md.is_empty() && md != app_name {
        display = md.to_string();
    } else if !plist.display_name.is_empty() {
        display = plist.display_name.clone();
    } else if !plist.bundle_name.is_empty() {
        display = plist.bundle_name.clone();
    }
    if display.starts_with('/') {
        display = app_name.to_string();
    }
    // "Keep versioned bundle names when metadata collapses distinct installs": if the bundle
    // basename merely extends the resolved name and the extra part contains a digit
    // ("Python Launcher" vs "Python Launcher 3.13"), the basename is the more useful label.
    if !display.is_empty() && app_name.starts_with(&display) && app_name != display {
        let suffix = &app_name[display.len()..];
        if suffix.chars().any(|c| c.is_ascii_digit()) {
            display = app_name.to_string();
        }
    }
    let display = display.strip_suffix(".app").unwrap_or(&display).to_string();
    sanitize(&display)
}

// ---------------------------------------------------------------------------------------------
// Homebrew cask resolution
// ---------------------------------------------------------------------------------------------

/// The budget for one `brew info --cask`. No oracle bounds this call, so the number comes from the
/// oracle's own timeout TABLE instead: `MOLE_TIMEOUT_PKG_LIST_SEC` (`lib/core/timeouts.sh:63`), the
/// bucket it documents as "Package manager listing (brew list, simctl list). ~10s" — the same class
/// of command, chosen by upstream for the same reason.
///
/// Measured warm on this machine at 0.40-0.92 s per token, so this is >10× the observed healthy
/// call and will not cut one short. It has to be that generous: a `brew info` that fails reads as
/// "this cask does not own the app" (the oracle's `|| return 1`), so an over-tight bound would
/// silently demote real Homebrew rows to `App` — the exact failure the memo lock exists to prevent.
/// The total cost of a wedged Homebrew is bounded by [`CaskIndex::brew_wedged`], not by this.
const BREW_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Everything the cask stages need, gathered once instead of per app.
///
/// The oracle runs `brew list --cask`, a `find` over the Caskroom, and a `brew info --cask` *per
/// application* (`lib/uninstall/brew.sh:177`). Over 138 apps that is hundreds of Homebrew
/// invocations. The inputs do not change during a scan, so they are collected once here; the
/// per-app decision below still follows the oracle's stage order.
pub struct CaskIndex {
    /// Tokens `brew list --cask` reports as installed.
    installed: HashSet<String>,
    /// Bundle basename (`Bitwarden.app`) → the cask tokens whose Caskroom contains it.
    by_bundle: HashMap<String, BTreeSet<String>>,
    /// `brew info --cask <token>` output, memoised. `None` means the call failed, which the oracle
    /// treats as "this cask does not own the app" rather than as a detail to shrug off.
    info: std::sync::Mutex<HashMap<String, Option<String>>>,
    available: bool,
    /// Set once a `brew info` hits its deadline, after which no further `brew` is spawned for the
    /// rest of the scan. A per-call timeout alone does not bound this: `brew` is called once per
    /// candidate token and every call is serialised behind `info`, so repeated deadlines can
    /// exceed the caller's overall scan budget. Once a call misses its deadline, later rows
    /// avoid repeating that wait.
    ///
    /// A non-zero EXIT does not trip it, only a deadline — see [`Bounded`]. Untrusted-tap refusals
    /// are ordinary and expected, and treating those as "Homebrew is down"
    /// would disable cask resolution for everyone who taps anything.
    brew_wedged: std::sync::atomic::AtomicBool,
}

impl CaskIndex {
    /// Build the index. Cheap and total: with no Homebrew installed every lookup returns `None`
    /// and every row is a plain `"App"`, exactly as the oracle degrades (`is_homebrew_available`).
    pub fn build() -> CaskIndex {
        let available = which("brew");
        if !available {
            return CaskIndex {
                installed: HashSet::new(),
                by_bundle: HashMap::new(),
                info: std::sync::Mutex::new(HashMap::new()),
                available: false,
                brew_wedged: std::sync::atomic::AtomicBool::new(false),
            };
        }
        let installed: HashSet<String> = capture("brew", &["list", "--cask"])
            .map(|s| s.lines().map(|l| l.trim().to_string()).collect())
            .unwrap_or_default();
        let mut by_bundle: HashMap<String, BTreeSet<String>> = HashMap::new();
        for room in ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"] {
            let root = Path::new(room);
            if !root.is_dir() {
                continue;
            }
            // The oracle's `find "$room" -maxdepth 3 -name "$app_bundle_name"`, inverted: walk the
            // Caskroom once and index what is there, rather than re-walking it for every app.
            let Ok(tokens) = std::fs::read_dir(root) else {
                continue;
            };
            for token_dir in tokens.flatten() {
                let token = token_dir.file_name().to_string_lossy().to_string();
                if !valid_cask_token(&token) {
                    continue;
                }
                let Ok(versions) = std::fs::read_dir(token_dir.path()) else {
                    continue;
                };
                for version in versions.flatten() {
                    let Ok(artifacts) = std::fs::read_dir(version.path()) else {
                        continue;
                    };
                    for artifact in artifacts.flatten() {
                        let name = artifact.file_name().to_string_lossy().to_string();
                        if name.ends_with(".app") {
                            by_bundle.entry(name).or_default().insert(token.clone());
                        }
                    }
                }
            }
        }
        CaskIndex {
            installed,
            by_bundle,
            info: std::sync::Mutex::new(HashMap::new()),
            available,
            brew_wedged: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// `brew info --cask <token>`, memoised per token. `None` when the call fails.
    ///
    /// It fails more often than one might expect: a cask from an untrusted tap makes Homebrew
    /// refuse outright, and the oracle's `|| return 1` treats that as a non-match. Accepting that
    /// failed lookup would report an app as `Homebrew` with a token that `brew` cannot load.
    ///
    /// # One at a time — concurrent `brew info` calls destroy each other on a cold cache
    ///
    /// The memo lock is held ACROSS the spawn, not just around the map, so at most one `brew` runs
    /// at a time. That is not tidiness. This engine resolves rows on a pool of up to eight threads
    /// where the oracle loops serially, and on a Homebrew cache with no API bundle yet, eight
    /// concurrent `brew info --cask` calls race to download the same file and all of them fail:
    ///
    /// ```text
    /// Error: Cannot download non-corrupt https://formulae.brew.sh/api/internal/packages…jws.json
    /// ✘ JSON API packages.arm64_tahoe.jws.json  Error: No such file or directory @ dir_s_rmdir
    /// Error: Failed to verify integrity (signature mismatch) of: https://formulae.brew.sh/…
    /// ```
    ///
    /// Reproduced 8-for-8 against a fresh `HOME`. Every failure reads as "this cask does not own
    /// the app", so EVERY Homebrew row degrades to `source: "App"` with `uninstall_name` set to the
    /// display name instead of the cask token — the exact substitution this module's header warns
    /// silently misfires, firing for 100% of brew-managed apps instead of 9%. Serialised, the first
    /// call populates the cache and the rest are memo hits or warm reads.
    ///
    /// # …which is exactly why it now has a deadline
    ///
    /// Serialising it made a single stuck `brew` everybody's problem: the lock is held across the
    /// spawn, so all eight workers inside `collect_from_dirs`'s `thread::scope` queue behind it and
    /// `--list` emits nothing until `MoEngine.capture`'s 180 s timeout kills the process and the
    /// Software tab goes `.unavailable`. Bash has no `brew` timeout either
    /// (`lib/uninstall/brew.sh:123`, `:159` are bare command substitutions), so the unbounded call
    /// is not itself a divergence — but bash loops serially, where one slow row costs one row. The
    /// concurrency fix is what turned that into the whole scan, so the bound belongs with it.
    fn brew_info(&self, token: &str) -> Option<String> {
        use std::sync::atomic::Ordering;
        if self.brew_wedged.load(Ordering::SeqCst) {
            return None;
        }
        let wedged = &self.brew_wedged;
        self.brew_info_with(token, |t| {
            match capture_env_bounded(
                "brew",
                &["info", "--cask", t],
                "HOMEBREW_NO_ENV_HINTS",
                "1",
                BREW_INFO_TIMEOUT,
            ) {
                Bounded::Ok(out) => Some(out),
                Bounded::Failed => None,
                Bounded::TimedOut => {
                    wedged.store(true, Ordering::SeqCst);
                    None
                }
            }
        })
    }

    /// [`Self::brew_info`] with the subprocess call injected — the seam that lets a test observe
    /// how many run at once without a real Homebrew. `run` is invoked with the memo lock held; that
    /// IS the behaviour under test.
    ///
    /// A POISONED mutex is recovered from, not treated as a miss. `lock().ok()?` returned `None` the
    /// moment any worker panicked while holding this lock — and `cask_owns_app` reads `None` as
    /// "this cask does not own the app", so one panic anywhere in the pool turned EVERY subsequent
    /// Homebrew row into `source: "App"` with the display name in `uninstall_name`. That is the same
    /// 0-of-9 failure the lock was added to fix, arriving through a different door and just as
    /// silently. The guarded value is a memo of subprocess output — a panic cannot leave it in a
    /// state that means anything different — so `into_inner` is safe here and is the difference
    /// between a crash that costs one row and one that quietly corrupts the whole answer.
    fn brew_info_with(
        &self,
        token: &str,
        run: impl FnOnce(&str) -> Option<String>,
    ) -> Option<String> {
        let mut guard = self.info.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = guard.get(token) {
            return hit.clone();
        }
        let fresh = run(token);
        guard.insert(token.to_string(), fresh.clone());
        fresh
    }

    /// The oracle's ownership check, shared by stages 2 and 4 (`lib/uninstall/brew.sh:122` and
    /// `:160`): `brew info` must succeed, and its output must mention the app path, the app under
    /// `/Applications`, or the bundle name.
    fn cask_owns_app(&self, token: &str, app_path: &Path, bundle_name: &str) -> bool {
        let Some(info) = self.brew_info(token) else {
            return false;
        };
        let path = app_path.to_string_lossy();
        info.contains(path.as_ref())
            || info.contains(&format!("/Applications/{bundle_name}"))
            || info.contains(bundle_name)
    }

    /// The cask token that owns `app_path`, following the oracle's stage order
    /// (`get_brew_cask_name`, `lib/uninstall/brew.sh:177`): fully-resolved path inside a Caskroom,
    /// then a Caskroom search by bundle name, then a direct symlink into a Caskroom, then a
    /// name match against the installed cask list.
    pub fn token_for(&self, app_path: &Path) -> Option<String> {
        if !self.available {
            return None;
        }
        let bundle_name = app_path.file_name()?.to_string_lossy().to_string();

        // Stage 1 — the resolved path is itself inside a Caskroom.
        if let Ok(resolved) = std::fs::canonicalize(app_path) {
            if let Some(t) = cask_token_from_path(&resolved.to_string_lossy()) {
                return Some(t);
            }
        }

        // Stage 2 — exactly one installed cask ships this bundle name, and `brew info` confirms
        // that cask really owns it. "Exactly one" is the oracle's guard against uninstalling the
        // wrong cask when two ship the same bundle name.
        if let Some(tokens) = self.by_bundle.get(&bundle_name) {
            if tokens.len() == 1 {
                let t = tokens.iter().next().expect("len checked");
                if self.installed.contains(t) && self.cask_owns_app(t, app_path, &bundle_name) {
                    return Some(t.clone());
                }
            }
        }

        // Stage 3 — the app is a direct symlink into a Caskroom.
        if let Ok(target) = std::fs::read_link(app_path) {
            if let Some(t) = cask_token_from_path(&target.to_string_lossy()) {
                return Some(t);
            }
        }

        // Stage 4 — the bundle basename, lowercased, is an installed cask token, verified the same
        // way. The oracle matches case-insensitively against the installed list.
        let lowered = bundle_name
            .strip_suffix(".app")
            .unwrap_or(&bundle_name)
            .to_lowercase();
        if let Some(t) = self
            .installed
            .iter()
            .find(|t| t.to_lowercase() == lowered)
            .cloned()
        {
            if self.cask_owns_app(&t, app_path, &bundle_name) {
                return Some(t);
            }
        }
        None
    }
}

/// Is `program` on PATH? The oracle's `command -v`.
fn which(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let p = dir.join(program);
                std::fs::metadata(&p).map(|m| m.is_file()).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// The oracle's `_extract_cask_token_from_path` (`lib/uninstall/brew.sh:57`): the first component
/// after `Caskroom/`, and only when it looks like a cask token.
fn cask_token_from_path(path: &str) -> Option<String> {
    let rest = ["/opt/homebrew/Caskroom/", "/usr/local/Caskroom/"]
        .iter()
        .find_map(|p| path.strip_prefix(p))?;
    let token = rest.split('/').next()?;
    valid_cask_token(token).then(|| token.to_string())
}

/// `^[a-z0-9][a-z0-9-]*$` — the oracle's token shape.
fn valid_cask_token(token: &str) -> bool {
    let mut chars = token.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ---------------------------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------------------------

/// Scan the given directories and build the inventory. Split out from [`collect`] so the walker and
/// the row-building can be exercised against a fixture tree instead of the real `/Applications`.
pub fn collect_from_dirs(dirs: &[PathBuf]) -> Vec<AppRow> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        find_app_bundles(dir, 3, &mut candidates);
    }
    candidates.retain(|p| !should_skip_app_path(p));

    let index = CaskIndex::build();

    // Metadata resolution is IO-bound subprocess work (`plutil`, `mdls`, sometimes `du`) and the
    // oracle fans it out too (`_scan_resolve_uncached`). Chunked across a small fixed pool: this is
    // the difference between a Software tab that loads and one that trips the app's timeout.
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 8))
        .unwrap_or(4);
    let chunk = candidates.len().div_ceil(workers.max(1)).max(1);
    let mut ranked: Vec<Ranked> = Vec::with_capacity(candidates.len());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for slice in candidates.chunks(chunk) {
            let index = &index;
            handles.push(scope.spawn(move || {
                slice
                    .iter()
                    .filter_map(|p| build_row(p, index))
                    .collect::<Vec<Ranked>>()
            }));
        }
        for h in handles {
            if let Ok(rows) = h.join() {
                ranked.extend(rows);
            }
        }
    });

    dedupe_by_bundle_id(&mut ranked);

    // The oracle's `sort -t'|' -k1,1n` on the last-used epoch: least-recently-used first. Ties keep
    // discovery order, which is the sorted directory walk above, so the result is deterministic.
    ranked.sort_by_key(|r| r.epoch);
    ranked.into_iter().map(|r| r.row).collect()
}

/// Resolve one bundle into a row, or drop it if the oracle's eligibility gate rejects it
/// (`uninstall_app_is_currently_eligible`, `bin/uninstall.sh:431`).
fn build_row(app_path: &Path, index: &CaskIndex) -> Option<Ranked> {
    let app_name = app_path
        .file_name()?
        .to_string_lossy()
        .strip_suffix(".app")
        .unwrap_or_default()
        .to_string();
    if app_name.is_empty() {
        return None;
    }
    let plist = read_plist(app_path);
    let bundle_id = if plist.bundle_id.is_empty() || plist.bundle_id == "(null)" {
        UNKNOWN_BUNDLE_ID.to_string()
    } else {
        plist.bundle_id.clone()
    };

    // Eligibility, in the oracle's order: a system-critical bundle is not listed at all, and neither
    // is a background-only agent (which has no UI to uninstall) unless it is top-level OneDrive.
    if bundle_id != UNKNOWN_BUNDLE_ID && should_protect_from_uninstall(&bundle_id) {
        return None;
    }
    if plist.background_only && !is_top_level_onedrive(app_path, &bundle_id) {
        return None;
    }

    let mdls = read_mdls(app_path);
    let name = resolve_display_name(&app_name, &plist, &mdls);
    let kb = size_kb(app_path, mdls.logical_size);
    // `human_size` in the oracle's awk returns "--" for a non-positive size, and
    // `uninstall_normalize_size_display` leaves "--" alone (`bin/uninstall.sh:43`).
    let size = if kb > 0 {
        kb_to_human(kb)
    } else {
        "--".to_string()
    };

    let cask = index.token_for(app_path);
    let source = if cask.is_some() { "Homebrew" } else { "App" };
    let uninstall_name = cask.unwrap_or_else(|| name.clone());

    // The oracle falls back to the bundle's mtime when there is no last-used date, so a
    // never-launched app still sorts by how long it has sat there.
    let epoch = if mdls.last_used_epoch > 0 {
        mdls.last_used_epoch
    } else {
        mtime_epoch(app_path)
    };

    Some(Ranked {
        epoch,
        row: AppRow {
            name,
            bundle_id,
            source: source.to_string(),
            uninstall_name,
            path: app_path.to_string_lossy().to_string(),
            size,
        },
    })
}

/// `uninstall_app_is_top_level_onedrive` (`bin/uninstall.sh:416`) — the one background-only bundle
/// the oracle still lists, because users genuinely want to remove it.
fn is_top_level_onedrive(app_path: &Path, bundle_id: &str) -> bool {
    if !bundle_id.starts_with("com.microsoft.OneDrive") {
        return false;
    }
    // Degrades: with no home the `~/Applications` spelling simply never matches, and the
    // `/Applications` one still does. Routed through `platform::home_dir` rather than `HOME`
    // directly so the match works on Windows too, where `USERPROFILE` holds the answer.
    let home = crate::platform::home_dir().unwrap_or_default();
    let p = app_path.to_string_lossy();
    p == "/Applications/OneDrive.app" || p == format!("{home}/Applications/OneDrive.app")
}

/// Modification time as unix epoch seconds, `0` when it cannot be read — the last-used fallback for
/// a bundle Spotlight has no `kMDItemLastUsedDate` for.
///
/// unix keeps the raw `st_mtime` (`MetadataExt::mtime`) so this side does not change at all.
#[cfg(unix)]
fn mtime_epoch(path: &Path) -> i64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.mtime()).unwrap_or(0)
}

/// Off unix, `Metadata::modified()` is a REAL equivalent rather than a degradation: it is the same
/// modification timestamp, just delivered as a `SystemTime` instead of a raw `st_mtime` field, and
/// it is populated on every Windows filesystem the engine could run on. It is not used on unix only
/// because `st_mtime` is already exactly the integer this returns, and routing the existing platform
/// through a `SystemTime` conversion would be a behaviour change (pre-1970 mtimes take the `Err`
/// arm) for no gain.
#[cfg(not(unix))]
fn mtime_epoch(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The oracle's `_scan_dedupe_bundle_ids`: one row per bundle id, keeping the best-ranked copy —
/// directly under `/Applications` beats directly under `~/Applications`, which beats anywhere else,
/// which beats `/Volumes`. Rows with no usable bundle id are all kept, since there is nothing to
/// dedupe them by.
fn dedupe_by_bundle_id(rows: &mut Vec<Ranked>) {
    // Degrades: an unknown home only collapses the `~/Applications` RANK into the catch-all tier,
    // which changes which duplicate wins, never whether a row survives.
    let home = crate::platform::home_dir().unwrap_or_default();
    let home_apps = format!("{home}/Applications/");
    let rank = |path: &str| -> u8 {
        let direct_under = |prefix: &str| {
            path.strip_prefix(prefix)
                .map(|rest| !rest.contains('/') && rest.ends_with(".app"))
                .unwrap_or(false)
        };
        if direct_under("/Applications/") {
            1
        } else if direct_under(&home_apps) {
            2
        } else if path.starts_with("/Volumes/") {
            4
        } else {
            3
        }
    };
    let mut best: HashMap<String, usize> = HashMap::new();
    let mut drop: Vec<bool> = vec![false; rows.len()];
    for i in 0..rows.len() {
        let bid = rows[i].row.bundle_id.clone();
        if bid.is_empty() || bid == UNKNOWN_BUNDLE_ID {
            continue;
        }
        match best.get(&bid).copied() {
            None => {
                best.insert(bid, i);
            }
            Some(prev) => {
                if rank(&rows[i].row.path) < rank(&rows[prev].row.path) {
                    drop[prev] = true;
                    best.insert(bid, i);
                } else {
                    drop[i] = true;
                }
            }
        }
    }
    let mut keep = drop.iter().map(|d| !d);
    rows.retain(|_| keep.next().unwrap_or(true));
}

/// The full inventory of this machine, as `uninstall --list` reports it.
///
/// An unknown home degrades rather than fails, and that is the right call HERE specifically:
/// `search_dirs` returns four roots of which only two are `~`-relative, so `/Applications` and
/// `/Library/Input Methods` are still scanned and the listing is still real — just missing the
/// per-user half. That is a partial answer, not the fabricated-path empty answer the commands in
/// `cli.rs` refuse over.
pub fn collect() -> Vec<AppRow> {
    let home = crate::platform::home_dir().unwrap_or_default();
    collect_from_dirs(&search_dirs(&home))
}

/// The vendored capture, shared by every test in the crate that needs a REAL app inventory.
///
/// It lives outside `mod tests` because three modules need it — this one, `uninstall::resolve`, and
/// `cli`'s multi-app dispatch test — and RULEBOOK §3e is that each of them must LOAD the golden
/// rather than retype the rows it asserts against. One loader, one `include_str!`, no transcription.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::AppRow;

    /// The anonymized contract fixture bundled for standalone CI. `scripts/check_fixtures.py`
    /// verifies its approved public copy; `FIXTURE_PROVENANCE.md` records its original authority.
    pub(crate) const GOLDEN: &str = include_str!("uninstall-list.golden.json");

    /// Parse the golden into rows, so every assertion built on it is anchored to the captured output
    /// of the real program rather than to a shape typed out in a test.
    pub(crate) fn golden_rows() -> Vec<AppRow> {
        let parsed = crate::json::Json::parse(GOLDEN).expect("golden parses");
        let arr = parsed.as_array().expect("golden is a top-level ARRAY");
        arr.iter()
            .map(|r| {
                let f = |k: &str| {
                    r.get(k)
                        .unwrap_or_else(|| panic!("golden row is missing {k}"))
                        .as_str()
                        .unwrap_or_else(|| panic!("golden's {k} is not a string"))
                        .to_string()
                };
                AppRow {
                    name: f("name"),
                    bundle_id: f("bundle_id"),
                    source: f("source"),
                    uninstall_name: f("uninstall_name"),
                    path: f("path"),
                    size: f("size"),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{golden_rows, GOLDEN};
    use super::*;

    /// The load-bearing shape assertion: the golden is a BARE ARRAY, not an envelope. An
    /// envelope-wrapped port decodes to `[]` in `MoleClient.parseApps` and produces an empty
    /// Software tab with no error anywhere.
    #[test]
    fn the_golden_is_a_bare_array_of_six_string_keys() {
        let parsed = crate::json::Json::parse(GOLDEN).expect("golden parses");
        let arr = parsed
            .as_array()
            .expect("the golden's top level is an array, NOT an envelope object");
        assert!(!arr.is_empty(), "golden should carry rows");
        for row in arr {
            for key in [
                "name",
                "bundle_id",
                "source",
                "uninstall_name",
                "path",
                "size",
            ] {
                let v = row
                    .get(key)
                    .unwrap_or_else(|| panic!("every golden row has {key}"));
                assert!(
                    v.as_str().is_some(),
                    "{key} is a STRING in the golden — `size` especially is never a number"
                );
            }
        }
    }

    /// `to_json` must reproduce the golden exactly, key-for-key and value-for-value. This is the
    /// gate that fails if anyone wraps this command in the Burrow envelope.
    #[test]
    fn to_json_round_trips_the_golden_without_an_envelope() {
        let rows = golden_rows();
        let rendered = to_json(&rows);
        assert!(
            rendered.starts_with('['),
            "output must be a bare array, got: {}",
            &rendered[..rendered.len().min(80)]
        );
        let reparsed = crate::json::Json::parse(&rendered).expect("our output parses");
        let ours = reparsed.as_array().expect("our output is an array");
        let golden = crate::json::Json::parse(GOLDEN).unwrap();
        let theirs = golden.as_array().unwrap();
        assert_eq!(ours.len(), theirs.len(), "row count");
        for (o, t) in ours.iter().zip(theirs) {
            for key in [
                "name",
                "bundle_id",
                "source",
                "uninstall_name",
                "path",
                "size",
            ] {
                assert_eq!(
                    o.get(key).and_then(|v| v.as_str()),
                    t.get(key).and_then(|v| v.as_str()),
                    "{key} differs from the golden"
                );
            }
        }
    }

    /// At most ONE `brew info` runs at a time, and a token is asked about once.
    ///
    /// This is the property the cold-cache failure turns on, not a style preference: eight
    /// concurrent `brew info --cask` calls against a Homebrew cache with no API bundle all fail
    /// (they race to download the same file and corrupt each other), every failure reads as "this
    /// cask does not own the app", and every Homebrew row then degrades to `source: "App"` with the
    /// display name in `uninstall_name`. Measured 0-of-9 correct before this lock, 9-of-9 after.
    ///
    /// The fake runner records how many calls overlap, so the assertion is about real concurrency
    /// rather than about the shape of the code. check_tests: no-golden — a golden pins output
    /// values; this pins how many subprocesses run at once, which no capture can express.
    #[test]
    fn brew_info_never_runs_two_at_a_time_and_asks_about_a_token_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let index = Arc::new(CaskIndex {
            installed: HashSet::new(),
            by_bundle: HashMap::new(),
            info: std::sync::Mutex::new(HashMap::new()),
            available: true,
            brew_wedged: std::sync::atomic::AtomicBool::new(false),
        });
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|scope| {
            for i in 0..8 {
                let (index, live, peak, calls) =
                    (&index, live.clone(), peak.clone(), calls.clone());
                scope.spawn(move || {
                    // Four distinct tokens across eight threads: two threads race for each token,
                    // which is both the overlap case and the memo case.
                    let token = format!("cask-{}", i % 4);
                    index.brew_info_with(&token, |t| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        live.fetch_sub(1, Ordering::SeqCst);
                        Some(t.to_string())
                    })
                });
            }
        });

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two `brew info` calls overlapped — that is the cold-cache download race"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "four distinct tokens, four invocations: the second thread for a token is a memo hit"
        );
    }

    /// A POISONED memo lock must not read as "no cask owns this app".
    ///
    /// `self.info.lock().ok()?` returned `None` for every later call once any worker panicked while
    /// holding the lock, and `cask_owns_app` reads `None` as a non-match — so ONE panic anywhere in
    /// the eight-thread pool turned every subsequent Homebrew row into `source: "App"` with the
    /// display name in `uninstall_name`. That is the same 0-of-9 failure the lock was added to fix,
    /// reached through a different door and just as silently, and it would have survived every test
    /// here because nothing panicked.
    ///
    /// The panic is real, not simulated: a worker is made to unwind inside `brew_info_with`, and the
    /// assertion is that the NEXT caller still gets its answer.
    //
    // check_tests: no-golden — no capture can express "a thread panicked while holding a mutex".
    // The contract being pinned is `into_inner` over `ok()?`, which is a property of this process.
    #[test]
    fn a_panic_in_one_worker_does_not_turn_every_later_cask_lookup_into_a_miss() {
        let index = CaskIndex {
            installed: HashSet::new(),
            by_bundle: HashMap::new(),
            info: std::sync::Mutex::new(HashMap::new()),
            available: true,
            brew_wedged: std::sync::atomic::AtomicBool::new(false),
        };
        // Poison the lock for real: unwind out of `run`, which is called with the guard held.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            index.brew_info_with("boom", |_| -> Option<String> {
                panic!("a worker died mid-lookup");
            })
        }));
        assert!(poisoned.is_err(), "the worker really panicked");
        assert!(
            index.info.is_poisoned(),
            "and it really poisoned the memo lock — otherwise this test proves nothing"
        );

        let got = index.brew_info_with("bitwarden", |t| Some(format!("{t}: 2024.12.1")));
        assert_eq!(
            got.as_deref(),
            Some("bitwarden: 2024.12.1"),
            "a poisoned lock must be recovered from — `lock().ok()?` answered None here, which \
             `cask_owns_app` reads as `this cask does not own the app`, demoting every remaining \
             Homebrew row to source:\"App\""
        );
    }

    /// A `brew info` that misses its deadline stops the scan from calling `brew` again; one that
    /// merely EXITS non-zero does not.
    ///
    /// Both halves matter. Without the breaker, a wedged Homebrew costs one deadline per candidate
    /// token, serialised behind the memo lock, so the total can exceed the caller's scan budget.
    /// With the breaker keyed on failure rather than timeout, an ordinary untrusted-tap refusal
    /// would disable cask resolution for every row after it. The oracle's `|| return 1` treats
    /// that refusal as a single non-match.
    //
    // check_tests: no-golden — this pins how many subprocesses run after a deadline, which no
    // capture of program OUTPUT can express. The oracle side is cited in `BREW_INFO_TIMEOUT`.
    #[test]
    fn a_timed_out_brew_stops_further_calls_but_a_failed_one_does_not() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let fresh = || CaskIndex {
            installed: HashSet::new(),
            by_bundle: HashMap::new(),
            info: std::sync::Mutex::new(HashMap::new()),
            available: true,
            brew_wedged: std::sync::atomic::AtomicBool::new(false),
        };

        // An ordinary failure (untrusted tap): later tokens are still asked about.
        let index = fresh();
        let calls = AtomicUsize::new(0);
        for token in ["untrusted-one", "untrusted-two", "fine"] {
            let _ = index.brew_info_with(token, |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            });
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a non-zero exit is the oracle's ordinary non-match and must not stop the scan"
        );
        assert!(!index.brew_wedged.load(Ordering::SeqCst));

        // A deadline: the breaker trips and `brew_info` spawns nothing further.
        let index = fresh();
        index.brew_wedged.store(true, Ordering::SeqCst);
        assert_eq!(
            index.brew_info("anything"),
            None,
            "once brew is known wedged, no further call is made"
        );
        assert!(
            index
                .info
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "and nothing was even memoised, because nothing ran"
        );

        // The bound itself is real: a command that never exits is killed, and the caller is told it
        // was a DEADLINE rather than a failure — which is what the breaker keys on.
        let started = std::time::Instant::now();
        let verdict = capture_bounded("sleep", &["30"], std::time::Duration::from_millis(150));
        assert_eq!(
            verdict,
            Bounded::TimedOut,
            "a hanging child must be killed and classified as a timeout, not as a failure"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "it returned at the deadline, not when the child felt like it: {:?}",
            started.elapsed()
        );
        // …and the same helper still returns real output when the command behaves, so the bound is
        // not just failing everything.
        assert_eq!(
            capture_bounded("echo", &["ok"], std::time::Duration::from_secs(5)),
            Bounded::Ok("ok".to_string())
        );
        // The env-prefixed form the Homebrew call uses really passes the variable through.
        assert_eq!(
            capture_env_bounded(
                "sh",
                &["-c", "printf %s \"$HOMEBREW_NO_ENV_HINTS\""],
                "HOMEBREW_NO_ENV_HINTS",
                "1",
                std::time::Duration::from_secs(5)
            ),
            Bounded::Ok("1".to_string()),
            "`env KEY=VALUE cmd` is how the oracle sets an environment under its own timeout \
             helper (bin/uninstall.sh:71)"
        );
    }

    /// **The golden graded against the ENGINE'S ANSWER, not against itself.**
    ///
    /// Every other test here reads the golden and asserts about the golden. `to_json_round_trips…`
    /// parses it into rows and feeds them back through `to_json`, which grades the serializer
    /// against itself; `homebrew_rows_carry_a_lowercase_cask_token…` asserts on the golden's static
    /// rows and cannot see `build_row`; `cli.rs`'s dispatch test runs the real `--list` but only
    /// checks that each row HAS six string keys. So the whole 549-test suite stayed green when
    /// `build_row`'s `cask.unwrap_or_else(|| name.clone())` was changed to `name.clone()` — the
    /// exact substitution this module's header calls the trap, verified by doing it.
    ///
    /// This runs the REAL row builder. One fixture bundle is planted per golden row and resolved
    /// through the production `build_row` + `CaskIndex::token_for`, with the cask index seeded from
    /// the golden's own Homebrew rows and its `brew info` memo pre-populated — so the oracle's
    /// stage-2 ownership check runs for real (`lib/uninstall/brew.sh:122`) without a Homebrew on the
    /// machine, and the test is identical on all three CI runners.
    ///
    /// Four of the six fields are asserted. `path` and `size` cannot be: the fixture lives in a temp
    /// dir and is a few bytes, where the golden records `/Applications/…` and `301.8MB`. Those two
    /// belong to the machine that was captured, not to the logic under test.
    ///
    /// On the 1.42-vs-1.46 caveat in `FIXTURE_PROVENANCE.md`: what this leans on is
    /// the SHAPE and the `uninstall_name` RULE, and both are verified against the shipping 1.42 fork
    /// directly — `local uninstall_name="${cask:-$app_name}"` at `bin/uninstall.sh:1240` and the
    /// six-key printf at `:1247`. The seven captured rows are used as example inputs, never as a
    /// claim that some app is installed or that some size string is right, which is precisely what
    /// the provenance note says a 1.46 capture is and is not good for.
    #[test]
    fn the_real_row_builder_reproduces_the_goldens_uninstall_name_not_the_display_name() {
        let rows = golden_rows();
        let base =
            std::env::temp_dir().join(format!("burrow-list-rowbuild-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // A fixture bundle per golden row, named the way the capture names it. `<name>.app` is what
        // `build_row` reads as the bundle basename and what stage 2 keys on.
        for r in &rows {
            let bundle = base.join(format!("{}.app", r.name));
            std::fs::create_dir_all(bundle.join("Contents")).unwrap();
            std::fs::write(
                bundle.join("Contents/Info.plist"),
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                     \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <plist version=\"1.0\"><dict>\
                     <key>CFBundleIdentifier</key><string>{}</string>\
                     <key>CFBundleName</key><string>{}</string>\
                     </dict></plist>\n",
                    r.bundle_id, r.name
                ),
            )
            .unwrap();
        }

        // The cask index the golden implies: every Homebrew row's token is installed and its
        // Caskroom ships that bundle name. The `brew info` memo is seeded with output that mentions
        // the bundle, which is what `cask_owns_app` looks for — so no `brew` is ever spawned and the
        // memo-hit path in `brew_info_with` is what serves it.
        let brew: Vec<&AppRow> = rows.iter().filter(|r| r.source == "Homebrew").collect();
        assert!(
            !brew.is_empty(),
            "the golden must carry Homebrew rows or this test asserts nothing"
        );
        let mut by_bundle: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut installed = HashSet::new();
        let mut memo: HashMap<String, Option<String>> = HashMap::new();
        for r in &brew {
            by_bundle
                .entry(format!("{}.app", r.name))
                .or_default()
                .insert(r.uninstall_name.clone());
            installed.insert(r.uninstall_name.clone());
            memo.insert(
                r.uninstall_name.clone(),
                Some(format!(
                    "{}: 1.0\nhttps://example.invalid\nArtifact: /Applications/{}.app (App)",
                    r.uninstall_name, r.name
                )),
            );
        }
        let index = CaskIndex {
            installed,
            by_bundle,
            info: std::sync::Mutex::new(memo),
            available: true,
            brew_wedged: std::sync::atomic::AtomicBool::new(false),
        };

        for want in &rows {
            let path = base.join(format!("{}.app", want.name));
            let got = build_row(&path, &index)
                .unwrap_or_else(|| panic!("{} was dropped by the eligibility gate", want.name))
                .row;
            assert_eq!(got.name, want.name, "display name for {}", want.name);
            assert_eq!(got.source, want.source, "source for {}", want.name);
            assert_eq!(
                got.uninstall_name, want.uninstall_name,
                "THE field: {} must resolve to the token the golden recorded, not to its display \
                 name",
                want.name
            );
            if got.source == "Homebrew" {
                assert_ne!(
                    got.uninstall_name, got.name,
                    "{}: a Homebrew row's uninstall_name is the cask token — substituting the \
                     display name is the trap",
                    want.name
                );
                assert!(
                    valid_cask_token(&got.uninstall_name),
                    "{}: `{}` is not a cask token (`^[a-z0-9][a-z0-9-]*$`), so `brew` would refuse \
                     it",
                    want.name,
                    got.uninstall_name
                );
            } else {
                assert_eq!(
                    got.uninstall_name, got.name,
                    "{}: a plain App row's uninstall_name IS the display name",
                    want.name
                );
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The trap the golden exists to pin: `uninstall_name` is the cask token on Homebrew rows and
    /// equals `name` everywhere else. Substituting `name` passes on the "App" rows and silently
    /// targets the wrong thing on the Homebrew ones.
    ///
    /// A claim about the CAPTURE, which is all it can be — it reads the golden's static rows and
    /// never reaches `build_row`. The test above is the one that grades the engine.
    #[test]
    fn homebrew_rows_carry_a_lowercase_cask_token_that_is_not_the_display_name() {
        let rows = golden_rows();
        let brew: Vec<&AppRow> = rows.iter().filter(|r| r.source == "Homebrew").collect();
        assert!(!brew.is_empty(), "the golden carries Homebrew rows");
        for r in &brew {
            assert_ne!(
                r.uninstall_name, r.name,
                "{}: a Homebrew row's uninstall_name is the cask token, not the display name",
                r.name
            );
            assert_eq!(
                r.uninstall_name,
                r.name.to_lowercase(),
                "{}: the cask token is the lowercased name in the capture",
                r.name
            );
        }
        for r in rows.iter().filter(|r| r.source == "App") {
            assert_eq!(
                r.uninstall_name, r.name,
                "{}: a plain App row's uninstall_name IS the display name",
                r.name
            );
        }
        // Only these two values appear, in the capture and in the 138-row live run behind it.
        for r in &rows {
            assert!(
                r.source == "App" || r.source == "Homebrew",
                "unexpected source {:?}",
                r.source
            );
        }
    }

    /// The path is not always `/Applications/<name>.app`; the scanner walks three levels, so a
    /// bundle in a subfolder is a normal row. A port that reconstructs paths from names loses these.
    #[test]
    fn the_golden_contains_a_nested_bundle_path() {
        let rows = golden_rows();
        assert!(
            rows.iter()
                .any(|r| r.path != format!("/Applications/{}.app", r.name)),
            "the golden pins at least one path that is not /Applications/<name>.app"
        );
    }

    #[test]
    fn an_empty_inventory_is_an_empty_array_not_an_envelope() {
        assert_eq!(to_json(&[]), "[]\n");
    }

    /// Quotes and backslashes escape, and a newline collapses to a space rather than becoming
    /// `\n`, matching `uninstall_list_json_escape` (`bin/uninstall.sh:1192`). Asserted through
    /// `to_json` so it exercises the real output path rather than the escaper in isolation.
    ///
    /// This is the behaviour that would have prevented the four directories now sitting under
    /// `~/Library/Logs` whose names embed a newline and a row of this very command's output.
    //
    // check_tests: no-golden — the capture has no app whose name or path contains a control
    // character, so there is no recorded row that can pin escaping. Anchoring this to the golden
    // would mean asserting nothing. The inputs are deliberately pathological and the assertion is
    // a property (the output still parses, and no raw control character survives), not a
    // transcribed shape.
    #[test]
    fn control_characters_cannot_escape_into_the_output() {
        let row = AppRow {
            name: "we\nird \"quoted\" \\ back".to_string(),
            bundle_id: "com.x.y".to_string(),
            source: "App".to_string(),
            uninstall_name: "we\nird".to_string(),
            path: "/Applications/we\tird.app".to_string(),
            size: "1KB".to_string(),
        };
        let rendered = to_json(&[row]);
        let parsed = crate::json::Json::parse(&rendered).expect("still valid JSON");
        let got = parsed.at(0).unwrap();
        assert_eq!(
            got.get("name").unwrap().as_str().unwrap(),
            "we ird \"quoted\" \\ back"
        );
        assert_eq!(
            got.get("path").unwrap().as_str().unwrap(),
            "/Applications/we ird.app"
        );
        assert!(
            !rendered.lines().any(|l| l.contains('\t')),
            "no raw tab survives into the output"
        );
    }

    #[test]
    fn cask_tokens_are_extracted_only_from_caskroom_paths() {
        assert_eq!(
            cask_token_from_path("/opt/homebrew/Caskroom/bitwarden/2024.12.1/Bitwarden.app"),
            Some("bitwarden".to_string())
        );
        assert_eq!(
            cask_token_from_path("/usr/local/Caskroom/obs/30.0/OBS.app"),
            Some("obs".to_string())
        );
        // Not a Caskroom path at all.
        assert_eq!(cask_token_from_path("/Applications/Bitwarden.app"), None);
        // Token shape the oracle rejects (uppercase).
        assert_eq!(
            cask_token_from_path("/opt/homebrew/Caskroom/BitWarden/1/x.app"),
            None
        );
    }

    #[test]
    fn nested_bundles_and_system_symlinks_are_skipped() {
        assert!(should_skip_app_path(Path::new(
            "/Applications/Xcode.app/Contents/Applications/Instruments.app"
        )));
        // A path that does not exist is skipped (the oracle's `[[ -e ]]` guard).
        assert!(should_skip_app_path(Path::new(
            "/Applications/DefinitelyNotInstalled-9e3f.app"
        )));
    }

    #[test]
    fn search_dirs_cover_the_oracles_four_fixed_roots() {
        let dirs = search_dirs("/Users/example");
        let as_str: Vec<String> = dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        for expected in [
            "/Applications",
            "/Users/example/Applications",
            "/Library/Input Methods",
            "/Users/example/Library/Input Methods",
        ] {
            assert!(
                as_str.iter().any(|d| d == expected),
                "search dirs must include {expected}, got {as_str:?}"
            );
        }
    }

    /// The walker finds bundles up to three levels down and does not descend into a bundle,
    /// reproducing `find -maxdepth 3 -name '*.app'` plus the nested-bundle skip.
    #[test]
    fn the_walker_finds_nested_bundles_and_ignores_bundles_inside_bundles() {
        let base = std::env::temp_dir().join(format!("burrow-list-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("Top.app")).unwrap();
        std::fs::create_dir_all(base.join("Python 3.13/IDLE.app")).unwrap();
        std::fs::create_dir_all(base.join("Top.app/Contents/Helper.app")).unwrap();
        std::fs::create_dir_all(base.join("a/b/c/TooDeep.app")).unwrap();

        let mut found = Vec::new();
        find_app_bundles(&base, 3, &mut found);
        found.retain(|p| !should_skip_app_path(p));
        let names: Vec<String> = found
            .iter()
            .map(|p| p.strip_prefix(&base).unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"Top.app".to_string()), "{names:?}");
        // Built with `join` rather than written `"Python 3.13/IDLE.app"`: the walker returns the
        // platform's own separator, and on Windows that is a backslash. The claim under test is
        // that the nested bundle is FOUND, not how the OS spells the path to it.
        let nested = Path::new("Python 3.13")
            .join("IDLE.app")
            .to_string_lossy()
            .into_owned();
        assert!(names.contains(&nested), "{names:?}");
        assert!(
            !names.iter().any(|n| n.contains("Helper.app")),
            "a bundle inside a bundle is not an app to uninstall: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("TooDeep.app")),
            "maxdepth 3 stops before this: {names:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
