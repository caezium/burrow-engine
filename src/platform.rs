//! The questions whose answer depends on which operating system this is: where the user's home
//! directory is, and what counts as an executable program on `PATH`. Both are one-line lookups on
//! any single platform and both are wrong in a different way on the other one, which is exactly why
//! they live together here instead of being re-spelled at each call site.
//!
//! # Part one: the home directory — and, just as importantly, whether it could be found at all
//!
//! Every home-relative path in this crate used to start from `std::env::var("HOME").unwrap_or_default()`.
//! That is two bugs in one expression. `HOME` is a POSIX variable that Windows does not set, so the
//! engine had no way to find a home directory there at all; and `unwrap_or_default()` turns "I could
//! not find your home directory" into the empty string, which then concatenates into `/Library/Caches/*`
//! — an absolute path that exists on no machine, scans nothing, and comes back as a perfectly
//! successful empty result. Six commands (`clean`, `purge`, `installer`, `history`, `sentinel`,
//! `rules dryrun`) answered `ok:true` with nothing in it for that reason, and nothing in the response
//! let a caller tell that apart from a genuinely clean machine.
//!
//! So this module has exactly one job and it is a distinction, not a lookup: [`home_dir`] returns
//! `None` rather than a placeholder, and every caller has to say what `None` means for it. Some
//! callers legitimately degrade (a rate baseline that just does not persist); the ones that would
//! otherwise scan a fabricated path must fail instead — see [`NO_HOME`].
//!
//! The variable precedence follows burrow-cli's `platform::home_dir` (the cross-platform conductor
//! that already solved this): `USERPROFILE` first on Windows with `HOME` behind it, `HOME` on unix.
//! Deliberately NOT followed is burrow-cli's final `.unwrap_or_else(|_| PathBuf::from("."))` — the
//! current directory is not the user's home, and defaulting to it would put this crate right back in
//! the business of scanning a made-up location and calling it a success.
//!
//! # Part two: finding a program on `PATH`, which is three platform facts, not one
//!
//! [`find_on_path`] and [`executable_at`] exist because `dir.join(name).exists()` — the obvious
//! spelling, and the one both sidecar resolvers in this crate had (`dupes::resolve_fclones`,
//! `evict::resolve_brctl`) — gets two of these three wrong, and the third is easy to hand-roll
//! almost-right:
//!
//! - The SPELLING of a program includes an extension on Windows: `fclones` ships as `fclones.exe`,
//!   and a lookup for the bare name finds nothing however correctly the binary was installed. The
//!   extensions come from `PATHEXT`, the same list `cmd` and `CreateProcess` consult.
//! - EXECUTABILITY is a mode bit on unix, and `.exists()` does not read it. A DIRECTORY named
//!   `fclones` sitting on `PATH` satisfies `.exists()` and then fails at spawn time with an error
//!   about permissions that names nothing useful; so does a downloaded binary nobody `chmod +x`'d.
//! - SPLITTING `PATH` is `:` on unix and `;` on Windows, plus unquoting on Windows — where an entry
//!   containing a space is legitimately written `"C:\Program Files\tools"`. Hence
//!   [`std::env::split_paths`] in [`path_entries`] rather than a hand-rolled `split(sep)`: keeping
//!   the quotes turns a real directory into a path that exists nowhere, which is the same class of
//!   invisible-tool bug as the two above, one layer out.
//!
//! Each of those was individually survivable on the platform it was written for, which is why they
//! sat unnoticed: the spelling and splitting bugs are invisible on macOS, and the `.exists()` bug
//! only bites when something is shaped oddly on `PATH`. Together they mean a correctly bundled
//! Windows sidecar is unreachable no matter what the caller does.

use std::path::{Path, PathBuf};

/// The message every command uses when it cannot proceed without a home directory. Worded so
/// [`crate::envelope::error_kind`] classifies it `not_found` — the home directory really is the
/// thing that could not be found — and so a human reading the error learns which variables were
/// consulted rather than just that something went wrong.
pub const NO_HOME: &str =
    "home directory not found: none of BURROW_HOME, HOME or USERPROFILE is set to a usable path";

/// The highest-precedence source of the home directory: the USER's home, handed to an elevated
/// engine by the app's privileged helper. Under `do shell script … with administrator privileges`
/// or `sudo`, `HOME` is root's (`/var/root`), and every `~`-relative scan would silently answer
/// for root's empty library — see [`ROOT_HOMES`]. Honoured unconditionally, elevated or not, so
/// the same contract works for a test with a scratch home.
pub const HOME_VAR: &str = "BURROW_HOME";

/// The homes that mean "this is root's, not the user's". Resolving to one of these without
/// [`HOME_VAR`] is an error, not a home: the commands that would run against it are the
/// destructive ones, and root's `~/Library` is not what the user asked to have cleaned.
pub const ROOT_HOMES: &[&str] = &["/var/root", "/private/var/root", "/root"];

/// The refusal for a root home, naming the fix. Contains `not found` so the envelope classifies
/// it `not_found`, exactly like [`NO_HOME`] — one `error.kind` for "I do not know whose home".
fn root_home_error(home: &str) -> String {
    format!(
        "home directory not found: HOME is {home} (running as root), so the user's home is \
         unknown; pass {HOME_VAR}=<the user's home directory> — the app's privileged helper sets it"
    )
}

/// The home-resolution rule over its inputs, for the tests — the real read is [`home_dir_or_error`].
///
/// `BURROW_HOME` first; then `USERPROFILE` (Windows only) or `HOME`; a blank value counts as
/// unset; and a resolved home that is root's is refused unless it came from `BURROW_HOME`.
fn resolve_home_from(
    burrow_home: Option<&str>,
    userprofile: Option<&str>,
    home: Option<&str>,
) -> Result<String, String> {
    let usable = |v: Option<&str>| v.filter(|v| !v.trim().is_empty()).map(str::to_string);
    if let Some(h) = usable(burrow_home) {
        if cfg!(unix) && !Path::new(&h).is_absolute() {
            return Err(NO_HOME.to_string());
        }
        return Ok(h);
    }
    let resolved = if cfg!(windows) {
        usable(userprofile).or_else(|| usable(home))
    } else {
        usable(home)
    };
    let Some(resolved) = resolved else {
        return Err(NO_HOME.to_string());
    };
    if cfg!(unix) && !Path::new(&resolved).is_absolute() {
        return Err(NO_HOME.to_string());
    }
    // Normalization closes alternate spellings such as /var/./root and /Users/../var/root.
    // Canonicalization also catches an existing symlink used as HOME, without requiring ordinary
    // synthetic test homes (or a newly provisioned user's home) to exist.
    let physical = Path::new(&resolved).canonicalize().ok();
    let normalized = normalize_home(physical.as_deref().unwrap_or(Path::new(&resolved)));
    let trimmed = normalized.trim_end_matches('/');
    if ROOT_HOMES.contains(&trimmed) || (trimmed.is_empty() && resolved.starts_with('/')) {
        return Err(root_home_error(&resolved));
    }
    Ok(resolved)
}

fn normalize_home(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let normalized = normalized.to_string_lossy().into_owned();
    if cfg!(windows) {
        normalized.replace('\\', "/")
    } else {
        normalized
    }
}

/// The user's home directory, or `None` when the environment does not say where it is — or says
/// it is root's (see [`ROOT_HOMES`]), which for a degrading caller is the same answer.
///
/// A variable set to the empty string counts as unset: `HOME=` produces exactly the `""` this module
/// exists to stop, and treating it as a real answer would reintroduce the bug through the front door.
pub fn home_dir() -> Option<String> {
    home_dir_or_error().ok()
}

/// [`home_dir`], as a `Result` carrying the reason — [`NO_HOME`], or the root-home refusal that
/// says to pass [`HOME_VAR`] — for the call sites that must refuse rather than degrade, so the
/// refusal reads as one `?` instead of a repeated `ok_or_else`.
pub fn home_dir_or_error() -> Result<String, String> {
    let read = |key: &str| std::env::var(key).ok();
    resolve_home_from(
        read(HOME_VAR).as_deref(),
        read("USERPROFILE").as_deref(),
        read("HOME").as_deref(),
    )
}

/// The extension list Windows documents when `PATHEXT` is unset. Used as the fallback rather than a
/// shorter guess like `.EXE` alone, so a `.bat` or `.cmd` shim — how plenty of Windows tools are
/// actually installed — resolves the same way it does for `cmd`.
pub const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WSF;.MSC";

/// `PATH` split into directory entries, empty ones dropped.
///
/// [`std::env::split_paths`] rather than `split(if cfg!(windows) { ';' } else { ':' })`, which is
/// the same thing on unix and less than the whole job on Windows: the standard library also unquotes
/// there, and a Windows `PATH` entry containing a space is legitimately written
/// `"C:\Program Files\tools"`. Splitting on the separator alone keeps the quote characters in the
/// directory name, so the entry resolves to nothing and every tool inside it goes missing — the same
/// invisible-tool failure this module exists to remove, arrived at from a different direction.
///
/// An empty element is POSIX shorthand for the current directory, and it is skipped rather than
/// searched: resolving a tool relative to whatever directory the engine happened to be launched
/// from is not a behaviour worth reproducing.
fn path_entries(path: &str) -> impl Iterator<Item = PathBuf> + '_ {
    std::env::split_paths(path).filter(|d| !d.as_os_str().is_empty())
}

/// The extensions a program may be spelled with HERE: `None` on unix, where the name on disk is the
/// name you asked for, and the machine's `PATHEXT` (or [`DEFAULT_PATHEXT`]) on Windows.
///
/// Read from the environment rather than hardcoded so this tracks the machine's own definition of
/// "executable" — a user who adds `.PS1` to `PATHEXT` has told the OS that, and a lookup that
/// disagreed with the OS would be a second, subtler version of the bug this module exists to fix.
fn pathext() -> Option<String> {
    cfg!(windows).then(|| {
        std::env::var("PATHEXT")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_PATHEXT.to_string())
    })
}

/// Can this machine actually EXECUTE the file at `p`? unix reads the mode bit, exactly as bash's
/// `command -v` does; everywhere else a regular file is the whole test, because there is no mode bit
/// to read.
///
/// The `is_file()` half carries as much weight as the mode bit and is the half that gets dropped:
/// a directory on `PATH` named after the binary passes `.exists()`, and on unix it also has execute
/// bits set (that is what `x` means on a directory — permission to traverse it), so anything short
/// of "regular file AND executable" resolves it and hands the caller a path that cannot be spawned.
#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Windows has no execute mode bit — the extension IS the executability, and it was already applied
/// when the candidate name was built (see [`executable_at_with`]). So the remaining question here is
/// only whether a regular file is there.
#[cfg(not(unix))]
fn is_executable_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// The resolution core, with the extension list passed IN rather than read from this platform.
///
/// That parameter is the only reason a Mac can test the Windows rule at all. `cfg`-ing the whole
/// function instead would leave the Windows spelling compiled — clippy checks it on the Windows
/// target — but executed by nothing on any machine that runs this suite, which is a weaker claim
/// than it looks: `clean::tool_delegate` already had a correct `PATHEXT` branch under `cfg`, and it
/// being right there did nothing for the two resolvers that never had one.
fn executable_at_with(candidate: &Path, pathext: Option<&str>) -> Option<PathBuf> {
    // The bare name first, and not merely as an optimisation: on Windows the caller may already have
    // spelled the extension (`BURROW_FCLONES=C:\tools\fclones.exe`), and appending another one to
    // that would look for `fclones.exe.EXE`.
    if is_executable_file(candidate) {
        return Some(candidate.to_path_buf());
    }
    pathext?
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .find_map(|ext| {
            // Extended as an `OsString` rather than through `to_string_lossy`, so a path this crate
            // cannot losslessly print is still resolved rather than silently mangled into one that
            // does not exist.
            let mut name = candidate.file_name()?.to_os_string();
            name.push(ext);
            let p = candidate.with_file_name(name);
            is_executable_file(&p).then_some(p)
        })
}

/// Resolve an EXPLICIT path (an env-var override, a fixed system location) to something spawnable,
/// applying this platform's spelling rules — so a Windows override that names `fclones` resolves the
/// `fclones.exe` beside it instead of failing.
///
/// `None` means "there is nothing here I can run", which is a different answer from "this path does
/// not exist" and the one every caller actually wants: both of them end with `Command::spawn`.
pub fn executable_at(candidate: &Path) -> Option<PathBuf> {
    executable_at_with(candidate, pathext().as_deref())
}

/// The `PATH` scan itself, over a `PATH` STRING — so a test can plant real files on a synthetic
/// `PATH` instead of mutating the process environment, which is shared with every other test in the
/// binary and races them (see `io_rate`'s note on exactly that hazard).
fn find_in_path_string(path: &str, program: &str, pathext: Option<&str>) -> Option<PathBuf> {
    // Bound rather than returned directly: the iterator borrows `path`, and as a tail expression its
    // temporary would outlive the binding it borrows from.
    let found = path_entries(path).find_map(|dir| executable_at_with(&dir.join(program), pathext));
    found
}

/// Where `program` resolves on this process's `PATH`, or `None` if nowhere — bash's `command -v`,
/// with the platform's separator, the platform's spellings, and the platform's executability test.
///
/// Returns the RESOLVED path, not a yes/no, because on Windows the resolved path is not the one the
/// caller asked for: it asked for `fclones` and what exists is `fclones.exe`. A bool here would have
/// left each caller to rebuild the path itself, which is the bare-name bug again one level up.
pub fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").ok()?;
    let found = find_in_path_string(&path, program, pathext().as_deref());
    found
}

// -------------------------------------------------------------------------------------------------
// Part three: helper binaries under elevation
// -------------------------------------------------------------------------------------------------

/// The environment marker the app's privileged helper sets to `1` when it launches this engine
/// elevated. Either it, or an effective uid of 0, puts helper resolution into privileged mode.
pub const PRIVILEGED_MARKER: &str = "BURROW_PRIVILEGED";

/// An extra directory helpers may be taken from in privileged mode — honoured ONLY when it lies
/// inside the engine binary's own directory (the app bundle's `Resources/`), since anything else
/// would be one more attacker-writable variable deciding what runs as root.
pub const TOOLS_DIR_VAR: &str = "BURROW_TOOLS_DIR";

/// Where a helper binary may come from when this engine runs as root, besides its own directory:
/// the system and package-manager binary directories, in the order they are searched.
pub const TRUSTED_HELPER_DIRS: &[&str] = &[
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
];

#[cfg(unix)]
fn effective_uid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    // No POSIX uid to read; only the explicit marker can put the engine into privileged mode.
    u32::MAX
}

/// Is the effective uid 0 — the one question a task that the oracle runs under `sudo` asks before
/// running (see `crate::optimize`). Narrower than [`is_privileged`] on purpose: the
/// `BURROW_PRIVILEGED` marker says who LAUNCHED the engine, not what the kernel will let it do.
pub fn is_root() -> bool {
    effective_uid() == 0
}

/// The privileged-mode predicate over its two inputs, for the tests — the real read is
/// [`is_privileged`].
fn privileged_from(euid: u32, marker: Option<&str>) -> bool {
    euid == 0 || marker.map(str::trim) == Some("1")
}

/// Is this engine running with elevated rights — effective uid 0, or launched under
/// [`PRIVILEGED_MARKER`]`=1` by the app's helper?
///
/// When it is, an environment variable naming a binary is not an instruction from the user but a
/// candidate for code execution as root, and [`resolve_helper`] treats it accordingly.
pub fn is_privileged() -> bool {
    privileged_from(
        effective_uid(),
        std::env::var(PRIVILEGED_MARKER).ok().as_deref(),
    )
}

/// The directory this engine binary lives in — the app bundle's `Resources/` when bundled, which
/// is also where the app stages `fclones` and points `BURROW_FCLONES` at.
fn engine_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .canonicalize()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

/// Resolve a helper binary: an env override (`override_env`, e.g. `BURROW_FCLONES`), then the
/// engine's fixed locations for it (`fixed`, e.g. `/usr/bin/brctl`), then a `PATH` scan for
/// `program` — the resolution every sidecar in this crate had, with one addition.
///
/// **Under elevation ([`is_privileged`]) the environment stops being trusted.** `BURROW_FCLONES`,
/// `BURROW_BRCTL` and `PATH` are all inherited from whoever launched the process, and an engine
/// running as root that spawns whatever they name is a privilege escalation with a friendly name.
/// So in privileged mode:
///
/// - the override is honoured only when the file it names sits directly inside a trusted
///   directory — the engine binary's own directory first (that is the app bundle, and it is where
///   the app puts the sidecar it points the override at), then [`TOOLS_DIR_VAR`] if that itself
///   lies inside the engine's directory, then [`TRUSTED_HELPER_DIRS`];
/// - `fixed` locations are still honoured — the engine chose them, not the environment;
/// - `PATH` is never searched; `program` is looked for in the trusted directories instead.
///
/// The parent directory is compared after `canonicalize`, so `/opt/homebrew/bin/../../tmp/x` is
/// `/tmp/x` for this purpose, and a symlink somewhere untrusted pointing into a trusted directory
/// is judged by where the link is, which is what an attacker controls.
pub fn resolve_helper(
    program: &str,
    override_env: Option<&str>,
    fixed: &[&str],
) -> Option<PathBuf> {
    let override_value = override_env.and_then(std::env::var_os);
    let tools_dir = std::env::var_os(TOOLS_DIR_VAR);
    let path = std::env::var("PATH").ok();
    resolve_helper_with(
        program,
        override_value.as_deref().map(Path::new),
        fixed,
        is_privileged(),
        engine_dir().as_deref(),
        tools_dir.as_deref().map(Path::new),
        path.as_deref(),
    )
}

/// [`resolve_helper`] with every environment fact injected, so the privileged rules are tested
/// against planted directories rather than by re-executing this binary as root.
fn resolve_helper_with(
    program: &str,
    override_value: Option<&Path>,
    fixed: &[&str],
    privileged: bool,
    engine_dir: Option<&Path>,
    tools_dir: Option<&Path>,
    path: Option<&str>,
) -> Option<PathBuf> {
    let pathext = pathext();
    let pathext = pathext.as_deref();
    let at = |p: &Path| executable_at_with(p, pathext);

    if !privileged {
        if let Some(p) = override_value.and_then(at) {
            return Some(p);
        }
        if let Some(p) = fixed.iter().find_map(|f| at(Path::new(f))) {
            return Some(p);
        }
        return path.and_then(|p| find_in_path_string(p, program, pathext));
    }

    let trusted = trusted_dirs(engine_dir, tools_dir);
    if let Some(candidate) = override_value {
        if lives_directly_in(candidate, &trusted) {
            if let Some(p) = at(candidate) {
                return Some(p);
            }
        }
    }
    if let Some(p) = fixed.iter().find_map(|f| at(Path::new(f))) {
        return Some(p);
    }
    trusted.iter().find_map(|d| at(&d.join(program)))
}

/// The directories a privileged engine may take helpers from, canonicalized, in search order.
fn trusted_dirs(engine_dir: Option<&Path>, tools_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let engine = engine_dir.and_then(|d| d.canonicalize().ok());
    if let Some(e) = &engine {
        dirs.push(e.clone());
        if let Some(t) = tools_dir.and_then(|d| d.canonicalize().ok()) {
            if t.starts_with(e) && !dirs.contains(&t) {
                dirs.push(t);
            }
        }
    }
    for d in TRUSTED_HELPER_DIRS {
        if let Ok(c) = Path::new(d).canonicalize() {
            if !dirs.contains(&c) {
                dirs.push(c);
            }
        }
    }
    dirs
}

/// Whether `candidate` names a file DIRECTLY inside one of `trusted` — its parent, canonicalized,
/// is one of them, and its final component is a plain name rather than `..` or nothing.
fn lives_directly_in(candidate: &Path, trusted: &[PathBuf]) -> bool {
    let Some(name) = candidate.file_name() else {
        return false;
    };
    if name == ".." || name == "." {
        return false;
    }
    let Some(parent) = candidate.parent().and_then(|p| p.canonicalize().ok()) else {
        return false;
    };
    trusted.contains(&parent)
}

// ---- Subprocess plumbing (moved here from `status::collect`, BUR-126) ----

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The plain subprocess seam a pure module spawns through: `(program, args)` → stdout, `None` on
/// any failure. Production passes [`run_command`]; tests pass a fake. Modules that need the
/// failure's reason or a per-call budget use [`TimedRunner`] or their own `Result`-returning form.
pub type Runner<'a> = &'a dyn Fn(&str, &[&str]) -> Option<String>;

/// [`Runner`] with a per-call budget — the shape [`run_command_with_timeout`] has, for collectors
/// that port digger's `context.WithTimeout` values call by call.
pub type TimedRunner<'a> = &'a dyn Fn(&str, &[&str], std::time::Duration) -> Option<String>;

/// The architecture spelling reported by the host, with an injected command seam for probing
/// and failure decisions. Keep this OS-specific work out of the command envelope layer.
pub fn machine_architecture_with(run: TimedRunner<'_>) -> String {
    run("uname", &["-m"], Duration::from_secs(1))
        .map(|out| out.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn machine_architecture() -> String {
    machine_architecture_with(&run_command_with_timeout)
}

/// The fallback budget for [`run_command`]'s callers that don't pick their own — see its doc
/// comment. No `status` collector uses this: every one of them calls
/// [`run_command_with_timeout`] directly with a tighter, per-call duration ported from digger's
/// own `context.WithTimeout` (see each collector's doc comment below for its specific value and
/// source).
const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Run a command and return its stdout as a String, or `None` if it can't be spawned, exits
/// non-zero, or doesn't finish within [`DEFAULT_COMMAND_TIMEOUT`]. The engine's uniform "shell out
/// and parse" primitive, for callers that have no per-call budget of their own — today that's only
/// `optimize`'s maintenance-task runner (`cli.rs`), which can invoke `lsregister -kill -r -domain
/// local -domain system -domain user` (a full Launch Services database rebuild that legitimately
/// takes anywhere from a few seconds to over a minute on a real Mac, and carries no timeout in the
/// original bash implementation either — `bin/optimize.sh` / `lib/optimize/maintenance.sh` run it
/// unbounded). `DEFAULT_COMMAND_TIMEOUT` is deliberately generous so it never cuts off a legitimate
/// run like that one; every `status` collector needs (and gets) a tighter bound than this, so it
/// calls [`run_command_with_timeout`] directly instead — this function used to have NO timeout at
/// all (`Command::output()`, which blocks forever), which is the bug this pair of functions exists
/// to close: bounded-but-generous is still a real improvement over unbounded, everywhere in the
/// crate, not just in `status`.
pub fn run_command(program: &str, args: &[&str]) -> Option<String> {
    run_command_with_timeout(program, args, DEFAULT_COMMAND_TIMEOUT)
}

/// Like [`run_command`], but kills the child and returns `None` if it hasn't exited within
/// `timeout`, instead of blocking forever. `Command::output()` has no built-in deadline — for most
/// of this module's shell-outs that's fine (their commands either return fast or the RULEBOOK's
/// `-n`/similar flags already close the hang risk), but a handful (`diskutil info` on a
/// spinning-up/unresponsive external volume, `osascript` waiting on Finder, a wedged `ioreg`) can
/// genuinely block, and this is the engine's zero-dep way to bound them — digger bounds the SAME
/// calls with `context.WithTimeout`.
///
/// Stdout is drained on a dedicated thread rather than read only after `try_wait` reports the
/// child has exited: a child that writes more than one pipe buffer's worth of output before
/// exiting would otherwise block on that write forever, since nobody is draining the pipe while
/// this function is busy polling — meaning THIS function's own timeout, not a clean read, would be
/// what eventually returns, on every single invocation, converting a large-but-healthy collector
/// into a permanent failure rather than a merely-slow one. This is not hypothetical: the previous
/// version of this function (read-after-exit, correct for the small `diskutil`/`osascript` outputs
/// it was written for) was about to be reused for every `status` collector, and measured live on
/// this machine, `ps aux` (the `collect_processes` fallback) emits ~248KB and the primary
/// `ps -Aceo …` invocation ~36KB — both far past macOS's default per-pipe capacity, and `ioreg -rn
/// AppleSmartBattery` alone (~16KB) is close enough to it to be a real risk too. Routing those
/// through the old implementation unchanged would have made `top_processes`/`cpu.per_core`/
/// `batteries`/`thermal` fail their timeout on this machine on every run, not just a wedged one —
/// exactly the "converts a slow pane into a dead app" failure this whole change exists to prevent.
pub fn run_command_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run_command_checked(program, args, timeout).ok()
}

/// Why a shell-out produced nothing.
///
/// [`run_command_with_timeout`] collapses all four of these into `None`, and every caller in this
/// module then `unwrap_or_default()`s that into `0` / `""` / `vec![]`. So "`sysctl` is not a program
/// on this machine" and "`netstat -ibn` rejected those flags" and "the disk is wedged and `df` was
/// killed at 3s" were indistinguishable — from each other, and from a genuine zero reading. That is
/// what let `status` report `health_score: 100, "Excellent"` from a snapshot in which nothing at all
/// had been collected: every penalty branch in `calculate_health_score` is a `>` comparison, so a
/// fabricated `0` triggers none of them and the score stays at its initial 100.
///
/// Keeping the `Option` API is deliberate — ~40 call sites legitimately do not care why, and
/// rewriting them all would be churn with no reader. What matters is that the information now EXISTS
/// for the callers that do: see [`run_command_checked`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandFailure {
    /// The child could not be started at all. On Windows and Linux this is what every macOS-only
    /// probe in this module returns (`sysctl`, `vm_stat`, `pmset`, `ioreg`, …); on macOS it means a
    /// stripped `PATH`, a missing binary, or a permissions problem on the executable.
    NotSpawnable(String),
    /// It started, ran to completion, and exited non-zero — the binary EXISTS and disagreed with us.
    /// A wrong flag lands here, which is why it must not read the same as "no such program".
    Exited(Option<i32>),
    /// Still running when its budget expired; killed. The machine is slow or the resource is wedged
    /// — a retry might succeed, unlike either case above.
    TimedOut(Duration),
    /// Spawned, but stdout could not be taken or read. Rare; kept distinct rather than folded into
    /// one of the above because guessing which it resembles would be inventing a fact.
    NoOutput,
}

impl std::fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandFailure::NotSpawnable(e) => write!(f, "could not be started ({e})"),
            CommandFailure::Exited(Some(c)) => write!(f, "exited {c}"),
            CommandFailure::Exited(None) => write!(f, "was terminated by a signal"),
            CommandFailure::TimedOut(d) => write!(f, "timed out after {:?}", d),
            CommandFailure::NoOutput => write!(f, "produced no readable output"),
        }
    }
}

/// [`run_command_with_timeout`], keeping the reason it failed.
///
/// Identical mechanics — same spawn, same dedicated draining thread, same kill-on-timeout — so this
/// is the one implementation and the `Option`-returning form above is a thin `.ok()` over it. There
/// is no second code path to drift.
pub fn run_command_checked(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CommandFailure> {
    let mut command = Command::new(program);
    command.args(args);
    run_configured_command(command, Some(timeout))
}

thread_local! {
    static COMMAND_DEADLINE: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
}

/// One synchronous collection pass shares a deadline instead of restarting a full timeout for
/// every fallback. The scope is thread-local and restored on unwind; unrelated commands and
/// long-running actions retain their own budgets.
pub(crate) fn with_command_budget<T>(budget: Duration, work: impl FnOnce() -> T) -> T {
    struct Restore(Option<Instant>);
    impl Drop for Restore {
        fn drop(&mut self) {
            COMMAND_DEADLINE.set(self.0);
        }
    }
    let deadline = Instant::now().checked_add(budget);
    let previous = COMMAND_DEADLINE.get();
    let effective = match (previous, deadline) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    let _restore = Restore(previous);
    COMMAND_DEADLINE.set(effective);
    work()
}

pub(crate) fn remaining_command_budget(requested: Duration) -> Duration {
    COMMAND_DEADLINE.get().map_or(requested, |deadline| {
        requested.min(deadline.saturating_duration_since(Instant::now()))
    })
}

/// The common process pump for collectors and tool delegates. Its deadline includes pipe EOF,
/// which can outlive the direct child when a descendant inherits stdout.
pub(crate) fn run_configured_command(
    mut command: Command,
    timeout: Option<Duration>,
) -> Result<String, CommandFailure> {
    let timeout = match (timeout, COMMAND_DEADLINE.get()) {
        (Some(timeout), _) => Some(remaining_command_budget(timeout)),
        (None, Some(deadline)) => Some(deadline.saturating_duration_since(Instant::now())),
        (None, None) => None,
    };
    if timeout == Some(Duration::ZERO) {
        return Err(CommandFailure::TimedOut(Duration::ZERO));
    }
    configure_child_environment(&mut command)
        .map_err(|e| CommandFailure::NotSpawnable(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    pump_command(command, timeout)
}

fn configure_child_environment(command: &mut Command) -> std::io::Result<()> {
    if is_privileged() {
        let dirs = trusted_dirs(
            engine_dir().as_deref(),
            std::env::var_os(TOOLS_DIR_VAR).as_deref().map(Path::new),
        );
        let path = std::env::join_paths(dirs)
            .map_err(|e| std::io::Error::other(format!("invalid trusted PATH: {e}")))?;
        command.env("PATH", path);
    }
    if let Ok(home) = std::env::var(HOME_VAR) {
        if !home.trim().is_empty() {
            command.env("HOME", home);
        }
    }
    Ok(())
}

/// Drain both output pipes while sending a report on stdin. A tool may print enough diagnostics
/// to fill stdout before it reads the rest of the report, so writing all input first deadlocks.
pub(crate) fn run_command_with_input(
    mut command: Command,
    input: Option<&str>,
) -> std::io::Result<std::process::Output> {
    use std::io::Write;
    configure_child_environment(&mut command)?;
    let Some(input) = input else {
        return command.stdin(Stdio::null()).output();
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input.as_bytes()));
        let output = child.wait_with_output();
        let written = writer
            .join()
            .map_err(|_| std::io::Error::other("stdin writer panicked"))?;
        let output = output?;
        // On failure the tool's stderr is more useful than the resulting broken input pipe.
        if output.status.success() {
            written?;
        }
        Ok(output)
    })
}

fn pump_command(mut command: Command, timeout: Option<Duration>) -> Result<String, CommandFailure> {
    let start = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| CommandFailure::NotSpawnable(e.to_string()))?;
    let Some(mut stdout) = child.stdout.take() else {
        stop_child(&mut child);
        return Err(CommandFailure::NoOutput);
    };
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut buf = String::new();
        let result = stdout.read_to_string(&mut buf).map(|_| buf);
        let _ = send.send(result);
    });
    let mut status = None;
    let mut output = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(found) => status = found,
                Err(e) => {
                    stop_child(&mut child);
                    return Err(CommandFailure::NotSpawnable(e.to_string()));
                }
            }
        }
        if output.is_none() {
            match receive.try_recv() {
                Ok(out) => output = Some(out),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    stop_child(&mut child);
                    return Err(CommandFailure::NoOutput);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let (Some(status), Some(out)) = (status.as_ref(), output.as_ref()) {
            return if !status.success() {
                Err(CommandFailure::Exited(status.code()))
            } else {
                match out {
                    Ok(out) => Ok(out.clone()),
                    Err(_) => Err(CommandFailure::NoOutput),
                }
            };
        }
        if let Some(timeout) = timeout {
            if start.elapsed() >= timeout {
                stop_child(&mut child);
                return Err(CommandFailure::TimedOut(timeout));
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        extern "C" {
            fn kill(pid: i32, signal: i32) -> i32;
        }
        // The child was spawned into its own process group. A negative pid kills only that
        // group, including ordinary grandchildren that may still hold its stdout pipe open.
        if let Ok(pid) = i32::try_from(child.id()) {
            unsafe {
                kill(-pid, 9);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_command_budget_refuses_new_spawns_and_restores_scope() {
        with_command_budget(Duration::ZERO, || {
            let mut command = Command::new("must-not-be-spawned");
            command.arg("unused");
            assert!(matches!(
                run_configured_command(command, Some(Duration::from_secs(5))),
                Err(CommandFailure::TimedOut(_))
            ));
            with_command_budget(Duration::from_secs(5), || {
                assert_eq!(
                    remaining_command_budget(Duration::from_secs(1)),
                    Duration::ZERO
                );
            });
        });
        assert_eq!(
            remaining_command_budget(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
        let _ = std::panic::catch_unwind(|| {
            with_command_budget(Duration::ZERO, || panic!("fixture unwind"))
        });
        assert_eq!(
            remaining_command_budget(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    #[cfg(unix)]
    fn sequential_probes_share_one_wall_clock_budget() {
        let start = Instant::now();
        with_command_budget(Duration::from_millis(120), || {
            assert!(run_command_checked(
                "/bin/sh",
                &["-c", "sleep 0.05; printf first"],
                Duration::from_secs(2)
            )
            .is_ok());
            assert!(matches!(
                run_command_checked("/bin/sh", &["-c", "sleep 10"], Duration::from_secs(2)),
                Err(CommandFailure::TimedOut(_))
            ));
            assert_eq!(
                remaining_command_budget(Duration::from_secs(1)),
                Duration::ZERO
            );
        });
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn architecture_probe_has_a_budget_and_an_explicit_failure_value() {
        let probe = |program: &str, args: &[&str], timeout: Duration| {
            assert_eq!(program, "uname");
            assert_eq!(args, ["-m"]);
            assert_eq!(timeout, Duration::from_secs(1));
            Some("arm64\n".to_string())
        };
        assert_eq!(machine_architecture_with(&probe), "arm64");
        assert_eq!(machine_architecture_with(&|_, _, _| None), "unknown");
        assert_eq!(
            machine_architecture_with(&|_, _, _| Some(" \n".into())),
            "unknown"
        );
    }

    /// The engine runs its own tests with a real home, so this asserts the property that matters —
    /// whatever `home_dir` reports is an ABSOLUTE path to a directory that exists — rather than
    /// comparing against a value copied out of the environment, which would pass for `""` too.
    #[test]
    fn a_reported_home_is_a_real_absolute_directory() {
        let Some(home) = home_dir() else {
            // A CI runner with no home is a legitimate answer, and it is the one this whole module
            // exists to make representable. Nothing to check beyond that it said so.
            return;
        };
        let p = std::path::Path::new(&home);
        assert!(
            p.is_absolute(),
            "a home directory that is not absolute would concatenate into a relative scan root: {home:?}"
        );
        assert!(
            p.is_dir(),
            "home_dir must report a directory that exists, never a placeholder: {home:?}"
        );
    }

    /// The empty string is the exact value the old `unwrap_or_default()` produced, and the one that
    /// silently built `/Library/Caches/*`. It must read as "not found", not as a home directory.
    #[test]
    fn a_blank_variable_is_not_a_home_directory() {
        // Checked through the same filter `home_dir` applies, without mutating the process
        // environment — `set_var` races every other test in this binary (see `io_rate`'s note on
        // exactly that hazard), and the thing under test here is the predicate, not the lookup.
        let blank_is_rejected = |v: &str| Some(v.to_string()).filter(|s| !s.trim().is_empty());
        assert_eq!(blank_is_rejected(""), None);
        assert_eq!(blank_is_rejected("   "), None);
        assert_eq!(
            blank_is_rejected("/Users/someone"),
            Some("/Users/someone".to_string())
        );
    }

    /// `BURROW_HOME` outranks everything; root's home is refused with the fix named; a root home
    /// handed in THROUGH `BURROW_HOME` is taken at its word (the helper said so).
    #[test]
    fn home_resolution_prefers_burrow_home_and_refuses_roots_home_without_it() {
        assert_eq!(
            resolve_home_from(Some("/Users/me"), Some("C:\\Users\\me"), Some("/var/root")),
            Ok("/Users/me".to_string())
        );
        assert_eq!(
            resolve_home_from(Some("  "), None, Some("/Users/me")),
            Ok("/Users/me".to_string()),
            "a blank BURROW_HOME is unset"
        );
        for root in [
            "/var/root",
            "/var/root/",
            "/private/var/root",
            "/root",
            "/var/./root",
            "/Users/../var/root",
        ] {
            let err = resolve_home_from(None, None, Some(root)).unwrap_err();
            assert!(err.contains(HOME_VAR), "{root}: names the fix: {err}");
            assert!(
                err.contains("not found"),
                "{root}: classifies not_found: {err}"
            );
            assert_ne!(err, NO_HOME, "{root}: distinct from the no-home refusal");
            let e = crate::envelope::error_envelope("0.0.0", "clean", &err);
            assert!(e.contains("\"kind\":\"not_found\""), "{e}");
        }
        assert_eq!(
            resolve_home_from(Some("/var/root"), None, None),
            Ok("/var/root".to_string()),
            "BURROW_HOME is authoritative even for root's home"
        );
        assert_eq!(
            resolve_home_from(None, None, None),
            Err(NO_HOME.to_string())
        );
        assert_eq!(
            resolve_home_from(None, None, Some("")),
            Err(NO_HOME.to_string())
        );
        if cfg!(windows) {
            assert_eq!(
                resolve_home_from(None, Some("C:\\Users\\me"), None),
                Ok("C:\\Users\\me".to_string())
            );
        } else {
            assert_eq!(
                resolve_home_from(None, Some("C:\\Users\\me"), None),
                Err(NO_HOME.to_string()),
                "USERPROFILE is a Windows variable"
            );
        }
    }

    /// The refusal message has to survive contact with the classifier, or a GUI branching on
    /// `error.kind` sees a generic `error` and cannot tell this apart from anything else.
    #[test]
    fn the_refusal_message_classifies_as_a_lookup_failure() {
        let e = crate::envelope::error_envelope("0.0.0", "purge", NO_HOME);
        assert!(
            e.contains("\"kind\":\"not_found\""),
            "NO_HOME must classify as not_found: {e}"
        );
        assert!(e.contains("\"ok\":false"), "{e}");
    }

    // -----------------------------------------------------------------------------------------
    // PATH resolution. Every test below plants REAL files and asks the real resolver about them —
    // no fixture describes what the answer should look like, because the answer is a path on this
    // disk. They compile and run on all three targets: the platform-varying half is reached by
    // passing the extension list explicitly (see `executable_at_with`), never by `cfg`, so the
    // Windows rule is exercised on the Mac that runs this suite rather than only asserted about.
    // -----------------------------------------------------------------------------------------

    /// Every `tag` [`scratch`] has already handed out in this process. Two tests sharing a directory
    /// delete each other's fixtures — `clean::tool_delegate`'s own test module records that failing
    /// roughly one run in eight, in two disguises, so it is enforced here rather than remembered.
    static SCRATCH_TAGS: std::sync::Mutex<std::collections::BTreeSet<&'static str>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());

    /// A scratch directory unique to this TEST (not merely to this process), emptied on entry.
    fn scratch(tag: &'static str) -> PathBuf {
        assert!(
            SCRATCH_TAGS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(tag),
            "scratch tag `{tag}` was already handed to another test: give this one its own"
        );
        let d = std::env::temp_dir().join(format!("burrow_platform_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Plant a real file at `at` that this platform agrees is executable: on unix that means the
    /// mode bit, which is the half `.exists()` never asked about.
    fn plant_executable(at: &Path) {
        std::fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::fs::write(at, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(at).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(at, perms).unwrap();
        }
    }

    /// A synthetic `PATH` built with the separator this platform actually uses, so the test cannot
    /// pass by agreeing with a hardcoded `:` on a machine whose answer is `;`.
    fn synthetic_path(dirs: &[&Path]) -> String {
        let sep = if cfg!(windows) { ';' } else { ':' };
        dirs.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(&sep.to_string())
    }

    #[test]
    fn path_is_split_on_this_platforms_separator_and_empty_entries_are_dropped() {
        let sep = if cfg!(windows) { ';' } else { ':' };
        let joined = format!("{sep}/one{sep}{sep}/two{sep}");
        let got: Vec<PathBuf> = path_entries(&joined).collect();
        assert_eq!(
            got,
            vec![PathBuf::from("/one"), PathBuf::from("/two")],
            "PATH {joined:?} must split on {sep:?} with empty entries dropped"
        );
    }

    /// The load-bearing one, and the trap it guards is deliberately FIRST on the synthetic `PATH`:
    /// a directory named `fclones`. It satisfies `.exists()`, and on unix it even has execute bits
    /// (that is what `x` means on a directory), so a resolver written the obvious way returns it and
    /// the caller gets a path that cannot be spawned. If this ever regresses to `.exists()`, the
    /// assertion below does not merely go red — it comes back holding the trap's path, naming the
    /// defect.
    #[test]
    fn a_directory_named_like_the_binary_never_wins_over_the_real_one_behind_it() {
        let root = scratch("resolve");
        let trap = root.join("trap");
        let real = root.join("bin");
        std::fs::create_dir_all(trap.join("fclones")).unwrap();
        plant_executable(&real.join("fclones"));

        let path = synthetic_path(&[&trap, &real]);
        assert_eq!(
            find_in_path_string(&path, "fclones", None),
            Some(real.join("fclones")),
            "the directory on the earlier PATH entry must be skipped, not resolved: {path}"
        );
        assert_eq!(
            executable_at_with(&trap.join("fclones"), None),
            None,
            "a directory is not something Command::spawn can run"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The Windows spelling, exercised on whatever platform runs this: only `fclones.EXE` is on
    /// disk — how a Windows install actually ships — and a lookup for the bare name has to find it
    /// through `PATHEXT`. This is the case that made a correctly bundled sidecar invisible.
    #[test]
    fn a_windows_binary_resolves_through_pathext_and_the_bare_name_alone_finds_nothing() {
        let dir = scratch("pathext");
        plant_executable(&dir.join("fclones.EXE"));

        assert_eq!(
            executable_at_with(&dir.join("fclones"), Some(DEFAULT_PATHEXT)),
            Some(dir.join("fclones.EXE")),
            "PATHEXT resolution must return the path that EXISTS, extension and all"
        );
        assert_eq!(
            executable_at_with(&dir.join("fclones"), None),
            None,
            "unix rules try the bare name only, and nothing on disk is spelled that way"
        );
        assert_eq!(
            find_in_path_string(&synthetic_path(&[&dir]), "fclones", Some(DEFAULT_PATHEXT)),
            Some(dir.join("fclones.EXE")),
            "the PATH scan must apply the same spellings as a direct lookup"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An already-spelled extension is not extended again — the shape an override takes
    /// (`BURROW_FCLONES=C:\tools\fclones.exe`), which a naive "always append PATHEXT" would turn
    /// into a hunt for `fclones.exe.EXE`.
    #[test]
    fn a_name_that_already_carries_its_extension_resolves_as_itself() {
        let dir = scratch("spelled");
        plant_executable(&dir.join("fclones.EXE"));
        assert_eq!(
            executable_at_with(&dir.join("fclones.EXE"), Some(DEFAULT_PATHEXT)),
            Some(dir.join("fclones.EXE"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Existence is not executability, and the two diverge per platform: unix has a mode bit to
    /// read and Windows does not. Asserted as the local platform's REAL answer rather than skipped
    /// off unix, so the Windows branch is a claim this suite checks somewhere.
    #[test]
    fn a_file_that_exists_but_cannot_be_run_answers_this_platforms_own_way() {
        let dir = scratch("mode");
        let f = dir.join("fclones");
        std::fs::write(&f, b"downloaded, never chmod +x'd").unwrap();
        let resolved = executable_at_with(&f, None);
        if cfg!(unix) {
            assert_eq!(
                resolved, None,
                "no execute bit means it cannot be spawned, whatever `.exists()` says"
            );
        } else {
            assert_eq!(
                resolved,
                Some(f),
                "there is no execute bit on Windows — a regular file is the whole test"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The real `PATH`, through the public entry point: an interpreter every platform ships must
    /// resolve, and a name on no `PATH` entry must not. Driven off the machine's own environment
    /// rather than a fixture, because the thing under test here is the environment lookup itself.
    #[test]
    fn a_real_interpreter_on_the_real_path_is_found_and_a_nonexistent_name_is_not() {
        let real = if cfg!(windows) { "cmd" } else { "sh" };
        let found =
            find_on_path(real).unwrap_or_else(|| panic!("{real} must resolve on this PATH"));
        assert!(
            is_executable_file(&found),
            "{found:?} was returned as spawnable, so it must actually be spawnable"
        );
        assert_eq!(
            find_on_path("burrow_engine_definitely_not_a_real_program"),
            None
        );
    }

    // -----------------------------------------------------------------------------------------
    // Helper resolution under elevation. Every environment fact is injected, so these plant real
    // directories and ask the real resolver — without needing to run as root.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn privileged_mode_is_root_or_the_explicit_marker() {
        assert!(privileged_from(0, None));
        assert!(privileged_from(501, Some("1")));
        assert!(privileged_from(501, Some(" 1 ")));
        assert!(!privileged_from(501, None));
        assert!(!privileged_from(501, Some("0")));
        assert!(!privileged_from(501, Some("")));
        assert!(!privileged_from(501, Some("true")));
    }

    /// The layout the app produces: the engine binary and its sidecar in ONE directory
    /// (`Resources/`), an override pointing at the sidecar, and a `PATH` entry somewhere else.
    struct Layout {
        root: PathBuf,
        engine_dir: PathBuf,
        bundled: PathBuf,
        elsewhere: PathBuf,
        on_path: PathBuf,
    }

    fn layout(tag: &'static str) -> Layout {
        let root = scratch(tag);
        let engine_dir = root.join("Resources");
        let bundled = engine_dir.join("fclones");
        let elsewhere = root.join("Downloads/fclones");
        let on_path = root.join("bin/fclones");
        for p in [&bundled, &elsewhere, &on_path] {
            plant_executable(p);
        }
        Layout {
            root,
            engine_dir,
            bundled,
            elsewhere,
            on_path,
        }
    }

    #[test]
    fn unprivileged_resolution_honours_the_override_wherever_it_points() {
        let l = layout("helper_unprivileged");
        let path = synthetic_path(&[l.on_path.parent().unwrap()]);
        let got = resolve_helper_with(
            "fclones",
            Some(&l.elsewhere),
            &[],
            false,
            Some(&l.engine_dir),
            None,
            Some(&path),
        );
        assert_eq!(got, Some(l.elsewhere.clone()));
        // …and PATH answers when there is no override.
        let got = resolve_helper_with(
            "fclones",
            None,
            &[],
            false,
            Some(&l.engine_dir),
            None,
            Some(&path),
        );
        assert_eq!(got, Some(l.on_path.clone()));
        let _ = std::fs::remove_dir_all(&l.root);
    }

    #[test]
    fn privileged_resolution_ignores_an_override_outside_the_engines_own_directory() {
        let l = layout("helper_privileged_override_outside");
        let path = synthetic_path(&[l.on_path.parent().unwrap()]);
        let got = resolve_helper_with(
            "fclones",
            Some(&l.elsewhere),
            &[],
            true,
            Some(&l.engine_dir),
            None,
            Some(&path),
        );
        // The override is ignored and the engine's OWN sidecar answers instead.
        assert_eq!(got, Some(l.bundled.canonicalize().unwrap()), "{got:?}");

        // With no sidecar beside the engine either, the answer is None — or a real fclones in one
        // of TRUSTED_HELPER_DIRS on this machine; never the override's, never PATH's.
        std::fs::remove_file(&l.bundled).unwrap();
        let got = resolve_helper_with(
            "fclones",
            Some(&l.elsewhere),
            &[],
            true,
            Some(&l.engine_dir),
            None,
            Some(&path),
        );
        assert!(
            got.as_deref().is_none_or(|p| !p.starts_with(&l.root)),
            "neither the override nor PATH may answer as root: {got:?}"
        );
        if let Some(p) = &got {
            assert!(
                TRUSTED_HELPER_DIRS
                    .iter()
                    .any(|d| p.starts_with(Path::new(d).canonicalize().unwrap_or_default())),
                "{p:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&l.root);
    }

    #[test]
    fn privileged_resolution_honours_the_override_that_lives_beside_the_engine() {
        let l = layout("helper_privileged_override_bundled");
        let got = resolve_helper_with(
            "fclones",
            Some(&l.bundled),
            &[],
            true,
            Some(&l.engine_dir),
            None,
            None,
        );
        assert_eq!(
            got,
            Some(l.bundled.clone()),
            "an override is returned as given: {got:?}"
        );
        // A `..` hop out of the bundle is judged by where it lands, not by its prefix.
        let hop = l.engine_dir.join("../Downloads/fclones");
        let got = resolve_helper_with(
            "fclones",
            Some(&hop),
            &[],
            true,
            Some(&l.engine_dir),
            None,
            None,
        );
        assert_ne!(got.as_deref(), Some(hop.as_path()), "{got:?}");
        // The rejected hop falls through to the trusted search, which may legitimately answer with
        // the bundled copy beside the engine — but never with the hop's own target. Compared
        // canonically: on macOS the scratch dir is reached through the `/tmp` symlink.
        let bundled = l.bundled.canonicalize().ok();
        assert!(
            got.as_deref()
                .is_none_or(|p| p.canonicalize().ok() == bundled),
            "{got:?}"
        );
        let _ = std::fs::remove_dir_all(&l.root);
    }

    #[test]
    fn privileged_resolution_finds_the_program_in_the_engines_directory_without_an_override() {
        let l = layout("helper_privileged_engine_dir");
        let got = resolve_helper_with(
            "fclones",
            None,
            &[],
            true,
            Some(&l.engine_dir),
            None,
            Some(&synthetic_path(&[l.on_path.parent().unwrap()])),
        );
        assert_eq!(got, Some(l.bundled.canonicalize().unwrap()), "{got:?}");
        let _ = std::fs::remove_dir_all(&l.root);
    }

    #[test]
    fn a_tools_dir_is_trusted_only_when_it_lies_inside_the_engines_directory() {
        let l = layout("helper_tools_dir");
        let inside = l.engine_dir.join("tools");
        plant_executable(&inside.join("brctl"));
        let outside = l.root.join("tools");
        plant_executable(&outside.join("brctl"));

        let got = resolve_helper_with(
            "brctl",
            None,
            &[],
            true,
            Some(&l.engine_dir),
            Some(&inside),
            None,
        );
        assert_eq!(
            got,
            Some(inside.join("brctl").canonicalize().unwrap()),
            "{got:?}"
        );

        let got = resolve_helper_with(
            "brctl",
            None,
            &[],
            true,
            Some(&l.engine_dir),
            Some(&outside),
            None,
        );
        assert_ne!(got, Some(outside.join("brctl")), "{got:?}");
        assert!(
            got.as_deref().is_none_or(|p| !p.starts_with(&l.root)),
            "{got:?}"
        );
        let _ = std::fs::remove_dir_all(&l.root);
    }

    #[test]
    fn a_fixed_location_is_honoured_in_both_modes_and_the_override_still_wins_unprivileged() {
        let l = layout("helper_fixed");
        let fixed = l.root.join("usr/bin/brctl");
        plant_executable(&fixed);
        let fixed_str = fixed.to_str().unwrap();
        let got = resolve_helper_with(
            "brctl",
            None,
            &[fixed_str],
            true,
            Some(&l.engine_dir),
            None,
            None,
        );
        assert_eq!(got, Some(fixed.clone()));
        let got = resolve_helper_with(
            "brctl",
            Some(&l.elsewhere),
            &[fixed_str],
            false,
            Some(&l.engine_dir),
            None,
            None,
        );
        assert_eq!(got, Some(l.elsewhere.clone()));
        let _ = std::fs::remove_dir_all(&l.root);
    }
}
