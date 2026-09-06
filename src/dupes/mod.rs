//! Duplicate-file engine — the engine port of burrow-cli's `dupes` command.
//!
//! Wraps the `fclones` sidecar (MIT) via its stdout->stdin round-trip: `fclones group
//! --format json <paths>` emits a report to stdout; `fclones dedupe|remove|link` read that
//! report from stdin. `dedupe` uses APFS `clonefile` on macOS (reclaim space without
//! deleting). Safety: the mutating actions only run with `--apply`; otherwise the command
//! returns the group report (read-only) or fclones's own `--dry-run` preview.
//!
//! The report filtering (`filter_report`, `filter_same_volume`) is pure — string in, string
//! out — and rides the engine's zero-dep JSON reader/writer, so it's fully unit-tested against
//! synthetic fclones reports without spawning fclones.

use crate::json::Json;
use std::path::{Path, PathBuf};

/// The three fclones verbs a mutating `dupes` plan can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupesAction {
    /// APFS clonefile within one volume (`fclones dedupe`).
    Dedupe,
    /// Delete every copy but the kept one (`fclones remove`).
    Remove,
    /// Replace the copies with hard links (`fclones link`).
    Link,
}

impl DupesAction {
    /// The subcommand word, as the argv and the preview JSON spell it.
    pub fn verb(self) -> &'static str {
        match self {
            DupesAction::Dedupe => "dedupe",
            DupesAction::Remove => "remove",
            DupesAction::Link => "link",
        }
    }

    fn parse(sub: &str) -> Option<Self> {
        match sub {
            "dedupe" => Some(DupesAction::Dedupe),
            "remove" => Some(DupesAction::Remove),
            "link" => Some(DupesAction::Link),
            _ => None,
        }
    }
}

/// What a `dupes` invocation resolves to.
#[derive(Debug, PartialEq, Eq)]
pub enum DupesPlan {
    /// Read-only: `fclones group --format json <paths>`.
    Group { paths: Vec<String> },
    /// Read-only preview of a mutating action: the filtered report piped into
    /// `fclones <action> --dry-run` — exactly what --apply would execute, executing nothing.
    Preview {
        paths: Vec<String>,
        action: DupesAction,
        keep: Vec<String>,
    },
    /// Mutating (requires --apply): `fclones group ... | keep-rule filter | fclones <action>`.
    /// Files under any `keep` reference folder are never acted on.
    Action {
        paths: Vec<String>,
        action: DupesAction,
        keep: Vec<String>,
    },
}

/// The `feature` a refused duplicate MUTATION carries. burrow-cli's wording, kept verbatim so the
/// envelope a caller sees is the one it saw before this command moved into the engine.
pub const APPLY_FEATURE: &str = "dupes apply";

/// The refusal detail, byte-for-byte the string burrow-cli emitted. See [`apply_refusal`].
pub const WINDOWS_APPLY_REFUSAL: &str = "Windows duplicate discovery is read-only; dedupe/remove/link apply actions are macOS/fclones-only.";

/// `Some(detail)` when a duplicate MUTATION must be refused on `os`, `None` when it may run.
///
/// THIS IS A RESTORED GUARD, NOT A NEW POLICY, and the distinction matters because everything else
/// Windows lost in `3633c19` was a CAPABILITY this engine declines honestly — `net` has no
/// IP-Helper walk, `orphans` has no registry inventory, `evict` has no OneDrive provider, and each
/// says so. This one was the opposite: a refusal that stood between a real, installed, perfectly
/// functional `fclones.exe` and a delete. burrow-cli carried it in `run_dupes`
/// (`src/main.rs:161-169` at `3633c19^`, and again at `:563` in `run_czkawka_duplicates` so the
/// Windows discovery fallback could not be talked into one either; both deleted in `3633c19`):
///
/// ```text
/// if platform::is_windows() && args.iter().any(|a| a == "--apply") {
///     return emit_failure(
///         "dupes",
///         platform::unsupported(
///             "dupes apply",
///             "Windows duplicate discovery is read-only; dedupe/remove/link apply actions are macOS/fclones-only.",
///         ),
///     );
/// }
/// ```
///
/// and its README turned that into a promise: "**Burrow does not delete duplicate files on
/// Windows.**" Nothing in this crate's `src/dupes/` replaced it — [`resolve_fclones`] deliberately
/// resolves `.exe` off `PATH`, so `dupes remove <dir> --apply` reached fclones and deleted.
///
/// Three details of the original are load-bearing and are reproduced rather than tidied:
///
///  - **Windows, not "not macOS".** fclones is cross-platform and its `dedupe` reflink path works
///    on Linux filesystems that support it, so refusing there would invent a limit the oracle
///    never had. Only Windows is refused — that is where the oracle drew the line and where
///    `dedupe`'s APFS `clonefile` genuinely has no counterpart.
///  - **It fires even with `$BURROW_FCLONES` set.** The oracle hoisted this gate ABOVE its czkawka
///    fallback and above `resolve_fclones`, so pointing the engine at a real fclones did not buy
///    back the mutation. Both call sites here keep that order: the CLI arm refuses before it
///    resolves a binary, and [`execute`] refuses before it spawns one.
///  - **Read-only `dupes` is untouched.** `group` is the default subcommand and works on Windows;
///    so does a `dedupe`/`remove`/`link` PREVIEW, which is fclones' own `--dry-run`. The oracle
///    keyed on `--apply` in argv, and the argv-level call site keys on the same thing — refusing
///    the mutating INTENT rather than the command.
pub fn apply_refusal(os: &str) -> Option<&'static str> {
    if os == "windows" {
        return Some(WINDOWS_APPLY_REFUSAL);
    }
    None
}

fn is_flag(a: &str) -> bool {
    a.starts_with("--")
}

/// Split out the repeatable `--keep <dir>` reference-folder args (whose VALUES must not be
/// mistaken for scan paths). Returns (keep_dirs, remaining_args).
pub fn split_keep(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut keep = Vec::new();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--keep" {
            if i + 1 < args.len() {
                keep.push(args[i + 1].clone());
                i += 2;
                continue;
            }
            i += 1; // trailing --keep with no value: ignore
            continue;
        }
        rest.push(args[i].clone());
        i += 1;
    }
    (keep, rest)
}

/// Map a `dupes` subcommand + args to a plan. Without `apply` (the caller's `wants_apply` — the
/// one `--apply` reader is `cli.rs`), the mutating subcommands (dedupe/remove/link) degrade to a
/// read-only `Preview` (fclones's own dry-run).
pub fn plan(sub: &str, args: &[String], apply: bool) -> Result<DupesPlan, String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--keep"
            && args
                .get(i + 1)
                .is_none_or(|value| value.is_empty() || value.starts_with('-'))
        {
            return Err("dupes: --keep needs a directory".into());
        }
    }
    let (keep, rest) = split_keep(args);
    let paths: Vec<String> = rest.iter().filter(|a| !is_flag(a)).cloned().collect();
    if paths.is_empty() {
        return Err("dupes: needs at least one path to scan".into());
    }
    match sub {
        "group" => Ok(DupesPlan::Group { paths }),
        "dedupe" | "remove" | "link" => {
            let action = DupesAction::parse(sub).expect("matched above");
            if apply {
                Ok(DupesPlan::Action {
                    paths,
                    action,
                    keep,
                })
            } else {
                Ok(DupesPlan::Preview {
                    paths,
                    action,
                    keep,
                })
            }
        }
        other => Err(format!("dupes: unknown subcommand '{other}'")),
    }
}

/// Is `path` inside any of `dirs`? Component-wise (Path::starts_with), so `/refsX` is NOT
/// under `/refs`.
fn under_any(path: &str, dirs: &[String]) -> bool {
    fn resolved(path: &str) -> PathBuf {
        let path = Path::new(path);
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        // A report entry can disappear between grouping and filtering. Resolve its
        // surviving ancestor so it still compares in the keep root's namespace:
        // Windows canonical paths have a verbatim prefix, and Unix parents may
        // be symlinks. Falling back to the whole lexical path loses both facts.
        let physical = absolute
            .ancestors()
            .find_map(|ancestor| {
                let root = ancestor.canonicalize().ok()?;
                Some(root.join(absolute.strip_prefix(ancestor).ok()?))
            })
            .unwrap_or(absolute);
        let mut normalized = PathBuf::new();
        for part in physical.components() {
            match part {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        normalized
    }
    let p = resolved(path);
    dirs.iter().any(|d| p.starts_with(resolved(d)))
}

/// The string values of a group's `files` array (skips non-strings).
fn file_strings(files: &[Json]) -> Vec<String> {
    files
        .iter()
        .filter_map(|f| f.as_str().map(str::to_string))
        .collect()
}

/// Replace a group's `files` array with `new`, preserving the rest of the group object.
fn set_files(group: &mut Json, new: Vec<String>) {
    if let Some(f) = group.get_mut("files").and_then(Json::as_array_mut) {
        *f = new.into_iter().map(Json::String).collect();
    }
}

/// Keep-rule filtering between `group` and a mutating action: files under a `--keep` reference
/// folder are never acted on. fclones keeps each group's FIRST file and acts on the rest, so at
/// most ONE protected file may lead a group (it becomes the kept reference); every other
/// protected copy is removed from the report entirely, and groups with nothing actionable (all
/// copies protected, or a lone survivor) are dropped. Returns the filtered report + how many
/// actionable groups remain.
pub fn filter_report(report: &str, keep: &[String]) -> Result<(String, usize), String> {
    let mut v = Json::parse(report).map_err(|e| format!("unparseable fclones report: {e}"))?;
    let Some(groups) = v.get_mut("groups").and_then(Json::as_array_mut) else {
        return Err("fclones report has no groups[]".into());
    };
    groups.retain_mut(|g| {
        let Some(files) = g.get_mut("files").and_then(Json::as_array_mut) else {
            return false;
        };
        let taken = file_strings(files);
        let (protected, actionable): (Vec<_>, Vec<_>) =
            taken.into_iter().partition(|p| under_any(p, keep));
        if actionable.is_empty() || (protected.is_empty() && actionable.len() < 2) {
            return false; // nothing to act on / degenerate group
        }
        let mut kept = protected.into_iter().take(1).collect::<Vec<_>>();
        kept.extend(actionable);
        set_files(g, kept);
        true
    });
    let n = groups.len();
    Ok((v.to_json_string(), n))
}

/// Per-volume guard for `dedupe` (APFS clonefile only works within one volume): drop a file
/// from its group only on POSITIVE knowledge that it sits on a different device than the
/// group's kept file (best-effort — unresolvable devices pass through; fclones itself errors
/// on a real cross-volume clone). Groups left with <2 files are dropped.
pub fn filter_same_volume(
    report: &str,
    dev_of: impl Fn(&str) -> Option<u64>,
) -> Result<(String, usize), String> {
    let mut v = Json::parse(report).map_err(|e| format!("unparseable fclones report: {e}"))?;
    let Some(groups) = v.get_mut("groups").and_then(Json::as_array_mut) else {
        return Err("fclones report has no groups[]".into());
    };
    groups.retain_mut(|g| {
        let Some(files) = g.get_mut("files").and_then(Json::as_array_mut) else {
            return false;
        };
        let taken = file_strings(files);
        let kept_dev = taken.first().and_then(|f| dev_of(f));
        let mut out = Vec::new();
        for (i, f) in taken.into_iter().enumerate() {
            if i > 0 {
                let d = dev_of(&f);
                if let (Some(k), Some(d)) = (kept_dev, d) {
                    if k != d {
                        continue; // positively cross-volume -> not clonable, drop
                    }
                }
            }
            out.push(f);
        }
        if out.len() < 2 {
            return false;
        }
        set_files(g, out);
        true
    });
    let n = groups.len();
    Ok((v.to_json_string(), n))
}

/// Real device id for the volume guard. Unix stats the file; elsewhere unknown (permissive —
/// the guard only drops on positive cross-device knowledge).
#[cfg(unix)]
fn device_of(path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| m.dev())
}
#[cfg(not(unix))]
fn device_of(_path: &str) -> Option<u64> {
    None
}

/// Resolve the fclones binary: `$BURROW_FCLONES`, else `fclones` on `PATH`.
///
/// Both halves go through [`crate::platform`], which is what makes the `PATH` half work off macOS at
/// all: this used to join the BARE name onto each `PATH` entry and ask `.exists()`, so a Windows
/// machine with a perfectly good `fclones.exe` installed reported "fclones not found" — and fclones
/// is genuinely cross-platform, so that is a real install this engine could not see. The `.exists()`
/// half was the second bug in the same line: a DIRECTORY named `fclones` on `PATH` satisfied it and
/// was handed to `Command::new`.
///
/// The bundled sidecar arrives through the OVERRIDE, not through a lookup of its own: the macOS app
/// ships `Resources/fclones` and points `$BURROW_FCLONES` at it (`BurrowConductor.environment`,
/// which leaves a user's own `$BURROW_FCLONES` alone if they set one). So there is no
/// "next to my own binary" search here to carry the same bare-name assumption — this engine never
/// looks there, and on Windows, where nothing bundles fclones today, the `PATH` scan above is the
/// only route to one.
///
/// Under elevation the override and `PATH` are not trusted — see
/// [`crate::platform::resolve_helper`]: only a sidecar beside the engine binary or a copy in a
/// trusted system directory is run as root.
pub fn resolve_fclones() -> Result<PathBuf, String> {
    crate::platform::resolve_helper("fclones", Some("BURROW_FCLONES"), &[]).ok_or_else(|| {
        "fclones not found; install it (cargo install fclones) or set BURROW_FCLONES".to_string()
    })
}

/// The fclones seam: `(fclones, args, stdin)` → stdout. Production is [`system_fclones`]; tests
/// pass a fake, so every plan is driven without an fclones binary.
pub type FclonesRunner<'a> = &'a dyn Fn(&Path, &[&str], Option<&str>) -> Result<String, String>;

/// The real thing: spawn `fclones <args>`, stream `stdin` into it when given, and hand back
/// stdout — a non-zero exit is an error carrying the verb, the status and fclones's stderr.
pub fn system_fclones(
    fclones: &Path,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<String, String> {
    let verb = args.first().copied().unwrap_or("");
    let mut command = std::process::Command::new(fclones);
    command.args(args);
    let out = crate::platform::run_command_with_input(command, stdin)
        .map_err(|e| format!("failed to run fclones {verb}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "fclones {verb} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `fclones group --format json <paths>` through `run`.
fn group_report(
    run: FclonesRunner<'_>,
    fclones: &Path,
    paths: &[String],
) -> Result<String, String> {
    let mut args = vec!["group", "--format", "json"];
    args.extend(paths.iter().map(String::as_str));
    run(fclones, &args, None)
}

/// group -> keep-rule filter -> (dedupe only) per-volume guard. Returns the filtered report +
/// actionable group count, shared by Preview and Action.
fn filtered_report(
    run: FclonesRunner<'_>,
    fclones: &Path,
    paths: &[String],
    action: DupesAction,
    keep: &[String],
) -> Result<(String, usize), String> {
    let raw = group_report(run, fclones, paths)?;
    let (mut report, mut actionable) = filter_report(&raw, keep)?;
    if action == DupesAction::Dedupe {
        let (r, n) = filter_same_volume(&report, device_of)?;
        report = r;
        actionable = n;
    }
    Ok((report, actionable))
}

const NOTHING_ACTIONABLE: &str = concat!(
    r#"{"skipped":true,"groups":0,"reason":"no actionable duplicate groups "#,
    r#"(all copies protected by --keep, cross-volume, or singletons)"}"#
);

/// Pipe a report into `fclones <action> [extra…]` through `run`, returning its stdout.
fn pipe_report(
    run: FclonesRunner<'_>,
    fclones: &Path,
    action: &str,
    extra: &[&str],
    report: &str,
) -> Result<String, String> {
    let mut args = vec![action];
    args.extend_from_slice(extra);
    run(fclones, &args, Some(report))
}

/// Build the `{preview:true,action,groups,plan:[…]}` JSON from an fclones dry-run's stdout.
fn preview_json(action: &str, groups: usize, dry_run_out: &str) -> String {
    use crate::json::escape as esc;
    let plan = dry_run_out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(esc)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"preview\":true,\"action\":{},\"groups\":{groups},\"plan\":[{plan}]}}",
        esc(action)
    )
}

/// Execute a plan and return the resulting JSON (group report, dry-run preview, or action result).
pub fn execute(fclones: &Path, plan: &DupesPlan) -> Result<String, String> {
    execute_with(fclones, plan, &system_fclones)
}

/// [`execute`] with the fclones invocation injected — every plan, including the mutating one's
/// refusal, is driven by a fake.
pub fn execute_with(
    fclones: &Path,
    plan: &DupesPlan,
    run: FclonesRunner<'_>,
) -> Result<String, String> {
    match plan {
        DupesPlan::Group { paths } => group_report(run, fclones, paths),
        DupesPlan::Preview {
            paths,
            action,
            keep,
        } => {
            let (report, actionable) = filtered_report(run, fclones, paths, *action, keep)?;
            if actionable == 0 {
                return Ok(NOTHING_ACTIONABLE.into());
            }
            // fclones's own dry-run IS the preview: the exact commands --apply would run.
            let out = pipe_report(run, fclones, action.verb(), &["--dry-run"], &report)?;
            Ok(preview_json(action.verb(), actionable, &out))
        }
        DupesPlan::Action {
            paths,
            action,
            keep,
        } => {
            // THE SECOND HALF OF THE RESTORED GUARD, at the last point before the delete.
            //
            // The CLI arm refuses this argv before it even resolves a binary, so from `dispatch`
            // this branch is unreachable — `DupesPlan::Action` exists only when `--apply` was in
            // argv, which is exactly what that gate keys on. It is here anyway because `execute`
            // is `pub` and the CLI is not its only caller: the whole reason this refusal belongs
            // in the engine rather than back in burrow-cli is that a second conductor, a GUI, or a
            // test harness can build an `Action` plan directly, and a guard that lives only in one
            // caller's argv parsing protects only that caller.
            //
            // Note WHERE it sits: before `filtered_report`, so nothing is even grouped, and well
            // before `pipe_report(fclones, action, &[], …)` — the one call in this file that runs
            // an fclones action with no `--dry-run`, i.e. the line that does the deleting.
            if let Some(detail) = apply_refusal(std::env::consts::OS) {
                return Err(format!(
                    "dupes {} --apply is unsupported here: {detail}",
                    action.verb()
                ));
            }
            let (report, actionable) = filtered_report(run, fclones, paths, *action, keep)?;
            if actionable == 0 {
                return Ok(NOTHING_ACTIONABLE.into());
            }
            pipe_report(run, fclones, action.verb(), &[], &report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn files_of(report: &str, group: usize) -> Vec<String> {
        let v = Json::parse(report).unwrap();
        v.get("groups")
            .and_then(|g| g.at(group))
            .and_then(|g| g.get("files"))
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .map(|f| f.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn group_is_default_readonly() {
        assert_eq!(
            plan("group", &a(&["/tmp"]), false).unwrap(),
            DupesPlan::Group {
                paths: a(&["/tmp"])
            }
        );
    }

    #[test]
    fn dedupe_without_apply_is_preview() {
        assert_eq!(
            plan("dedupe", &a(&["/tmp"]), false).unwrap(),
            DupesPlan::Preview {
                paths: a(&["/tmp"]),
                action: DupesAction::Dedupe,
                keep: vec![]
            }
        );
    }

    #[test]
    fn dedupe_apply_is_action() {
        assert_eq!(
            plan("dedupe", &a(&["/tmp", "--apply"]), true).unwrap(),
            DupesPlan::Action {
                paths: a(&["/tmp"]),
                action: DupesAction::Dedupe,
                keep: vec![]
            }
        );
    }

    #[test]
    fn remove_and_link_apply() {
        assert_eq!(
            plan("remove", &a(&["--apply", "/tmp"]), true).unwrap(),
            DupesPlan::Action {
                paths: a(&["/tmp"]),
                action: DupesAction::Remove,
                keep: vec![]
            }
        );
        assert_eq!(
            plan("link", &a(&["/tmp", "--apply"]), true).unwrap(),
            DupesPlan::Action {
                paths: a(&["/tmp"]),
                action: DupesAction::Link,
                keep: vec![]
            }
        );
    }

    #[test]
    fn needs_a_path() {
        assert!(plan("group", &[], false).is_err());
        assert!(plan("dedupe", &a(&["--apply"]), true).is_err());
    }

    #[test]
    fn unknown_subcommand_errors() {
        assert!(plan("frobnicate", &a(&["/tmp"]), false).is_err());
    }

    #[test]
    fn split_keep_extracts_reference_dirs_and_their_values() {
        let (keep, rest) = split_keep(&a(&["--keep", "/refs", "/scan", "--apply"]));
        assert_eq!(keep, a(&["/refs"]));
        assert_eq!(rest, a(&["/scan", "--apply"]));
    }

    #[test]
    fn keep_value_is_not_mistaken_for_a_scan_path() {
        let p = plan("remove", &a(&["--keep", "/refs", "/scan", "--apply"]), true).unwrap();
        match p {
            DupesPlan::Action { paths, keep, .. } => {
                assert_eq!(paths, a(&["/scan"]));
                assert_eq!(keep, a(&["/refs"]));
            }
            other => panic!("expected Action, got {other:?}"),
        }
    }

    const REPORT: &str = r#"{"header":{"stats":{"redundant_file_size":10}},"groups":[
        {"file_len":5,"file_hash":"h1","files":["/refs/a.txt","/scan/a.txt","/scan/b.txt"]},
        {"file_len":5,"file_hash":"h2","files":["/refs/x.txt","/refs/y.txt"]},
        {"file_len":5,"file_hash":"h3","files":["/scan/c.txt","/scan/d.txt"]}]}"#;

    #[test]
    fn filter_report_protects_reference_files_and_acts_on_the_rest() {
        let (out, actionable) = filter_report(REPORT, &a(&["/refs"])).unwrap();
        // Group h2 (all files protected) is dropped entirely; h1 + h3 stay.
        assert_eq!(actionable, 2);
        assert_eq!(
            Json::parse(&out)
                .unwrap()
                .get("groups")
                .and_then(Json::as_array)
                .unwrap()
                .len(),
            2
        );
        // h1: the protected file leads (fclones keeps files[0]), both scan copies are acted on.
        assert_eq!(
            files_of(&out, 0),
            a(&["/refs/a.txt", "/scan/a.txt", "/scan/b.txt"])
        );
    }

    #[test]
    fn filter_report_never_exposes_extra_protected_copies_to_the_action() {
        // Two protected copies + one actionable: only ONE protected file may lead the group
        // (fclones acts on everything after files[0]) — the other must vanish from the report.
        let report = r#"{"groups":[{"files":["/scan/z.txt","/refs/p1.txt","/refs/p2.txt"]}]}"#;
        let (out, actionable) = filter_report(report, &a(&["/refs"])).unwrap();
        assert_eq!(actionable, 1);
        assert_eq!(
            files_of(&out, 0),
            a(&["/refs/p1.txt", "/scan/z.txt"]),
            "p2 must not be in the report at all"
        );
    }

    #[test]
    fn filter_report_without_keep_dirs_leaves_groups_intact() {
        let (out, actionable) = filter_report(REPORT, &[]).unwrap();
        assert_eq!(actionable, 3);
        assert_eq!(
            Json::parse(&out)
                .unwrap()
                .get("groups")
                .and_then(Json::as_array)
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            files_of(&out, 0)[0],
            "/refs/a.txt",
            "order untouched without keep rules"
        );
    }

    #[test]
    fn filter_report_preserves_sibling_group_fields() {
        // The header + each group's file_len/file_hash must survive the round-trip untouched.
        let (out, _) = filter_report(REPORT, &a(&["/refs"])).unwrap();
        let v = Json::parse(&out).unwrap();
        assert_eq!(
            v.get("header")
                .and_then(|h| h.get("stats"))
                .and_then(|s| s.get("redundant_file_size"))
                .and_then(Json::as_u64),
            Some(10)
        );
        assert_eq!(
            v.get("groups")
                .and_then(|g| g.at(0))
                .and_then(|g| g.get("file_hash"))
                .and_then(Json::as_str),
            Some("h1")
        );
    }

    #[test]
    fn keep_matches_whole_path_components_only() {
        // /refsX/f.txt is NOT under /refs — prefix matching must be component-wise.
        let report = r#"{"groups":[{"files":["/refsX/f.txt","/scan/f.txt"]}]}"#;
        let (out, _) = filter_report(report, &a(&["/refs"])).unwrap();
        assert_eq!(
            files_of(&out, 0).len(),
            2,
            "no file may be treated as protected"
        );
        assert_eq!(files_of(&out, 0)[0], "/refsX/f.txt");
    }

    #[test]
    fn keep_protects_missing_report_entries_under_an_existing_root() {
        let root =
            std::env::temp_dir().join(format!("burrow_dupes_keep_missing_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("missing/first");
        let second = root.join("missing/second");
        let report = format!(
            r#"{{"groups":[{{"files":[{},{}]}}]}}"#,
            crate::json::escape(first.to_str().unwrap()),
            crate::json::escape(second.to_str().unwrap())
        );
        let (filtered, actionable) =
            filter_report(&report, &[root.to_str().unwrap().to_string()]).unwrap();
        assert_eq!(
            actionable, 0,
            "the keep root protects stale entries: {filtered}"
        );
        assert!(
            !first.exists() && !second.exists(),
            "filtering stays read-only"
        );
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn same_volume_filter_drops_cross_device_files_for_dedupe() {
        let report = r#"{"groups":[{"files":["/vol1/a","/vol1/b","/vol2/c"]},{"files":["/vol1/d","/vol2/e"]}]}"#;
        let dev = |p: &str| -> Option<u64> {
            if p.starts_with("/vol1") {
                Some(1)
            } else {
                Some(2)
            }
        };
        let (out, actionable) = filter_same_volume(report, dev).unwrap();
        // Group 1 keeps its same-device pair; group 2 (kept file alone on vol1) is dropped.
        assert_eq!(actionable, 1);
        assert_eq!(
            Json::parse(&out)
                .unwrap()
                .get("groups")
                .and_then(Json::as_array)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(files_of(&out, 0), a(&["/vol1/a", "/vol1/b"]));
    }

    #[test]
    fn same_volume_passes_through_unknown_devices() {
        // dev_of returns None -> no positive cross-device knowledge -> nothing dropped.
        let report = r#"{"groups":[{"files":["/x/a","/y/b"]}]}"#;
        let (out, actionable) = filter_same_volume(report, |_| None).unwrap();
        assert_eq!(actionable, 1);
        assert_eq!(files_of(&out, 0), a(&["/x/a", "/y/b"]));
    }

    #[test]
    fn filter_errors_on_missing_groups() {
        assert!(filter_report(r#"{"nope":1}"#, &[]).is_err());
        assert!(filter_report("not json", &[]).is_err());
    }

    #[test]
    fn preview_json_splits_plan_lines() {
        let j = preview_json("dedupe", 2, "cp -c /a /b\n\ncp -c /c /d\n");
        let v = Json::parse(&j).unwrap();
        assert_eq!(v.get("preview").and_then(Json::as_bool), Some(true));
        assert_eq!(v.get("action").and_then(Json::as_str), Some("dedupe"));
        assert_eq!(v.get("groups").and_then(Json::as_u64), Some(2));
        assert_eq!(
            v.get("plan").and_then(Json::as_array).unwrap().len(),
            2,
            "blank line dropped"
        );
    }

    // ---------------------------------------------------------------------------------------
    // The envelope boundary: `dupes` is the only command whose `data` is a foreign process's
    // stdout, and it is the only one that ever emitted a document that did not parse.
    // ---------------------------------------------------------------------------------------

    /// The oracle's capture of a `dupes <remove|link|dedupe> --apply`, from the real shipping
    /// binary — see `dupes-apply.golden.provenance.txt`. All three actions produced this
    /// byte-for-byte.
    const GOLDEN_APPLY: &str = include_str!("dupes-apply.golden.json");

    /// The oracle's capture of `dupes group` over `make_fixtures.sh`'s `dupes_fixture` — a real
    /// fclones report, used here as a REAL payload for the JSON branch rather than a typed-out
    /// stand-in.
    const GOLDEN_GROUP: &str = include_str!("dupes.golden.json");

    /// `dupes … --apply` shipped emitting `{…,"data":}` — no value, not JSON at all — because
    /// `fclones remove|link|dedupe` report on STDERR and leave stdout EMPTY, and the envelope
    /// spliced that empty string in verbatim. The run had already deleted the file, so every
    /// consumer failed to decode a SUCCESS.
    ///
    /// The input is not invented: it is read back out of the golden's own `data.text`, which IS
    /// the stdout the oracle captured. So a re-capture moves the input and the expectation
    /// together, and nothing here is a hand-typed shape (RULEBOOK §3e). The assertion that does
    /// the work is the `Json::parse` — a substring check would have passed against `"data":`
    /// quite happily, which is precisely how this survived.
    ///
    /// `burrow_cli` and `engine` are deliberately NOT compared: `envelope.golden.provenance.txt`
    /// records that the oracle reports `0.0.1`/`fclones` (it drove the sidecar itself) where this
    /// engine reports its own version and `burrow-engine`, and that those two vary legitimately.
    #[test]
    fn a_dupes_apply_emits_the_oracles_envelope_and_not_a_document_that_cannot_parse() {
        let golden = Json::parse(GOLDEN_APPLY).expect("vendored golden must parse");
        let fclones_stdout = golden
            .get("data")
            .and_then(|d| d.get("text"))
            .and_then(Json::as_str)
            .expect("the golden's data.text IS the captured fclones stdout");

        let out = crate::cli::dupes_envelope(fclones_stdout);
        let parsed = Json::parse(&out)
            .unwrap_or_else(|e| panic!("an apply must emit parseable JSON ({e}), got: {out}"));

        let (Json::Object(golden_map), Json::Object(parsed_map)) = (&golden, &parsed) else {
            panic!("both envelopes must be objects");
        };
        assert_eq!(
            parsed_map.keys().collect::<Vec<_>>(),
            golden_map.keys().collect::<Vec<_>>(),
            "the wrapper key set must match the oracle's: {out}"
        );
        assert_eq!(parsed.get("ok"), golden.get("ok"), "{out}");
        assert_eq!(parsed.get("command"), golden.get("command"), "{out}");
        assert_eq!(
            parsed.get("data"),
            golden.get("data"),
            "the oracle answers an apply with TEXT — it reports no file count and no bytes freed, \
             because fclones's tally is on stderr and the oracle never reads it. A structured \
             result here would be a shape BurrowConductor and the MCP tools were never written \
             against: {out}"
        );
    }

    /// The other half of the same change: routing through `wrap` must leave every payload that
    /// ALREADY is JSON spliced in verbatim, or the fix would have traded one broken shape for
    /// three. All three read payloads are the real constructors, not stand-ins — the oracle's own
    /// captured fclones report, the actual `NOTHING_ACTIONABLE` constant the nothing-to-do path
    /// returns, and `preview_json`'s real output.
    #[test]
    fn the_read_payloads_still_ride_verbatim_as_data() {
        for (label, payload) in [
            ("group report", GOLDEN_GROUP.to_string()),
            ("nothing actionable", NOTHING_ACTIONABLE.to_string()),
            (
                "preview",
                preview_json("dedupe", 2, "cp -c /a/one.bin /b/one_copy.bin\n"),
            ),
        ] {
            let expected = Json::parse(&payload)
                .unwrap_or_else(|e| panic!("{label} must be valid JSON to begin with ({e})"));
            let out = crate::cli::dupes_envelope(&payload);
            let parsed = Json::parse(&out)
                .unwrap_or_else(|e| panic!("{label} must emit parseable JSON ({e}): {out}"));
            assert_eq!(
                parsed.get("data"),
                Some(&expected),
                "{label} must ride as `data` verbatim — wrapping it as {{\"text\":…}} would hand \
                 every caller a string where it decodes an object: {out}"
            );
        }
    }

    /// The restored Windows delete-guard, and the three things about it that a tidier version
    /// would get wrong. Every assertion runs on every host, because [`apply_refusal`] is asked
    /// about an OS rather than about the one it happens to be compiled for.
    ///
    /// The detail string is compared verbatim against burrow-cli's, because it is not decoration:
    /// it is what a caller reads out of `error.message`, and the README promise it backs
    /// ("Burrow does not delete duplicate files on Windows") was written about these words.
    //
    // check_tests: no-golden — no capture exists or could: a golden of this would have to be taken
    // by running a mutating dupes action on a Windows box, which is the thing being refused. The
    // oracle is the deleted source, quoted in `apply_refusal`'s doc comment.
    #[test]
    fn the_windows_delete_guard_refuses_mutation_without_refusing_discovery() {
        assert_eq!(
            apply_refusal("windows"),
            Some(WINDOWS_APPLY_REFUSAL),
            "the guard burrow-cli carried at src/main.rs:161-169 must still answer for Windows"
        );
        assert_eq!(
            WINDOWS_APPLY_REFUSAL,
            "Windows duplicate discovery is read-only; dedupe/remove/link apply actions are \
             macOS/fclones-only.",
            "verbatim from the deleted guard — a caller reads this, and a README promises it"
        );
        assert_eq!(
            APPLY_FEATURE, "dupes apply",
            "the oracle's own feature name"
        );

        // NOT refused anywhere else. fclones is cross-platform and its reflink dedupe works on
        // Linux filesystems that support it; the oracle refused Windows alone, and widening that
        // would invent a limit rather than restore one.
        for os in ["macos", "linux", "freebsd"] {
            assert_eq!(
                apply_refusal(os),
                None,
                "{os} was never refused by the oracle and must not start being refused here"
            );
        }
    }

    /// WHAT THE GUARD IS STANDING IN FRONT OF, measured rather than asserted in prose — the half
    /// that says removing it has a cost. `plan` is pure, so these answers are byte-identical on
    /// every host, which makes this a real measurement of the Windows behaviour and not an
    /// analogy for it.
    ///
    /// Two facts, and together they are the whole risk. First, `--apply` on a mutating subcommand
    /// produces `DupesPlan::Action`, and `Action` is the ONLY arm of [`execute`] that calls
    /// `pipe_report` with an empty `extra` — every other path passes `--dry-run`, so `Action` is
    /// literally the one code path in this file that deletes. Second, nothing between argv and
    /// that call has any platform vocabulary at all: `resolve_fclones` supports `.exe` off `PATH`
    /// deliberately, so on Windows a real fclones resolves and the plan runs.
    #[test]
    fn without_the_guard_the_mutating_argv_reaches_fclones_with_no_dry_run() {
        for action in ["dedupe", "remove", "link"] {
            let with = plan(action, &a(&["/scan", "--apply"]), true).unwrap();
            assert!(
                matches!(with, DupesPlan::Action { .. }),
                "{action} --apply is the destructive plan variant, not a preview"
            );
            let without = plan(action, &a(&["/scan"]), false).unwrap();
            assert!(
                matches!(without, DupesPlan::Preview { .. }),
                "{action} without --apply stays fclones' own --dry-run, which is why the guard \
                 keys on --apply and not on the subcommand"
            );
        }
        // …and `group`, the read-only default, is never an Action however it is spelled — which is
        // why discovery keeps working on Windows and only the mutation is refused.
        assert!(matches!(
            plan("group", &a(&["/scan", "--apply"]), true).unwrap(),
            DupesPlan::Group { .. }
        ));
    }

    /// The guard fires even when a perfectly good fclones was found — the promise the oracle made
    /// by hoisting its check ABOVE `resolve_fclones` and above the czkawka fallback, so
    /// `$BURROW_FCLONES` could not buy the mutation back.
    ///
    /// Proven at the [`execute`] layer, where the binary is a parameter, so the property is tested
    /// by INJECTION instead of by mutating a process-wide environment variable mid-suite (which
    /// races the other tests in this crate — see `io_rate`'s note). The injected path does not
    /// exist, which is what makes the assertion sharp in both directions: on Windows the error is
    /// the refusal, and off Windows it is a SPAWN failure naming that path, i.e. proof that the
    /// very next thing after the guard is the subprocess, and that nothing else was ever going to
    /// stop it.
    #[test]
    fn a_resolved_fclones_does_not_buy_the_mutation_back() {
        let bogus = Path::new("/burrow-engine-test/no-such-fclones");
        let action = DupesPlan::Action {
            paths: a(&["/scan"]),
            action: DupesAction::Remove,
            keep: Vec::new(),
        };
        let err = execute(bogus, &action).expect_err("a missing binary cannot succeed either way");
        if apply_refusal(std::env::consts::OS).is_some() {
            assert!(
                err.contains(WINDOWS_APPLY_REFUSAL),
                "the guard must answer before the spawn is even attempted, got {err:?}"
            );
            assert!(
                err.to_ascii_lowercase().contains("unsupported"),
                "the message must classify as `unsupported` through envelope::error_kind, since a \
                 library caller reaching execute() directly gets no `feature` key: {err:?}"
            );
            assert!(
                !err.contains("failed to run fclones"),
                "nothing may be spawned once the guard has fired: {err:?}"
            );
        } else {
            assert!(
                err.contains("failed to run fclones"),
                "off Windows the guard is silent and the spawn is the next thing to happen — if \
                 this stops being true, the guard has started over-refusing: {err:?}"
            );
        }
    }
    /// Every plan through a fake fclones: the group report rides verbatim, a preview pipes the
    /// keep-filtered report into `<action> --dry-run` and wraps the lines, a fully-protected set is
    /// the `skipped` object without a second spawn, and the exact argv is what burrow-cli sent.
    #[test]
    fn execute_with_drives_every_plan_through_the_injected_fclones() {
        let report = r#"{"groups":[{"file_len":10,"files":["/scan/a","/scan/b","/refs/c"]}]}"#;
        let calls = std::cell::RefCell::new(Vec::<(Vec<String>, Option<String>)>::new());
        let fake = |bin: &Path, args: &[&str], stdin: Option<&str>| -> Result<String, String> {
            assert_eq!(bin, Path::new("/fake/fclones"));
            calls.borrow_mut().push((
                args.iter().map(|a| a.to_string()).collect(),
                stdin.map(String::from),
            ));
            match args[0] {
                "group" => Ok(report.to_string()),
                "remove" => Ok("would remove /scan/b\n\n".to_string()),
                other => Err(format!("unexpected {other}")),
            }
        };
        let bin = Path::new("/fake/fclones");

        let out = execute_with(
            bin,
            &DupesPlan::Group {
                paths: vec!["/scan".into()],
            },
            &fake,
        )
        .unwrap();
        assert_eq!(out, report, "group returns fclones's report untouched");
        assert_eq!(
            calls.borrow()[0].0,
            ["group", "--format", "json", "/scan"],
            "burrow-cli's argv"
        );
        assert_eq!(calls.borrow()[0].1, None);

        let out = execute_with(
            bin,
            &DupesPlan::Preview {
                paths: vec!["/scan".into()],
                action: DupesAction::Remove,
                keep: vec!["/refs".into()],
            },
            &fake,
        )
        .unwrap();
        let parsed = Json::parse(&out).unwrap();
        assert_eq!(parsed.get("preview").and_then(Json::as_bool), Some(true));
        assert_eq!(parsed.get("action").and_then(Json::as_str), Some("remove"));
        assert_eq!(parsed.get("groups").and_then(Json::as_u64), Some(1));
        assert_eq!(
            parsed.get("plan").and_then(Json::as_array).map(<[_]>::len),
            Some(1)
        );
        let (args, stdin) = calls.borrow()[2].clone();
        assert_eq!(args, ["remove", "--dry-run"]);
        let piped = stdin.expect("the report is piped in");
        assert!(
            piped.contains("/refs/c") && piped.contains("/scan/a"),
            "the protected copy leads the group it is kept in: {piped}"
        );

        // Everything under --keep: nothing actionable, and no `remove` spawn at all.
        let before = calls.borrow().len();
        let out = execute_with(
            bin,
            &DupesPlan::Preview {
                paths: vec!["/scan".into()],
                action: DupesAction::Remove,
                keep: vec!["/".into()],
            },
            &fake,
        )
        .unwrap();
        assert_eq!(out, NOTHING_ACTIONABLE);
        assert_eq!(calls.borrow().len(), before + 1, "only the group call");

        // A failing fclones is the caller's error, verbatim.
        let broken = |_: &Path, args: &[&str], _: Option<&str>| -> Result<String, String> {
            Err(format!("fclones {} exited 2: boom", args[0]))
        };
        let err = execute_with(
            bin,
            &DupesPlan::Group {
                paths: vec!["/scan".into()],
            },
            &broken,
        )
        .unwrap_err();
        assert_eq!(err, "fclones group exited 2: boom");
    }
}
