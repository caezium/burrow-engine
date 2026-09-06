//! `rules` — the `burrow.rules/v1` declarative per-app cleaning format, and the three read-only
//! subcommands over a directory of them: `list`, `validate`, `dryrun`.
//!
//! The engine port of burrow-cli's `src/rules.rs` plus the `run_rules` arm at `src/main.rs:238-344`
//! and `build_app_summary` at `:944-964`. Like `sentinel` this is CONDUCTOR-NATIVE
//! (`engine_for` -> `"native"`, `main.rs:968-977`): the whole oracle is those two files, and none
//! of it ever reached the bash engine.
//!
//! Nothing in this module deletes, moves, or writes anything. `dryrun` is a pure report: it reads
//! rule files, expands each target path, and asks the filesystem two questions about it (does it
//! exist; does it satisfy the rule's `when{}` conditions). The ACTION half of the format
//! (`delete`/`truncate`, `trash`/`remove`) is parsed and reported so a caller can see what a rule
//! WOULD do, and is never executed here.
//!
//! ## Why this is hand-parsed
//!
//! burrow-cli deserializes with serde derives. This crate is deliberately zero-dep, so the parse
//! below is written against `crate::json::Json` and reproduces serde's strictness on purpose:
//! a missing required field, a wrong type, or an unknown enum spelling all FAIL the file, because
//! in the oracle they do — and a rule file that fails to parse is skipped by `list`/`dryrun` and
//! reported by `validate`. Being laxer here would quietly admit rule files the oracle rejects.
//!
//! The one thing that cannot be reproduced is serde_json's own diagnostic PROSE. The oracle's
//! parse failures read `rule parse error: EOF while parsing an object at line 2 column 0`; this
//! parser says what is wrong in its own words behind the same `rule parse error: ` prefix. The
//! structure of the report is identical and nothing consumes the message text — see
//! `rules-dryrun.golden.provenance.txt`, which records this as the single divergence.

use crate::json::Json;
use std::path::Path;

// ─── the format ──────────────────────────────────────────────────────────────────────────────

/// Risk tier. `risky` is never preselected, whatever else a rule says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    Safe,
    Caution,
    Risky,
}

impl Risk {
    pub fn as_str(&self) -> &'static str {
        match self {
            Risk::Safe => "safe",
            Risk::Caution => "caution",
            Risk::Risky => "risky",
        }
    }
    fn parse(s: &str) -> Option<Risk> {
        match s {
            "safe" => Some(Risk::Safe),
            "caution" => Some(Risk::Caution),
            "risky" => Some(Risk::Risky),
            _ => None,
        }
    }
}

/// How a target path is expanded into entries. Parsed for fidelity (an unknown spelling must fail
/// the file, as it does under serde) — none of the three read-only subcommands act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Search {
    File,
    Glob,
    WalkFiles,
    #[default]
    WalkAll,
}

impl Search {
    fn parse(s: &str) -> Option<Search> {
        match s {
            "file" => Some(Search::File),
            "glob" => Some(Search::Glob),
            "walk_files" => Some(Search::WalkFiles),
            "walk_all" => Some(Search::WalkAll),
            _ => None,
        }
    }
}

/// The CLOSED action enum — never arbitrary shell, which is what makes every rule statically
/// auditable and dry-runnable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionType {
    Delete,
    Truncate,
}

impl ActionType {
    fn parse(s: &str) -> Option<ActionType> {
        match s {
            "delete" => Some(ActionType::Delete),
            "truncate" => Some(ActionType::Truncate),
            _ => None,
        }
    }
}

/// Recoverable (Trash) vs immediate (remove). Defaults to Trash — the recoverable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Method {
    #[default]
    Trash,
    Remove,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Trash => "trash",
            Method::Remove => "remove",
        }
    }
    fn parse(s: &str) -> Option<Method> {
        match s {
            "trash" => Some(Method::Trash),
            "remove" => Some(Method::Remove),
            _ => None,
        }
    }
}

/// Named conditions gating selection. Every condition PRESENT must hold or the target is not
/// auto-selected; absent means unconditional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conditions {
    pub min_age_days: Option<u64>,
    pub min_size_bytes: Option<u64>,
    pub min_days_unaccessed: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub path: String,
    pub search: Search,
    pub when: Option<Conditions>,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub kind: ActionType,
    pub method: Method,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub risk: Risk,
    pub recommend: bool,
    pub explain: Option<String>,
    /// Per-rule opt-in for AUTOMATED cleaning. Default false; `validate` restricts it to risk:safe.
    pub auto: bool,
    pub targets: Vec<Target>,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct AppSpec {
    pub bundle_ids: Vec<String>,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Provenance {
    /// builtin | community | agent | user
    pub source: String,
    pub evidence: Vec<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleFile {
    pub schema: String,
    pub app: AppSpec,
    pub rules: Vec<Rule>,
    pub provenance: Provenance,
}

// ─── parsing ─────────────────────────────────────────────────────────────────────────────────

fn want_object<'a>(v: &'a Json, what: &str) -> Result<&'a Json, String> {
    match v {
        Json::Object(_) => Ok(v),
        _ => Err(format!("{what}: expected an object")),
    }
}

/// A required string field.
fn req_str(o: &Json, key: &str) -> Result<String, String> {
    match o.get(key) {
        Some(Json::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("field `{key}`: expected a string")),
        None => Err(format!("missing field `{key}`")),
    }
}

/// An optional string field. Absent or `null` -> None, matching `#[serde(default)] Option<String>`.
fn opt_str(o: &Json, key: &str) -> Result<Option<String>, String> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("field `{key}`: expected a string")),
    }
}

/// An optional bool field defaulting to false, matching `#[serde(default)] bool`.
fn opt_bool(o: &Json, key: &str) -> Result<bool, String> {
    match o.get(key) {
        None => Ok(false),
        Some(Json::Bool(b)) => Ok(*b),
        Some(_) => Err(format!("field `{key}`: expected a boolean")),
    }
}

/// An optional unsigned-integer field. A negative or fractional number is rejected — serde's
/// `Option<u64>` refuses both, and silently truncating `min_age_days: 30.5` would change which
/// files a rule selects.
fn opt_u64(o: &Json, key: &str) -> Result<Option<u64>, String> {
    match o.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Number(n))
            if n.is_finite() && *n >= 0.0 && *n < u64::MAX as f64 && n.fract() == 0.0 =>
        {
            Ok(Some(*n as u64))
        }
        Some(Json::Number(_)) => Err(format!(
            "field `{key}`: expected a non-negative whole number"
        )),
        Some(_) => Err(format!("field `{key}`: expected a number")),
    }
}

/// A required array-of-strings field.
fn req_str_array(o: &Json, key: &str) -> Result<Vec<String>, String> {
    let Some(v) = o.get(key) else {
        return Err(format!("missing field `{key}`"));
    };
    let Some(items) = v.as_array() else {
        return Err(format!("field `{key}`: expected an array"));
    };
    items
        .iter()
        .map(|e| match e {
            Json::String(s) => Ok(s.clone()),
            _ => Err(format!("field `{key}`: expected an array of strings")),
        })
        .collect()
}

/// An optional array-of-strings field defaulting to empty.
fn opt_str_array(o: &Json, key: &str) -> Result<Vec<String>, String> {
    match o.get(key) {
        None => Ok(Vec::new()),
        Some(_) => req_str_array(o, key),
    }
}

/// A required enum field, given its parser and the spellings it accepts.
fn req_enum<T>(
    o: &Json,
    key: &str,
    parse: impl Fn(&str) -> Option<T>,
    accepted: &str,
) -> Result<T, String> {
    let s = req_str(o, key)?;
    parse(&s)
        .ok_or_else(|| format!("field `{key}`: unknown variant `{s}`, expected one of {accepted}"))
}

fn parse_conditions(v: &Json) -> Result<Conditions, String> {
    want_object(v, "when")?;
    if let Json::Object(fields) = v {
        if let Some(key) = fields.keys().find(|key| {
            !matches!(
                key.as_str(),
                "min_age_days" | "min_size_bytes" | "min_days_unaccessed"
            )
        }) {
            return Err(format!("when: unknown condition `{key}`"));
        }
    }
    Ok(Conditions {
        min_age_days: opt_u64(v, "min_age_days")?,
        min_size_bytes: opt_u64(v, "min_size_bytes")?,
        min_days_unaccessed: opt_u64(v, "min_days_unaccessed")?,
    })
}

fn parse_target(v: &Json) -> Result<Target, String> {
    want_object(v, "target")?;
    Ok(Target {
        path: req_str(v, "path")?,
        search: match v.get("search") {
            None => Search::default(),
            Some(_) => req_enum(
                v,
                "search",
                Search::parse,
                "`file`, `glob`, `walk_files`, `walk_all`",
            )?,
        },
        when: match v.get("when") {
            None | Some(Json::Null) => None,
            Some(w) => Some(parse_conditions(w)?),
        },
    })
}

fn parse_action(v: &Json) -> Result<Action, String> {
    want_object(v, "action")?;
    Ok(Action {
        // `type` in JSON; `kind` in Rust, because `type` is a keyword. Same rename the oracle does.
        kind: req_enum(v, "type", ActionType::parse, "`delete`, `truncate`")?,
        method: match v.get("method") {
            None => Method::default(),
            Some(_) => req_enum(v, "method", Method::parse, "`trash`, `remove`")?,
        },
    })
}

fn parse_rule(v: &Json) -> Result<Rule, String> {
    want_object(v, "rule")?;
    let Some(targets) = v.get("targets") else {
        return Err("missing field `targets`".to_string());
    };
    let Some(items) = targets.as_array() else {
        return Err("field `targets`: expected an array".to_string());
    };
    Ok(Rule {
        id: req_str(v, "id")?,
        category: req_str(v, "category")?,
        risk: req_enum(v, "risk", Risk::parse, "`safe`, `caution`, `risky`")?,
        recommend: opt_bool(v, "recommend")?,
        explain: opt_str(v, "explain")?,
        auto: opt_bool(v, "auto")?,
        targets: items.iter().map(parse_target).collect::<Result<_, _>>()?,
        action: match v.get("action") {
            Some(a) => parse_action(a)?,
            None => return Err("missing field `action`".to_string()),
        },
    })
}

/// Parse a rule file from JSON. The error is prefixed exactly as the oracle prefixes it
/// (`rules.rs:179-181`), so the string a `validate` problem carries has the same shape.
pub fn parse(json: &str) -> Result<RuleFile, String> {
    let doc = Json::parse(json).map_err(|e| format!("rule parse error: {e}"))?;
    parse_rule_file(&doc).map_err(|e| format!("rule parse error: {e}"))
}

fn parse_rule_file(doc: &Json) -> Result<RuleFile, String> {
    want_object(doc, "rule file")?;
    let app = match doc.get("app") {
        Some(a) => {
            want_object(a, "app")?;
            AppSpec {
                bundle_ids: req_str_array(a, "bundle_ids")?,
                name: req_str(a, "name")?,
            }
        }
        None => return Err("missing field `app`".to_string()),
    };
    let provenance = match doc.get("provenance") {
        Some(p) => {
            want_object(p, "provenance")?;
            Provenance {
                source: req_str(p, "source")?,
                evidence: opt_str_array(p, "evidence")?,
                license: opt_str(p, "license")?,
            }
        }
        None => return Err("missing field `provenance`".to_string()),
    };
    let rules = match doc.get("rules") {
        None => Vec::new(),
        Some(r) => {
            let Some(items) = r.as_array() else {
                return Err("field `rules`: expected an array".to_string());
            };
            items.iter().map(parse_rule).collect::<Result<_, _>>()?
        }
    };
    Ok(RuleFile {
        schema: req_str(doc, "schema")?,
        app,
        rules,
        provenance,
    })
}

// ─── the pure logic ──────────────────────────────────────────────────────────────────────────

/// Validate a rule file; returns human-readable problems (empty = valid). Transcribed from
/// `rules.rs:184-229` — the wording is the contract's, not this port's.
pub fn validate(rf: &RuleFile) -> Vec<String> {
    let mut errs = Vec::new();
    if rf.schema != "burrow.rules/v1" {
        errs.push(format!(
            "schema must be 'burrow.rules/v1', got '{}'",
            rf.schema
        ));
    }
    if rf.app.bundle_ids.is_empty() {
        errs.push("app.bundle_ids must not be empty".into());
    }
    if rf.provenance.source.trim().is_empty() {
        errs.push("provenance.source is required".into());
    }
    for r in &rf.rules {
        if r.targets.is_empty() {
            errs.push(format!("rule '{}' has no targets", r.id));
        }
        if r.risk == Risk::Risky && r.recommend {
            errs.push(format!(
                "rule '{}' is risky but recommend=true (risky must never be preselected)",
                r.id
            ));
        }
        if r.auto && r.risk != Risk::Safe {
            errs.push(format!(
                "rule '{}' is auto but not risk:safe (automation may only touch safe rules)",
                r.id
            ));
        }
        for t in &r.targets {
            if let Some(w) = &t.when {
                if w.min_age_days.is_none()
                    && w.min_size_bytes.is_none()
                    && w.min_days_unaccessed.is_none()
                {
                    errs.push(format!(
                        "rule '{}' target '{}' has an empty when{{}} (name at least one condition)",
                        r.id, t.path
                    ));
                }
            }
        }
    }
    errs
}

/// Whether a rule is preselected in quick-clean. Only `safe` + `recommend`; `risky` never.
///
/// NOTE this does NOT consider `when{}` — the dryrun arm ANDs the condition result in separately
/// (`main.rs:323-324`) while `list` reports this value raw (`main.rs:953`). The two subcommands
/// therefore print DIFFERENT `default_selected` values for the same conditional rule, and both
/// goldens pin their own. That asymmetry is the oracle's, and reproducing it is the point.
pub fn default_selected(r: &Rule) -> bool {
    r.risk == Risk::Safe && r.recommend
}

/// Expand a leading `~` against `home`. (Env-var expansion is not part of the format.)
pub fn expand_path(path: &str, home: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if path == "~" {
        home.to_string()
    } else {
        path.to_string()
    }
}

/// Pure condition check. CONSERVATIVE: a condition whose metadata is unavailable is NOT met — we
/// never auto-select what we cannot verify.
pub fn condition_met(
    c: &Conditions,
    age_days: Option<u64>,
    size_bytes: Option<u64>,
    unaccessed_days: Option<u64>,
) -> bool {
    fn holds(min: Option<u64>, actual: Option<u64>) -> bool {
        match (min, actual) {
            (None, _) => true,
            (Some(m), Some(a)) => a >= m,
            (Some(_), None) => false,
        }
    }
    holds(c.min_age_days, age_days)
        && holds(c.min_size_bytes, size_bytes)
        && holds(c.min_days_unaccessed, unaccessed_days)
}

/// Probe a path's `(age_days, size_bytes, unaccessed_days)` for condition evaluation.
/// Directories report NO size (a recursive walk would be dryrun-hostile), so a `min_size_bytes`
/// condition on a directory is always unmet.
pub fn probe_path(p: &Path) -> (Option<u64>, Option<u64>, Option<u64>) {
    let Ok(md) = std::fs::metadata(p) else {
        return (None, None, None);
    };
    let days_since = |t: std::io::Result<std::time::SystemTime>| {
        t.ok()
            .and_then(|m| m.elapsed().ok())
            .map(|e| e.as_secs() / 86_400)
    };
    let age_days = days_since(md.modified());
    let unaccessed_days = days_since(md.accessed());
    let size = if md.is_file() { Some(md.len()) } else { None };
    (age_days, size, unaccessed_days)
}

/// A rule file loaded from disk (the parse may have failed).
#[derive(Debug)]
pub struct Loaded {
    pub file: String,
    pub result: Result<RuleFile, String>,
}

/// Load every `*.json` rule file in a directory, sorted by path.
///
/// A file that fails to read or parse is KEPT as an `Err` rather than dropped: `list`/`dryrun`
/// skip it silently and only `validate` reports it, which is exactly the oracle's split. An
/// unreadable DIRECTORY, by contrast, is a hard error — unlike `sentinel`, which treats the same
/// input as an empty scan.
pub fn load_dir(dir: &Path) -> Result<Vec<Loaded>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut paths: Vec<_> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();
    Ok(paths
        .into_iter()
        .map(|p| {
            let file = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let result = std::fs::read_to_string(&p)
                .map_err(|e| format!("read error: {e}"))
                .and_then(|s| parse(&s));
            Loaded { file, result }
        })
        .collect())
}

// ─── the three subcommand reports ────────────────────────────────────────────────────────────

/// One row of a `dryrun` report: a single rule target, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryrunItem {
    pub app: String,
    pub rule: String,
    pub risk: &'static str,
    pub default_selected: bool,
    pub method: &'static str,
    pub path: String,
    pub exists: bool,
    /// `None` when the target has no `when{}` — the key is then OMITTED from the JSON, which is
    /// how a caller tells "unconditional" from "conditions checked and met".
    pub condition_met: Option<bool>,
}

/// Resolve every target of every rule into a dryrun row. Touches the filesystem twice per target
/// (`exists`, and `probe_path` only when the target carries conditions) and writes nothing.
///
/// `app_filter` is a bundle id: a file whose `app.bundle_ids` does not contain it is skipped
/// whole. Files that failed to parse are skipped silently — `validate` is where those surface.
pub fn dryrun_items(loaded: &[Loaded], app_filter: Option<&str>, home: &str) -> Vec<DryrunItem> {
    let mut items = Vec::new();
    for l in loaded {
        let Ok(rf) = &l.result else { continue };
        if let Some(f) = app_filter {
            if !rf.app.bundle_ids.iter().any(|b| b == f) {
                continue;
            }
        }
        for r in &rf.rules {
            for t in &r.targets {
                let p = expand_path(&t.path, home);
                let exists = Path::new(&p).exists();
                let met = t.when.as_ref().map(|w| {
                    let (age, size, unaccessed) = probe_path(Path::new(&p));
                    condition_met(w, age, size, unaccessed)
                });
                items.push(DryrunItem {
                    app: rf.app.name.clone(),
                    rule: r.id.clone(),
                    risk: r.risk.as_str(),
                    default_selected: default_selected(r) && met.unwrap_or(true),
                    method: r.action.method.as_str(),
                    path: p,
                    exists,
                    condition_met: met,
                });
            }
        }
    }
    items
}

/// `{"items":[…]}` — the `dryrun` payload.
pub fn dryrun_json(items: &[DryrunItem]) -> String {
    let rows = items
        .iter()
        .map(|i| {
            let mut fields = format!(
                "\"app\":{},\"rule\":{},\"risk\":{},\"default_selected\":{},\"method\":{},\"path\":{},\"exists\":{}",
                esc(&i.app),
                esc(&i.rule),
                esc(i.risk),
                i.default_selected,
                esc(i.method),
                esc(&i.path),
                i.exists
            );
            if let Some(met) = i.condition_met {
                fields.push_str(&format!(",\"condition_met\":{met}"));
            }
            format!("{{{fields}}}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"items\":[{rows}]}}")
}

/// `{"count":N,"apps":[…]}` — the `list` payload. Files that failed to parse are omitted, so
/// `count` is the number of VALID files, not the number of files on disk (`main.rs:254-265`).
pub fn list_json(loaded: &[Loaded]) -> String {
    let apps: Vec<String> = loaded
        .iter()
        .filter_map(|l| l.result.as_ref().ok().map(|rf| app_summary(&l.file, rf)))
        .collect();
    format!("{{\"count\":{},\"apps\":[{}]}}", apps.len(), apps.join(","))
}

fn app_summary(file: &str, rf: &RuleFile) -> String {
    let rules = rf
        .rules
        .iter()
        .map(|r| {
            format!(
                "{{\"id\":{},\"category\":{},\"risk\":{},\"default_selected\":{}}}",
                esc(&r.id),
                esc(&r.category),
                esc(r.risk.as_str()),
                default_selected(r)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let ids = rf
        .app
        .bundle_ids
        .iter()
        .map(|b| esc(b))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"file\":{},\"app\":{},\"bundle_ids\":[{}],\"provenance\":{},\"rules\":[{}]}}",
        esc(file),
        esc(&rf.app.name),
        ids,
        esc(&rf.provenance.source),
        rules
    )
}

/// The `validate` payload plus whether everything validated.
///
/// The bool is the real verdict: the oracle prints a SUCCESS envelope regardless
/// (`main.rs:286` calls the hardcoded-`ok:true` wrapper) and signals failure only through the
/// process exit code. So `ok:true` here does not mean "validated" — measured on the golden's
/// fixture, which exits 1. Reproduced exactly rather than tidied, because a GUI branching on the
/// envelope's `ok` would change behaviour if this were "fixed".
pub fn validate_report(loaded: &[Loaded]) -> (String, bool) {
    let mut problems: Vec<String> = Vec::new();
    let mut valid = 0usize;
    for l in loaded {
        match &l.result {
            Ok(rf) => {
                let errs = validate(rf);
                if errs.is_empty() {
                    valid += 1;
                } else {
                    problems.push(problem_json(&l.file, &errs));
                }
            }
            Err(e) => problems.push(problem_json(&l.file, std::slice::from_ref(e))),
        }
    }
    let ok = problems.is_empty();
    let data = format!(
        "{{\"files\":{},\"valid\":{},\"problems\":[{}]}}",
        loaded.len(),
        valid,
        problems.join(",")
    );
    (data, ok)
}

fn problem_json(file: &str, errors: &[String]) -> String {
    let errs = errors.iter().map(|e| esc(e)).collect::<Vec<_>>().join(",");
    format!("{{\"file\":{},\"errors\":[{}]}}", esc(file), errs)
}

use crate::json::escape as esc;

#[cfg(test)]
mod tests {
    use super::*;

    // Some tests in this module are `#[cfg(unix)]`. They assert POSIX-shaped filesystem
    // behaviour, which is the only shape this engine's path vocabulary has: the clean target
    // table is entirely `~/Library/...`, the protection tables are macOS paths, the glob expander
    // splits on `/`, and `clean::validate::validate_path_for_deletion` refuses OUTRIGHT off unix
    // rather than pretending otherwise. Read the guard comment in that function before ungating
    // any of them — it is the reason these are gated rather than "fixed", and the reason making
    // them pass on Windows is a protection-table port, not a test change.

    #[cfg(unix)]
    const DRYRUN_GOLDEN: &str = include_str!("rules-dryrun.golden.json");
    #[cfg(unix)]
    const LIST_GOLDEN: &str = include_str!("rules-list.golden.json");
    #[cfg(unix)]
    const VALIDATE_GOLDEN: &str = include_str!("rules-validate.golden.json");

    #[cfg(unix)]
    fn parse_golden(src: &str) -> Json {
        Json::parse(src).expect("vendored golden must be valid JSON")
    }

    /// Rebuild the golden's own fixture (`make_fixtures.sh`) under `dir`, with every target path
    /// rewritten from the golden's `/tmp/rules_fixture/...` prefix to `dir`. The rule files are
    /// generated from that same rewrite, so the fixture and the expectations cannot drift apart:
    /// change the golden and this moves with it.
    #[cfg(unix)]
    fn rebuild_fixture(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir.join("targets/alpha-cache")).unwrap();
        std::fs::write(dir.join("targets/alpha-cache/blob.bin"), b"cached\n").unwrap();
        std::fs::write(dir.join("targets/aged.log"), b"small\n").unwrap();
        let big: Vec<u8> = (0..4096u32).map(|i| ((i * 7 + 11) % 251) as u8).collect();
        std::fs::write(dir.join("targets/big.bin"), &big).unwrap();

        let t = |leaf: &str| {
            dir.join("targets")
                .join(leaf)
                .to_string_lossy()
                .into_owned()
        };
        let alpha = format!(
            r#"{{
  "schema": "burrow.rules/v1",
  "app": {{ "bundle_ids": ["com.burrow.fixture.alpha", "com.burrow.fixture.alpha.helper"], "name": "Alpha" }},
  "rules": [
    {{ "id": "alpha.cache", "category": "cache", "risk": "safe", "recommend": true,
      "explain": "Rebuilt on next launch.",
      "targets": [{{ "path": "{cache}", "search": "walk_all" }}],
      "action": {{ "type": "delete", "method": "trash" }} }},
    {{ "id": "alpha.archives", "category": "dev-artifact", "risk": "risky", "recommend": false,
      "explain": "Never preselected, and this path does not exist.",
      "targets": [{{ "path": "{absent}", "search": "walk_all" }}],
      "action": {{ "type": "delete", "method": "remove" }} }},
    {{ "id": "alpha.aged", "category": "log", "risk": "safe", "recommend": true,
      "explain": "Gated on an age no freshly-built fixture can meet.",
      "targets": [{{ "path": "{aged}", "search": "file", "when": {{ "min_age_days": 3650 }} }}],
      "action": {{ "type": "delete", "method": "trash" }} }},
    {{ "id": "alpha.big", "category": "cache", "risk": "safe", "recommend": true,
      "explain": "Gated on a size this 4096-byte file always meets.",
      "targets": [{{ "path": "{big}", "search": "file", "when": {{ "min_size_bytes": 100 }} }}],
      "action": {{ "type": "delete", "method": "trash" }} }}
  ],
  "provenance": {{ "source": "builtin", "evidence": ["synthetic fixture"], "license": "Apache-2.0" }}
}}"#,
            cache = t("alpha-cache"),
            absent = t("absent-archives"),
            aged = t("aged.log"),
            big = t("big.bin"),
        );
        std::fs::write(dir.join("com.burrow.fixture.alpha.json"), alpha).unwrap();
        let beta = format!(
            r#"{{
  "schema": "burrow.rules/v1",
  "app": {{ "bundle_ids": ["com.burrow.fixture.beta"], "name": "Beta" }},
  "rules": [
    {{ "id": "beta.history", "category": "history", "risk": "caution", "recommend": false,
      "explain": "Caution is never preselected even without a when{{}}.",
      "targets": [{{ "path": "{blob}", "search": "file" }}],
      "action": {{ "type": "delete", "method": "remove" }} }}
  ],
  "provenance": {{ "source": "community", "evidence": [], "license": "Apache-2.0" }}
}}"#,
            blob = t("alpha-cache/blob.bin"),
        );
        std::fs::write(dir.join("com.burrow.fixture.beta.json"), beta).unwrap();
        // The deliberate parse failure: dryrun/list must skip it, validate must report it.
        std::fs::write(
            dir.join("zz-broken.json"),
            "{ \"schema\": \"burrow.rules/v1\", \"app\": {\n",
        )
        .unwrap();
        std::fs::write(dir.join("README.md"), b"notes, not a rule file\n").unwrap();
    }

    #[cfg(unix)]
    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("burrow_rules_{tag}_{}", std::process::id()));
        rebuild_fixture(&d);
        d
    }

    /// Rewrite the golden's fixture-rooted paths onto the scratch directory, so the golden's own
    /// values — not retyped ones — are what the run is compared against.
    #[cfg(unix)]
    fn rebase(s: &str, dir: &Path) -> String {
        s.replace("/tmp/rules_fixture", &dir.to_string_lossy())
    }

    /// RUN the real dryrun over a rebuild of the golden's fixture and require the result to equal
    /// `rules-dryrun.golden.json` row for row, key for key — including `condition_met` being
    /// PRESENT on the two conditional rows and ABSENT on the other three.
    ///
    /// Every expectation is read out of the golden at run time (RULEBOOK §3e). Nothing here is
    /// transcribed, so a re-capture moves the test with it, and the fixture rebuild above is
    /// derived from the same paths the golden carries.
    #[cfg(unix)]
    #[test]
    fn dryrun_over_the_goldens_fixture_reproduces_the_golden() {
        let dir = scratch("dryrun");
        let golden = parse_golden(&rebase(DRYRUN_GOLDEN, &dir));
        let want = golden
            .get("items")
            .and_then(Json::as_array)
            .expect("golden.items must be an array");
        assert!(
            !want.is_empty(),
            "golden.items is empty — this test can no longer prove anything (RULEBOOK §3b)"
        );

        let loaded = load_dir(&dir).expect("fixture must load");
        let items = dryrun_items(&loaded, None, "/unused-home");
        let got = Json::parse(&dryrun_json(&items)).expect("dryrun_json must emit valid JSON");
        let got_items = got.get("items").and_then(Json::as_array).expect("items");

        assert_eq!(
            got_items.len(),
            want.len(),
            "row count must match the golden"
        );
        for (i, expected) in want.iter().enumerate() {
            let Json::Object(keys) = expected else {
                panic!("golden item {i} must be an object");
            };
            for k in keys.keys() {
                assert_eq!(
                    got_items[i].get(k.as_str()),
                    expected.get(k.as_str()),
                    "row {i} field {k} diverges from the golden"
                );
            }
            // The absence of `condition_met` is contract too: it is how a caller tells an
            // unconditional target from one whose conditions were checked and met.
            if expected.get("condition_met").is_none() {
                assert!(
                    got_items[i].get("condition_met").is_none(),
                    "row {i} has no when{{}} in the golden, so condition_met must be OMITTED"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--app` narrows to one bundle id. The expectation is DERIVED from the dryrun golden (the
    /// rows whose `app` is Beta) rather than retyped, so it stays anchored to the capture.
    #[cfg(unix)]
    #[test]
    fn the_app_filter_selects_exactly_the_goldens_rows_for_that_bundle_id() {
        let dir = scratch("filter");
        let golden = parse_golden(&rebase(DRYRUN_GOLDEN, &dir));
        let want: Vec<&Json> = golden
            .get("items")
            .and_then(Json::as_array)
            .expect("items")
            .iter()
            .filter(|i| i.get("app").and_then(Json::as_str) == Some("Beta"))
            .collect();
        assert!(!want.is_empty(), "the golden has no Beta rows to filter to");

        let loaded = load_dir(&dir).expect("fixture must load");
        let items = dryrun_items(&loaded, Some("com.burrow.fixture.beta"), "/unused-home");
        assert_eq!(
            items.len(),
            want.len(),
            "filter must keep exactly the Beta rows"
        );
        for (got, expected) in items.iter().zip(want) {
            assert_eq!(
                got.rule,
                expected.get("rule").and_then(Json::as_str).unwrap()
            );
            assert_eq!(
                got.path,
                expected.get("path").and_then(Json::as_str).unwrap()
            );
        }
        // A bundle id no file claims filters everything out — the `--app` argument is honoured,
        // not merely accepted.
        assert!(dryrun_items(&loaded, Some("com.nobody.at.all"), "/unused-home").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `list` over the same fixture must reproduce `rules-list.golden.json` — which is also where
    /// the oracle's own inconsistency is pinned: `alpha.aged` is `default_selected: true` here and
    /// `false` in the dryrun golden, because `list` never evaluates `when{}`. Both values are read
    /// from their own golden, so neither can be quietly "corrected" into agreement.
    #[cfg(unix)]
    #[test]
    fn list_over_the_goldens_fixture_reproduces_the_golden() {
        let dir = scratch("list");
        let golden = parse_golden(LIST_GOLDEN);
        let loaded = load_dir(&dir).expect("fixture must load");
        let got = Json::parse(&list_json(&loaded)).expect("list_json must emit valid JSON");

        assert_eq!(got.get("count"), golden.get("count"), "count must match");
        let want = golden.get("apps").and_then(Json::as_array).expect("apps");
        assert!(!want.is_empty(), "golden.apps is empty (RULEBOOK §3b)");
        let got_apps = got.get("apps").and_then(Json::as_array).expect("apps");
        assert_eq!(got_apps.len(), want.len());
        for (i, expected) in want.iter().enumerate() {
            assert_eq!(&got_apps[i], expected, "app {i} diverges from the golden");
        }

        // The cross-golden claim, asserted rather than described: the same rule id carries
        // different `default_selected` values in the two goldens.
        let dryrun = parse_golden(DRYRUN_GOLDEN);
        let listed = want
            .iter()
            .flat_map(|a| a.get("rules").and_then(Json::as_array).unwrap_or(&[]))
            .find(|r| r.get("id").and_then(Json::as_str) == Some("alpha.aged"))
            .and_then(|r| r.get("default_selected"))
            .and_then(Json::as_bool);
        let dried = dryrun
            .get("items")
            .and_then(Json::as_array)
            .expect("items")
            .iter()
            .find(|i| i.get("rule").and_then(Json::as_str) == Some("alpha.aged"))
            .and_then(|i| i.get("default_selected"))
            .and_then(Json::as_bool);
        assert_eq!(
            (listed, dried),
            (Some(true), Some(false)),
            "the goldens must still disagree about alpha.aged — if they now agree, the oracle \
             quirk this port reproduces has changed and both goldens need re-capturing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `validate` over the same fixture. STRUCTURE is compared against
    /// `rules-validate.golden.json`; the parse-error TEXT is not, and cannot be: the golden's
    /// string is serde_json's diagnostic (`EOF while parsing an object at line 2 column 0`) and
    /// this crate is zero-dep. See rules-dryrun.golden.provenance.txt — that prose is the one
    /// recorded divergence, and nothing consumes it. Everything a consumer branches on (file
    /// count, valid count, WHICH file failed, that it failed at all, and the `rule parse error: `
    /// prefix) is read off the golden and compared.
    #[cfg(unix)]
    #[test]
    fn validate_over_the_goldens_fixture_reproduces_the_goldens_structure() {
        let dir = scratch("validate");
        let golden = parse_golden(VALIDATE_GOLDEN);
        let loaded = load_dir(&dir).expect("fixture must load");
        let (data, ok) = validate_report(&loaded);
        let got = Json::parse(&data).expect("validate_report must emit valid JSON");

        assert_eq!(got.get("files"), golden.get("files"), "files must match");
        assert_eq!(got.get("valid"), golden.get("valid"), "valid must match");

        let want = golden
            .get("problems")
            .and_then(Json::as_array)
            .expect("problems");
        assert!(
            !want.is_empty(),
            "golden.problems is empty — the failure path is unproven (RULEBOOK §3b)"
        );
        let got_problems = got
            .get("problems")
            .and_then(Json::as_array)
            .expect("problems");
        assert_eq!(got_problems.len(), want.len(), "problem count must match");
        for (i, expected) in want.iter().enumerate() {
            assert_eq!(
                got_problems[i].get("file"),
                expected.get("file"),
                "problem {i} must name the same file as the golden"
            );
            let errs = got_problems[i]
                .get("errors")
                .and_then(Json::as_array)
                .expect("errors must be an array");
            assert_eq!(
                errs.len(),
                expected
                    .get("errors")
                    .and_then(Json::as_array)
                    .expect("errors")
                    .len(),
                "problem {i} must carry as many errors as the golden"
            );
            let prefix = expected
                .get("errors")
                .and_then(|e| e.at(0))
                .and_then(Json::as_str)
                .expect("golden error string");
            let prefix = prefix
                .split_once(':')
                .map(|(p, _)| p)
                .expect("prefixed error");
            assert!(
                errs[0].as_str().unwrap_or_default().starts_with(prefix),
                "the error must keep the golden's `{prefix}:` prefix, only the parser's own \
                 wording after it may differ: {:?}",
                errs[0]
            );
        }
        // The oracle's other quirk: a SUCCESS envelope with a FAILURE exit code. This bool is what
        // cli.rs turns into exit 1 while still emitting ok:true.
        assert!(!ok, "a fixture with a broken file must report not-ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `load_dir` on a directory it cannot read is an ERROR — the opposite of `sentinel`, which
    /// answers the same input with an empty successful scan. Measured on the oracle:
    /// `rules dryrun /tmp/definitely_absent_rules` exits 1 with `cannot read …`.
    //
    // check_tests: no-golden — a golden captures one fixture's ANSWER; the input here is a path
    // that deliberately does not exist, which no fixture can be. The oracle measurement is
    // recorded in rules-dryrun.golden.provenance.txt.
    #[test]
    fn an_unreadable_directory_is_an_error_unlike_sentinel() {
        let missing =
            std::env::temp_dir().join(format!("burrow_rules_absent_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let err = load_dir(&missing).expect_err("a missing directory must fail");
        assert!(err.starts_with("cannot read "), "got: {err}");
    }

    // ─── the pure logic, exercised where a golden cannot reach ────────────────────────────────

    /// The conservative rule: an unverifiable condition is NOT met, so nothing is auto-selected on
    /// metadata we could not read. `min_days_unaccessed` is covered here because no fixture can
    /// hold a file that has genuinely not been read for 30 days.
    //
    // check_tests: no-golden — pure predicate over injected values; the golden's rows exercise
    // min_age_days/min_size_bytes end-to-end in dryrun_over_the_goldens_fixture_reproduces_the_golden.
    #[test]
    fn condition_met_requires_every_present_condition_and_is_conservative() {
        let both = Conditions {
            min_age_days: Some(30),
            min_size_bytes: Some(1024),
            ..Default::default()
        };
        assert!(condition_met(&both, Some(40), Some(2048), None));
        assert!(
            !condition_met(&both, Some(10), Some(2048), None),
            "too young"
        );
        assert!(!condition_met(&both, Some(40), Some(10), None), "too small");
        assert!(!condition_met(&both, None, None, None), "unverifiable");

        let unaccessed = Conditions {
            min_days_unaccessed: Some(30),
            ..Default::default()
        };
        assert!(condition_met(&unaccessed, None, None, Some(45)));
        assert!(
            !condition_met(&unaccessed, None, None, Some(3)),
            "recently used"
        );
        assert!(!condition_met(&unaccessed, None, None, None), "stale atime");
    }

    /// A directory reports no size, so a `min_size_bytes` condition on one can never be met — the
    /// reason the golden's size-gated target is a file. Run against the real filesystem.
    //
    // check_tests: no-golden — this is a property of probe_path on a directory, which the golden's
    // fixture deliberately does not contain.
    #[test]
    fn probe_path_reports_no_size_for_a_directory() {
        let dir = std::env::temp_dir().join(format!("burrow_rules_probe_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (_, size, _) = probe_path(&dir);
        assert_eq!(size, None, "a directory must report no size");
        let f = dir.join("f.bin");
        std::fs::write(&f, vec![0u8; 128]).unwrap();
        assert_eq!(probe_path(&f).1, Some(128));
        // A path that does not exist probes as entirely unknown.
        assert_eq!(probe_path(&dir.join("nope")), (None, None, None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    //
    // check_tests: no-golden — `~` expansion never appears in the golden: every fixture path is
    // absolute on purpose, so the capture is machine-portable. The rule is still contract.
    #[test]
    fn expand_path_only_touches_a_leading_tilde() {
        assert_eq!(
            expand_path("~/Library/Caches", "/Users/x"),
            "/Users/x/Library/Caches"
        );
        assert_eq!(expand_path("~", "/Users/x"), "/Users/x");
        assert_eq!(expand_path("/abs/path", "/Users/x"), "/abs/path");
        assert_eq!(expand_path("./rel/~/mid", "/Users/x"), "./rel/~/mid");
    }

    /// The parse must be as STRICT as serde's derive, because laxity here admits rule files the
    /// oracle rejects — and a rule file that parses is a rule file that can select paths for
    /// deletion. Each case names the serde behaviour it mirrors.
    //
    // check_tests: no-golden — these are malformed inputs; a golden records the oracle's answer
    // for a WELL-FORMED fixture. The equivalence being asserted is with serde's derive rules
    // (burrow-cli/src/rules.rs:11-176), which are source, not a captured artifact.
    #[test]
    fn the_parser_is_as_strict_as_the_oracles_derive() {
        let valid = r#"{
            "schema": "burrow.rules/v1",
            "app": { "bundle_ids": ["com.example.App"], "name": "Example" },
            "rules": [{
                "id": "example.cache", "category": "cache", "risk": "safe", "recommend": true,
                "targets": [{ "path": "~/Library/Caches/com.example.App" }],
                "action": { "type": "delete", "method": "trash" }
            }],
            "provenance": { "source": "builtin", "evidence": ["vendor docs"], "license": "Apache-2.0" }
        }"#;
        let rf = parse(valid).expect("the reference file must parse");
        assert_eq!(rf.app.name, "Example");
        assert_eq!(
            rf.rules[0].targets[0].search,
            Search::WalkAll,
            "search defaults to walk_all"
        );
        assert_eq!(
            rf.rules[0].action.method,
            Method::Trash,
            "method defaults to trash"
        );
        assert!(!rf.rules[0].auto, "auto defaults to false (opt-in)");
        assert_eq!(rf.rules[0].explain, None, "explain is optional");
        assert!(validate(&rf).is_empty(), "{:?}", validate(&rf));

        // Unknown enum spellings: serde's derived enums accept only the listed variants.
        for bad in [
            valid.replace("\"risk\": \"safe\"", "\"risk\": \"medium\""),
            valid.replace("\"type\": \"delete\"", "\"type\": \"shred\""),
            valid.replace("\"method\": \"trash\"", "\"method\": \"vaporize\""),
            valid.replace(
                "\"path\": \"~/Library/Caches/com.example.App\"",
                "\"path\": \"~/x\", \"search\": \"recurse\"",
            ),
        ] {
            assert!(parse(&bad).is_err(), "unknown variant must fail: {bad}");
        }
        // Missing required fields.
        for key in ["schema", "app", "provenance"] {
            let bad = valid.replace(&format!("\"{key}\""), "\"_removed\"");
            let e = parse(&bad).expect_err("a missing required field must fail");
            assert!(
                e.starts_with("rule parse error: "),
                "prefix must survive: {e}"
            );
        }
        // `rules` itself is optional (#[serde(default)]), so a file with no rules is VALID.
        let no_rules = r#"{"schema":"burrow.rules/v1",
            "app":{"bundle_ids":["a"],"name":"A"},"provenance":{"source":"builtin"}}"#;
        assert!(parse(no_rules)
            .expect("rules defaults to empty")
            .rules
            .is_empty());
        // A fractional threshold is refused rather than truncated — 30.5 days is not 30.
        let fractional = valid.replace(
            "\"path\": \"~/Library/Caches/com.example.App\"",
            "\"path\": \"~/x\", \"when\": { \"min_age_days\": 30.5 }",
        );
        assert!(
            parse(&fractional).is_err(),
            "a fractional condition must fail"
        );
        // Unknown EXTRA keys are ignored, as serde does without deny_unknown_fields.
        let extra = valid.replace("\"schema\":", "\"future_field\": 1, \"schema\":");
        assert!(
            parse(&extra).is_ok(),
            "an unknown key must not fail the file"
        );
    }

    /// `validate`'s own rules, which are about SAFETY rather than syntax: a risky rule may never
    /// be preselected, automation may only touch safe rules, and an empty `when{}` is a mistake
    /// rather than a no-op.
    //
    // check_tests: no-golden — the golden's fixture contains only files that are either valid or
    // unparseable; these are files that PARSE and are still wrong, which is a different axis.
    #[test]
    fn validate_rejects_the_unsafe_combinations() {
        let make = |risk: &str, extra: &str| {
            format!(
                r#"{{"schema":"burrow.rules/v1","app":{{"bundle_ids":["a"],"name":"A"}},
                "rules":[{{"id":"r","category":"cache","risk":"{risk}","recommend":true,{extra}
                "targets":[{{"path":"/t"}}],"action":{{"type":"delete"}}}}],
                "provenance":{{"source":"builtin"}}}}"#
            )
        };
        let risky = parse(&make("risky", "")).unwrap();
        assert!(validate(&risky).iter().any(|e| e.contains("risky")));
        let auto_caution = parse(&make("caution", "\"auto\": true,")).unwrap();
        assert!(validate(&auto_caution).iter().any(|e| e.contains("auto")));

        let empty_when = parse(
            r#"{"schema":"burrow.rules/v1","app":{"bundle_ids":["a"],"name":"A"},
            "rules":[{"id":"r","category":"cache","risk":"safe","recommend":true,
            "targets":[{"path":"/t","when":{}}],"action":{"type":"delete"}}],
            "provenance":{"source":"builtin"}}"#,
        )
        .unwrap();
        assert!(validate(&empty_when).iter().any(|e| e.contains("when")));

        let bad_schema = parse(
            r#"{"schema":"burrow.rules/v0","app":{"bundle_ids":["a"],"name":"A"},
            "provenance":{"source":"builtin"}}"#,
        )
        .unwrap();
        assert!(validate(&bad_schema).iter().any(|e| e.contains("schema")));
        let no_ids = parse(
            r#"{"schema":"burrow.rules/v1","app":{"bundle_ids":[],"name":"A"},
            "provenance":{"source":"builtin"}}"#,
        )
        .unwrap();
        assert!(validate(&no_ids).iter().any(|e| e.contains("bundle_ids")));
    }

    /// Rule ids, app names and paths land inside JSON strings, so a quote in any of them must be
    /// escaped rather than concatenated. `dryrun` reports whatever a rule file holds.
    //
    // check_tests: no-golden — an escaping test needs values no captured fixture should contain.
    #[test]
    fn odd_strings_stay_valid_json_in_every_report() {
        let items = vec![DryrunItem {
            app: "Qu\"ote".into(),
            rule: "back\\slash".into(),
            risk: "safe",
            default_selected: true,
            method: "trash",
            path: "/t/a\"b".into(),
            exists: false,
            condition_met: Some(true),
        }];
        let parsed = Json::parse(&dryrun_json(&items)).expect("dryrun_json must stay parseable");
        let row = parsed.get("items").and_then(|i| i.at(0)).expect("row");
        assert_eq!(row.get("app").and_then(Json::as_str), Some("Qu\"ote"));
        assert_eq!(row.get("path").and_then(Json::as_str), Some("/t/a\"b"));

        let problem = validate_report(&[Loaded {
            file: "we\"ird.json".into(),
            result: Err("rule parse error: it went \"wrong\"".into()),
        }]);
        assert!(
            Json::parse(&problem.0).is_ok(),
            "validate_report must stay parseable"
        );
    }
}
