//! `clean --plan <file>` — execute an EXACT, previously-reviewed clean plan without re-scanning.
//!
//! The GUI runs the dry run, shows the user every candidate, lets them untick some, and then needs
//! the engine to remove precisely what is left: not "whatever a fresh scan finds now", which can
//! differ from what was shown (a cache that appeared in the meantime, a whitelist edit, a tool that
//! came onto `PATH`). So it writes the kept paths to a file and hands the file here. The engine
//! removes ONLY the listed paths, in file order, and never re-runs the planner.
//!
//! A file of paths is otherwise an arbitrary-deletion API — every rail still runs per path through
//! [`super::execute::remove_guarded`], but the rails were written to keep a SCAN away from the
//! wrong places, not to bound a list someone else wrote. So a listed path is additionally refused,
//! reported as `protected` with reason [`NOT_A_CLEAN_TARGET`], unless it lies at or under something
//! the clean planner's own target table could enumerate on this machine
//! ([`super::plan::covering_target`], the same table [`super::plan::plan_clean`] reads, against the
//! same home). A path the scan could never have produced is a path this file may not name.
//!
//! The file format is the smallest thing that survives a round trip through a Swift `String`: UTF-8
//! text, one absolute path per line, blank lines and lines starting with `#` ignored, surrounding
//! whitespace trimmed. No escaping, so a path containing a newline cannot be written — and
//! `validate_path_for_deletion` refuses control characters anyway.

use super::execute::{execute_one, CleanEvent, CleanOutcome, Removal};
use super::plan::{covering_target, size_if_exists, CleanCandidate, CleanTarget};
use super::protect::{should_protect_path, ProtectionMode};
use crate::json::escape as esc;
use std::path::Path;

/// The refusal reason for a listed path that no clean target covers.
pub const NOT_A_CLEAN_TARGET: &str = "not_a_clean_target";

/// The refusal reason for a covered path that the planner's own two rails
/// ([`should_protect_path`], then the whitelist) would have kept out of the scan — refused at
/// classification so the dry run and the apply of one file agree, exactly as they do for a scan,
/// where `cleanable_paths` filters before anything is sized. The executor's rails still run per
/// candidate underneath; this is the planner's half, not a replacement for the remover's.
pub const PROTECTED: &str = "protected";

/// What a plan line came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Covered by a target and present on disk: a candidate the executor may remove, sized and
    /// labelled exactly as the scan would have sized and labelled it.
    Candidate(CleanCandidate),
    /// Covered by a target but not on disk. Nothing to remove and nothing to refuse — the same
    /// silence the executor keeps for a candidate that vanished between plan and apply.
    Missing,
    /// Not covered by any target ([`NOT_A_CLEAN_TARGET`]), or covered but kept out by the
    /// planner's rails ([`PROTECTED`]). Never sized, never handed to a remover.
    Refused { reason: &'static str },
}

/// One line of the file, in file order, with its verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    pub path: String,
    pub verdict: Verdict,
}

/// A read and classified plan file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanFile {
    /// The path the file was read from, echoed back in the output so a log line can be traced to
    /// the file that drove it.
    pub file: String,
    pub entries: Vec<PlanEntry>,
    targets: Vec<CleanTarget>,
    home: String,
}

impl PlanFile {
    /// Read `file` and classify every line against `targets` resolved under `home`, with the
    /// user's `whitelist` applied as the scan applies it.
    ///
    /// `Err` is the file itself being unusable — missing, unreadable, not UTF-8 — and is the ONE
    /// thing that fails the whole command: a plan that cannot be read is not a plan that removes
    /// nothing, it is an argv error, and reporting a clean success over it would be the empty-scan
    /// bug in a new coat. A line that cannot be acted on is never an error; it is a verdict.
    pub fn read(
        file: &str,
        targets: &[CleanTarget],
        home: &str,
        whitelist: &[&str],
    ) -> Result<PlanFile, String> {
        let bytes = std::fs::read(file)
            .map_err(|e| format!("plan file not found or unreadable: {file} ({e})"))?;
        let text =
            String::from_utf8(bytes).map_err(|_| format!("plan file is not UTF-8 text: {file}"))?;
        Ok(PlanFile {
            file: file.to_string(),
            entries: classify(&text, targets, home, whitelist),
            targets: targets.to_vec(),
            home: home.to_string(),
        })
    }

    /// Every line that carried a path — the `listed` count.
    pub fn listed(&self) -> usize {
        self.entries.len()
    }

    /// The refused entries, in file order.
    pub fn refusals(&self) -> impl Iterator<Item = (&str, &'static str)> {
        self.entries.iter().filter_map(|e| match e.verdict {
            Verdict::Refused { reason } => Some((e.path.as_str(), reason)),
            _ => None,
        })
    }

    /// How many lines were covered by a target but not on disk.
    pub fn missing(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.verdict == Verdict::Missing)
            .count()
    }

    /// The candidates the executor may act on, in file order — what a dry run lists.
    pub fn candidates(&self) -> Vec<CleanCandidate> {
        self.entries
            .iter()
            .filter_map(|e| match &e.verdict {
                Verdict::Candidate(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    /// The `plan` object appended to the command's `data`:
    /// `{"file","listed","refused","missing","refusals":[{"path","reason"}]}`. `refusals` carries
    /// the reason the buffered `protected` array (a list of paths) has nowhere to put.
    pub fn summary_json(&self) -> String {
        let refusals = self
            .refusals()
            .map(|(path, reason)| format!("{{\"path\":{},\"reason\":{}}}", esc(path), esc(reason)))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"file\":{},\"listed\":{},\"refused\":{},\"missing\":{},\"refusals\":[{refusals}]}}",
            esc(&self.file),
            self.listed(),
            self.refusals().count(),
            self.missing()
        )
    }

    /// `data` — a `clean` result object (`plan_to_json` or `outcome_to_json`) — with this file's
    /// summary added as its `plan` field. A plain splice onto the object's closing brace, so every
    /// field the shape already has is byte-identical to the scan's; the field is additive
    /// (RULEBOOK RULE 1).
    pub fn with_summary(&self, data: &str) -> String {
        let body = data
            .strip_suffix('}')
            .expect("a clean result object ends in its closing brace");
        format!("{body},\"plan\":{}}}", self.summary_json())
    }

    /// Emit one `would_remove` per candidate and one `protected` (with reason) per refusal, in file
    /// order — the `--stream` preview's lines, minus the terminal `done` the caller totals.
    pub fn preview_events(&self, mut emit: impl FnMut(String)) {
        use super::stream::{event_ndjson, would_remove_ndjson};
        for e in &self.entries {
            match &e.verdict {
                Verdict::Candidate(c) => emit(would_remove_ndjson(c)),
                Verdict::Refused { reason } => emit(event_ndjson(&CleanEvent::Refused {
                    path: &e.path,
                    reason,
                })),
                Verdict::Missing => {}
            }
        }
    }

    /// Remove the plan, in file order, every candidate through the shared guarded remover
    /// ([`super::execute::execute_one`] → `remove_guarded`) and every refusal recorded as
    /// `protected` beside them — so `done.protected` and the buffered `protected` array count the
    /// file's refusals together with the rails', and a consumer reconciling events against the
    /// file sees one verdict per line it wrote.
    ///
    /// `Cleanup` is the regime, as for `clean --apply`: a plan file is a clean, not an uninstall.
    pub fn execute(
        &self,
        whitelist: &[&str],
        permanent: bool,
        mut emit: impl FnMut(CleanEvent),
        remover: impl Fn(&Path, bool) -> Result<Removal, String>,
    ) -> CleanOutcome {
        let mut outcome = CleanOutcome::default();
        for e in &self.entries {
            match &e.verdict {
                Verdict::Candidate(c)
                    if !physically_covered(&c.path, &self.targets, &self.home) =>
                {
                    emit(CleanEvent::Refused {
                        path: &c.path,
                        reason: NOT_A_CLEAN_TARGET,
                    });
                    outcome.protected.push(c.path.clone());
                }
                Verdict::Candidate(c) => execute_one(
                    &mut outcome,
                    c,
                    whitelist,
                    permanent,
                    ProtectionMode::Cleanup,
                    &mut emit,
                    &remover,
                ),
                Verdict::Refused { reason } => {
                    emit(CleanEvent::Refused {
                        path: &e.path,
                        reason,
                    });
                    outcome.protected.push(e.path.clone());
                }
                Verdict::Missing => {}
            }
        }
        outcome
    }
}

/// The lines of a plan file that name a path: trimmed, blanks and `#` comments dropped, order kept.
pub fn plan_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Classify every path line: not covered by any target → refused [`NOT_A_CLEAN_TARGET`]; covered
/// but caught by the planner's rails → refused [`PROTECTED`]; covered and absent →
/// [`Verdict::Missing`]; covered and on disk → a sized candidate under that target's label. The
/// rail order is `cleanable_paths`'s (`should_protect_path`, then the whitelist), and the
/// existence check comes after both, as in the scan — a protected path is refused whether or not
/// it is there. Pure over the target table except for the one `stat` that sizes a covered path.
pub fn classify(
    text: &str,
    targets: &[CleanTarget],
    home: &str,
    whitelist: &[&str],
) -> Vec<PlanEntry> {
    plan_lines(text)
        .into_iter()
        .map(|path| {
            let verdict = match covering_target(path, targets, home) {
                _ if !physically_covered(path, targets, home) => Verdict::Refused {
                    reason: NOT_A_CLEAN_TARGET,
                },
                None => Verdict::Refused {
                    reason: NOT_A_CLEAN_TARGET,
                },
                Some(_)
                    if should_protect_path(path, ProtectionMode::Cleanup)
                        || super::validate::deletion_is_whitelisted(path, whitelist)
                        || super::validate::validate_path_for_deletion(
                            path,
                            ProtectionMode::Cleanup,
                        )
                        .is_err() =>
                {
                    Verdict::Refused { reason: PROTECTED }
                }
                Some(_) if !super::plan::crash_report_retention_allows(path) => {
                    Verdict::Refused { reason: PROTECTED }
                }
                Some(target) => match size_if_exists(path) {
                    None => Verdict::Missing,
                    Some(size) => Verdict::Candidate(CleanCandidate {
                        path: path.to_string(),
                        label: target.label.to_string(),
                        size,
                    }),
                },
            };
            PlanEntry {
                path: path.to_string(),
                verdict,
            }
        })
        .collect()
}

fn physically_covered(path: &str, targets: &[CleanTarget], home: &str) -> bool {
    let Some(physical) = super::validate::physical_deletion_path(path) else {
        return covering_target(path, targets, home).is_some();
    };
    let physical_home = Path::new(home).canonicalize().ok();
    covering_target(
        &physical,
        targets,
        physical_home
            .as_deref()
            .and_then(Path::to_str)
            .unwrap_or(home),
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;
    use std::fs;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("burrow_plan_file_{}_{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    const TABLE: &[CleanTarget] = &[
        CleanTarget {
            path: "~/Library/Caches/*",
            label: "User app cache",
        },
        CleanTarget {
            path: "~/Library/Application Support/CrashReporter",
            label: "Crash reports",
        },
    ];

    #[test]
    fn lines_are_trimmed_and_comments_and_blanks_are_dropped_in_order() {
        let text = "# written by the GUI\n\n  /a/one  \n/a/two\n   \n#/a/not-this\n/a/three\n";
        assert_eq!(plan_lines(text), vec!["/a/one", "/a/two", "/a/three"]);
    }

    #[test]
    fn a_missing_file_is_an_error_and_a_non_utf8_file_is_too() {
        let root = scratch("read");
        let err = PlanFile::read(
            root.join("nope.txt").to_str().unwrap(),
            TABLE,
            "/Users/me",
            &[],
        )
        .unwrap_err();
        assert!(err.contains("not found or unreadable"), "{err}");
        let bad = root.join("bad.txt");
        fs::write(&bad, [0xff, 0xfe, b'/', b'a']).unwrap();
        let err = PlanFile::read(bad.to_str().unwrap(), TABLE, "/Users/me", &[]).unwrap_err();
        assert!(err.contains("not UTF-8"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }

    // check_tests: no-golden — BUR-142's gate has no oracle; the anchor is the target table.
    #[cfg(unix)]
    #[test]
    fn each_line_gets_exactly_one_verdict_and_the_order_is_the_files() {
        let home = scratch("classify");
        let caches = home.join("Library/Caches");
        fs::create_dir_all(caches.join("present")).unwrap();
        fs::write(caches.join("present/blob"), vec![b'x'; 300]).unwrap();
        fs::create_dir_all(caches.join("com.apple.Safari")).unwrap();
        fs::create_dir_all(caches.join("kept")).unwrap();
        let home_s = home.to_str().unwrap();
        let text = format!(
            "{home_s}/Documents/keep\n{home_s}/Library/Caches/present\n{home_s}/Library/Caches/absent\n\
             {home_s}/Library/Caches/../Documents/keep\nrelative/path\n\
             {home_s}/Library/Caches/com.apple.Safari\n{home_s}/Library/Caches/kept\n"
        );
        let whitelisted = format!("{home_s}/Library/Caches/kept");
        let entries = classify(&text, TABLE, home_s, &[whitelisted.as_str()]);
        assert_eq!(entries.len(), 7);
        assert_eq!(
            entries[0].verdict,
            Verdict::Refused {
                reason: NOT_A_CLEAN_TARGET
            }
        );
        match &entries[1].verdict {
            Verdict::Candidate(c) => {
                assert_eq!(c.label, "User app cache");
                assert_eq!(c.size, 300);
            }
            other => panic!("present path must be a candidate: {other:?}"),
        }
        assert_eq!(entries[2].verdict, Verdict::Missing);
        assert!(matches!(entries[3].verdict, Verdict::Refused { .. }));
        assert!(matches!(entries[4].verdict, Verdict::Refused { .. }));
        // Covered, on disk, and still not a candidate: the planner's rails apply to a file's
        // lines exactly as they apply to a scan's expansions.
        assert_eq!(entries[5].verdict, Verdict::Refused { reason: PROTECTED });
        assert_eq!(entries[6].verdict, Verdict::Refused { reason: PROTECTED });
        assert!(caches.join("com.apple.Safari").exists() && caches.join("kept").exists());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn the_summary_is_valid_json_carrying_counts_and_reasons_and_splices_onto_a_result() {
        let plan = PlanFile {
            file: "/tmp/p.txt".into(),
            targets: Vec::new(),
            home: "/tmp".into(),
            entries: vec![
                PlanEntry {
                    path: "/x".into(),
                    verdict: Verdict::Refused {
                        reason: NOT_A_CLEAN_TARGET,
                    },
                },
                PlanEntry {
                    path: "/y".into(),
                    verdict: Verdict::Missing,
                },
                PlanEntry {
                    path: "/z".into(),
                    verdict: Verdict::Candidate(CleanCandidate {
                        path: "/z".into(),
                        label: "t".into(),
                        size: 1,
                    }),
                },
            ],
        };
        let data = plan.with_summary("{\"dry_run\":true}");
        let parsed = Json::parse(&data).expect("valid JSON");
        assert_eq!(parsed.get("dry_run").and_then(Json::as_bool), Some(true));
        let p = parsed.get("plan").expect("plan object");
        assert_eq!(p.get("file").and_then(Json::as_str), Some("/tmp/p.txt"));
        assert_eq!(p.get("listed").and_then(Json::as_u64), Some(3));
        assert_eq!(p.get("refused").and_then(Json::as_u64), Some(1));
        assert_eq!(p.get("missing").and_then(Json::as_u64), Some(1));
        let r = p.get("refusals").and_then(Json::as_array).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].get("path").and_then(Json::as_str), Some("/x"));
        assert_eq!(
            r[0].get("reason").and_then(Json::as_str),
            Some(NOT_A_CLEAN_TARGET)
        );
    }
}
