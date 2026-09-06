//! Name resolution for `uninstall <name>…` — the port of the oracle's `match_apps_by_name`
//! (`bin/uninstall.sh:1110-1188`).
//!
//! # Why this exists
//!
//! The oracle never uninstalls what you typed. It scans the machine first (`scan_applications` →
//! `load_applications` → `apps_data`), resolves every argument against that inventory, and acts on
//! the resolved app records — so a name that matches nothing is refused (`bin/uninstall.sh:1394`,
//! `No matching applications found.`, `return 1`) and a name that matches several removes several.
//!
//! The engine had none of that. `uninstall` read ONE positional and interpolated it straight into
//! `~/Library/Containers/{arg}` and friends. Two failures fell out of that:
//!
//!  1. **Every app after the first was silently dropped.** The app really sends more than one:
//!     `MoActions.argv` splats a Software-tab multi-select into
//!     `["uninstall", app1, app2, …]`, which `BurrowConductor.engineArgv` turns into
//!     `[…, "--apply"]`. Three selected apps, one uninstalled, a success report for all three.
//!  2. **A name that matches nothing reported success.** `uninstall com.nonexistent.App --dry-run`
//!     answered `ok:true` with an empty `items` list — indistinguishable from an app that is
//!     installed and simply has no leftovers.
//!
//! # The oracle's algorithm, exactly
//!
//! Per search term, in order:
//!
//!  - **Exact pass.** Lowercased term against the lowercased display name and the lowercased `.app`
//!    directory basename. The first hit wins and the pass stops (`break`) — an exact match never
//!    yields more than one app.
//!  - **Substring pass**, only when the exact pass found nothing for that term. Same two haystacks,
//!    `contains` instead of `==`, and it does NOT stop early: every app containing the term is
//!    taken. `mo uninstall test` matching three apps is upstream-intended behaviour
//!    (`tests/uninstall.bats:1439`).
//!  - **No hit at all** prints `Warning: No application found matching '<term>'` and moves to the
//!    next term. It is not fatal; only an entirely empty result set is.
//!
//! Deduplication is by position in the inventory, not by name (`matched_indices`), so
//! `uninstall Slack Slack` resolves to one app, and an app already taken by an earlier term is not
//! taken again by a later one. `tests/uninstall.bats:1461` pins that.
//!
//! The bash escapes `\`, `*`, `?` and `[` in the search term before comparing, because `[[ x == $y ]]`
//! would otherwise treat the term as a glob pattern. Escaping them makes the comparison literal,
//! which is what Rust's `==` and `str::contains` already are — so there is nothing to port there,
//! and a term containing `*` matches an app whose name really contains `*`, in both programs.
//!
//! # The one deliberate extension: bundle ids and cask tokens also resolve
//!
//! The oracle matches display names only. This engine must also accept an exact **bundle id** and an
//! exact **`uninstall_name`** (the lowercase Homebrew cask token), because both are what its own
//! callers send:
//!
//!  - `SoftwareModel.previewSource` sends `app.bundleId` positionally to this engine
//!    (`SoftwareView.swift:712`), and the MCP tool surface documents `uninstall` as bundle-id-shaped.
//!  - `SoftwareModel.removeSelected` sends `app.uninstallName` (`SoftwareView.swift:916`), which for
//!    a brew-managed app is the cask token — `google-chrome`, not `Google Chrome`. The oracle's own
//!    matcher cannot resolve that, even though the same program's `--list` prints it under
//!    `UNINSTALL NAME` and tells the user to pass it. Matching it here is a fix for that, not a
//!    liberty: it resolves to the same app `--list` was describing.
//!
//! The extension runs BETWEEN the oracle's two passes. That placement is what keeps it additive:
//! anything the oracle exact-matched still exact-matches first and resolves identically, and only a
//! term the oracle would have substring-matched (or missed entirely) can reach the new pass — a term
//! that is character-for-character some app's bundle id or cask token, where a substring match would
//! have been an accident.
//!
//! Two things the extension must NOT do, both of which it used to:
//!
//!  - **Resolve the `"unknown"` sentinel.** `list::build_row` writes the literal
//!    [`crate::uninstall::list::UNKNOWN_BUNDLE_ID`] into `bundle_id` for a bundle with no
//!    `CFBundleIdentifier`, `dedupe_by_bundle_id` deliberately skips those rows so every one of them
//!    survives into the inventory, and `uninstall --list` PUBLISHES it as that row's identifier. So
//!    `uninstall unknown` used to take the first such app and delete it, with nothing anywhere
//!    reporting an ambiguity. It is not an identifier and it is excluded here.
//!  - **Pick one of several.** The pass was a `position()` — first hit, silently. That is only safe
//!    while the identifier is unique, which the sentinel broke; it now collects every hit and the
//!    caller refuses a term that identified more than one app.
//!
//! # What "ambiguous" means, and why counting [`Resolution::matched`] cannot answer it
//!
//! `matched` is deduplicated by inventory position, so an app a later term sweeps but an earlier
//! term already took does not appear again. Counting a term's contribution to `matched` therefore
//! counts what it NEWLY ADDED, not what it SWEPT — and naming k apps explicitly beside a broad term
//! that hits those k plus one more made the broad term look like a 1:1 match. [`Resolution::swept`]
//! records the sweep itself, before dedup, which is the number the confirmation gate has to read.

use crate::uninstall::list::{AppRow, UNKNOWN_BUNDLE_ID};

/// Which of the three passes produced a match. Reported because "you named this app" and "a
/// substring sweep happened to reach it" are different facts about a deletion, and only the caller
/// can decide what to do about the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchPass {
    /// Pass 1 — the oracle's exact display-name / `.app` basename match.
    Exact,
    /// Pass 1b — this engine's exact bundle-id / cask-token extension.
    Identifier,
    /// Pass 2 — the oracle's substring fallback.
    Substring,
}

/// One resolved app, and the search term that resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    /// The argument the caller passed, verbatim — so a report can say which request produced this.
    pub query: String,
    /// The inventory row it resolved to.
    pub row: AppRow,
    /// How it was found.
    pub pass: MatchPass,
}

/// A term that identified more than one application, and every app it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    pub query: String,
    /// Every app the term hit, INCLUDING ones an earlier term had already taken — the whole point
    /// of recording this separately from [`Resolution::matched`].
    pub names: Vec<String>,
}

/// The outcome of resolving a whole argv's worth of names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    /// Resolved apps, in the order the oracle would have collected them: term by term, and within a
    /// substring pass, in inventory order. Deduplicated by inventory position.
    pub matched: Vec<Matched>,
    /// Terms that matched no app. The oracle warns per term and carries on
    /// (`bin/uninstall.sh:1185`); these are reported rather than dropped.
    pub unmatched: Vec<String>,
    /// Terms that reached more than one application. Counted BEFORE the position dedup, so a term
    /// that swept an app an earlier term already took still counts it. See the module docs.
    pub swept: Vec<Sweep>,
}

impl Resolution {
    /// True when nothing resolved — the oracle's `${#selected_apps[@]} -eq 0`, which is the one
    /// condition it treats as fatal (`bin/uninstall.sh:1393-1397`).
    pub fn is_empty(&self) -> bool {
        self.matched.is_empty()
    }
}

/// The `.app` directory basename without its extension — the oracle's
/// `basename "$app_path" .app`, the second haystack every comparison below uses.
fn dir_name(path: &str) -> &str {
    let base = path.rsplit('/').next().unwrap_or(path);
    base.strip_suffix(".app").unwrap_or(base)
}

/// Resolve search terms against the installed inventory. Pure: the caller supplies the inventory, so
/// this is exercised against a loaded fixture rather than against whatever is in `/Applications`.
///
/// See the module docs for the ported algorithm and for the one deliberate extension.
pub fn match_apps_by_name(inventory: &[AppRow], terms: &[&str]) -> Resolution {
    let mut out = Resolution::default();
    let mut taken = vec![false; inventory.len()];

    // Lowercased once per row rather than once per (row, term) — the oracle re-runs `tr` inside both
    // loops, which is the same comparison at a few thousand times the cost.
    let lowered: Vec<(String, String)> = inventory
        .iter()
        .map(|r| (r.name.to_lowercase(), dir_name(&r.path).to_lowercase()))
        .collect();

    for term in terms {
        let needle = term.to_lowercase();
        // bash's per-term `found`. It is set by a HIT, not by an addition: an app already taken by
        // an earlier term still counts as found, so `uninstall Slack Slack` neither falls through to
        // the substring sweep on the second term nor warns about it.
        let mut found = false;
        let take = |i: usize, pass: MatchPass, taken: &mut Vec<bool>, out: &mut Resolution| {
            if !taken[i] {
                taken[i] = true;
                out.matched.push(Matched {
                    query: (*term).to_string(),
                    row: inventory[i].clone(),
                    pass,
                });
            }
        };
        // Every app THIS term reached, recorded before the dedup above can hide one. See the module
        // docs: this is the number the confirmation gate reads, and counting `matched` instead is
        // what let one named app disguise a two-app sweep.
        let mut hits: Vec<String> = Vec::new();

        // Pass 1 — the oracle's exact match: first hit only, then `break`.
        if let Some(i) = lowered
            .iter()
            .position(|(name, dir)| *name == needle || *dir == needle)
        {
            hits.push(inventory[i].name.clone());
            take(i, MatchPass::Exact, &mut taken, &mut out);
            found = true;
        }

        // Pass 1b — the engine's extension: an exact bundle id or cask token. See the module docs
        // for why this is here, why it sits between the oracle's two passes, why the `"unknown"`
        // sentinel is excluded, and why it collects instead of taking the first hit.
        // The two exclusions are on the NEEDLE rather than repeated per row, so there is exactly one
        // place that decides what is not an identifier: the empty string, and the `"unknown"`
        // sentinel that `list::build_row` writes for a bundle with no `CFBundleIdentifier`. An app
        // genuinely DISPLAY-NAMED "unknown" is unaffected — pass 1 matches display names and runs
        // first.
        if !found && !needle.is_empty() && needle != UNKNOWN_BUNDLE_ID {
            for (i, r) in inventory.iter().enumerate() {
                if r.bundle_id.to_lowercase() == needle || r.uninstall_name.to_lowercase() == needle
                {
                    hits.push(r.name.clone());
                    take(i, MatchPass::Identifier, &mut taken, &mut out);
                    found = true;
                }
            }
        }

        // Pass 2 — the oracle's substring fallback: every match, no early exit.
        if !found {
            for (i, (name, dir)) in lowered.iter().enumerate() {
                if name.contains(&needle) || dir.contains(&needle) {
                    hits.push(inventory[i].name.clone());
                    take(i, MatchPass::Substring, &mut taken, &mut out);
                    found = true;
                }
            }
        }

        if hits.len() > 1 {
            out.swept.push(Sweep {
                query: (*term).to_string(),
                names: hits,
            });
        }
        if !found {
            out.unmatched.push((*term).to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vendored `uninstall --list` capture, loaded and parsed into rows — the same real
    /// inventory the resolver sees in production, not a shape typed out here (RULEBOOK §3e).
    fn inventory() -> Vec<AppRow> {
        crate::uninstall::list::tests_support::golden_rows()
    }

    #[test]
    fn the_fixture_is_the_real_capture() {
        let inv = inventory();
        assert!(
            inv.len() >= 4,
            "the golden capture should carry several rows: {}",
            inv.len()
        );
        assert!(
            inv.iter().any(|r| r.source == "Homebrew"),
            "the golden covers both source values, which is what makes the cask-token case testable"
        );
    }

    #[test]
    fn an_exact_display_name_resolves_case_insensitively() {
        let inv = inventory();
        let target = &inv[0];
        let res = match_apps_by_name(&inv, &[&target.name.to_uppercase()]);
        assert_eq!(res.matched.len(), 1, "one app, from an exact name");
        assert_eq!(res.matched[0].row, *target);
        assert!(res.unmatched.is_empty());
    }

    #[test]
    fn a_bundle_directory_name_resolves_even_when_the_display_name_differs() {
        let inv = inventory();
        // A row whose `.app` basename is not its display name is the case the oracle's second
        // haystack exists for; skip the assertion when the capture happens to have none.
        let Some(row) = inv
            .iter()
            .find(|r| dir_name(&r.path).to_lowercase() != r.name.to_lowercase())
        else {
            return;
        };
        let res = match_apps_by_name(&inv, &[dir_name(&row.path)]);
        assert_eq!(res.matched.len(), 1, "{:?}", res);
        assert_eq!(&res.matched[0].row, row);
    }

    #[test]
    fn every_uninstall_name_the_listing_advertises_resolves() {
        // `--list` prints `uninstall_name` under `UNINSTALL NAME` and tells the user to pass it, so
        // every value it emits has to resolve. Most reach the app through the plain exact-name pass;
        // the ones that do not are what the cask-token pass exists for (next test).
        let inv = inventory();
        for row in &inv {
            let res = match_apps_by_name(&inv, &[&row.uninstall_name]);
            assert!(
                res.matched.iter().any(|m| &m.row == row),
                "`--list` advertises `{}` for {} but it does not resolve: {res:?}",
                row.uninstall_name,
                row.name
            );
        }
    }

    #[test]
    fn a_cask_token_resolves_even_when_it_is_not_the_display_name() {
        // Every Homebrew row in the capture is a single-word app whose cask token and display name
        // are the same string once lowercased ("Stats" / "stats"), so they all resolve through the
        // oracle's plain exact-name pass and none of them exercises this one. The case that does —
        // a multi-word cask, `google-chrome` for "Google Chrome", which the oracle's own matcher
        // cannot resolve — has to be built from a real captured row; only the three fields whose
        // divergence is the whole point are changed.
        let mut inv = inventory();
        let i = inv
            .iter()
            .position(|r| r.source == "Homebrew")
            .expect("the golden covers the Homebrew source");
        let bundle_id = inv[i].bundle_id.clone();
        inv[i].name = "Google Chrome".to_string();
        inv[i].path = "/Applications/Google Chrome.app".to_string();
        inv[i].uninstall_name = "google-chrome".to_string();

        let res = match_apps_by_name(&inv, &["google-chrome"]);
        assert_eq!(
            res.matched.len(),
            1,
            "`google-chrome` is exactly what `--list` tells the user to pass, and what \
             `SoftwareModel.removeSelected` sends: {res:?}"
        );
        assert_eq!(res.matched[0].row.bundle_id, bundle_id);
        assert!(res.unmatched.is_empty(), "{res:?}");
    }

    #[test]
    fn an_exact_bundle_id_resolves_to_its_app() {
        let inv = inventory();
        let row = inv
            .iter()
            .find(|r| r.bundle_id != "unknown")
            .expect("the golden has a row with a real bundle id")
            .clone();
        let res = match_apps_by_name(&inv, &[&row.bundle_id]);
        assert_eq!(res.matched.len(), 1, "{res:?}");
        assert_eq!(res.matched[0].row, row);
    }

    #[test]
    fn every_app_in_a_multi_app_request_resolves() {
        let inv = inventory();
        let names: Vec<String> = inv.iter().take(3).map(|r| r.name.clone()).collect();
        assert_eq!(names.len(), 3, "the golden must carry at least three rows");
        let terms: Vec<&str> = names.iter().map(String::as_str).collect();
        let res = match_apps_by_name(&inv, &terms);
        assert_eq!(
            res.matched.len(),
            3,
            "three names in, three apps out — one-in-three-out is the bug this closes: {res:?}"
        );
        for (want, got) in names.iter().zip(&res.matched) {
            assert_eq!(&got.row.name, want);
            assert_eq!(
                &got.query, want,
                "each match remembers which argument made it"
            );
        }
    }

    #[test]
    fn a_name_matching_nothing_is_reported_and_the_rest_still_resolve() {
        let inv = inventory();
        let good = inv[0].name.clone();
        let res = match_apps_by_name(&inv, &[&good, "definitely-not-installed-zzz"]);
        assert_eq!(res.matched.len(), 1, "the good name still resolves");
        assert_eq!(
            res.unmatched,
            vec!["definitely-not-installed-zzz".to_string()],
            "the oracle warns per term and carries on, it does not abort: {res:?}"
        );
        assert!(!res.is_empty(), "a partial match is not an empty result");
    }

    #[test]
    fn nothing_matching_at_all_is_an_empty_resolution() {
        let inv = inventory();
        let res = match_apps_by_name(&inv, &["zzz-nope", "also-zzz-nope"]);
        assert!(res.is_empty(), "{res:?}");
        assert_eq!(res.unmatched.len(), 2);
    }

    #[test]
    fn the_same_name_twice_resolves_to_one_app() {
        let inv = inventory();
        let name = inv[0].name.clone();
        let res = match_apps_by_name(&inv, &[&name, &name]);
        assert_eq!(
            res.matched.len(),
            1,
            "dedup is by inventory position, exactly as bash's matched_indices does it: {res:?}"
        );
        assert!(
            res.unmatched.is_empty(),
            "the second term found the app, it was simply already taken — no warning: {res:?}"
        );
    }

    #[test]
    fn a_substring_takes_every_match_not_just_the_first() {
        // Two rows sharing a substring, built from real golden rows so the shape is the captured
        // one; only the names are set to make the ambiguity deterministic.
        let mut inv = inventory();
        assert!(inv.len() >= 2);
        inv[0].name = "Shared Alpha".to_string();
        inv[1].name = "Shared Beta".to_string();
        let res = match_apps_by_name(&inv, &["shared"]);
        assert_eq!(
            res.matched.len(),
            2,
            "the oracle's substring pass has no `break`: {res:?}"
        );
    }

    /// **A sweep is counted by what it HITS, not by what it newly contributes.**
    ///
    /// `matched` is deduplicated by inventory position, so an app a later term sweeps but an earlier
    /// term already took never appears in the later term's contribution. That is why the caller's
    /// confirmation gate reads `swept`: grouping `matched` by `query` gave every group a length of 1
    /// for `["Qxzy One", "qxzy"]`, and the apply then removed both applications without asking.
    #[test]
    fn a_sweep_counts_an_app_an_earlier_term_already_took() {
        let mut inv = inventory();
        assert!(inv.len() >= 2);
        inv[0].name = "Qxzy One".to_string();
        inv[1].name = "Qxzy Two".to_string();

        let res = match_apps_by_name(&inv, &["Qxzy One", "qxzy"]);
        assert_eq!(res.matched.len(), 2, "both apps still resolve: {res:?}");
        // The dedup really does hide it — this is the fact the gate used to be built on.
        assert_eq!(
            res.matched.iter().filter(|m| m.query == "qxzy").count(),
            1,
            "the sweep contributed one NEW app, which is what made it look precise: {res:?}"
        );
        assert_eq!(res.swept.len(), 1, "{res:?}");
        assert_eq!(res.swept[0].query, "qxzy");
        assert_eq!(
            res.swept[0].names,
            vec!["Qxzy One".to_string(), "Qxzy Two".to_string()],
            "the sweep names BOTH, including the one already taken: {res:?}"
        );

        // A term that reaches exactly one app is not a sweep, so a precise request is untouched.
        let res = match_apps_by_name(&inv, &["Qxzy One", "Qxzy Two"]);
        assert!(res.swept.is_empty(), "{res:?}");
        assert!(res.matched.iter().all(|m| m.pass == MatchPass::Exact));
    }

    /// **The `"unknown"` sentinel is not an identifier.** `list::build_row` writes it for a bundle
    /// with no `CFBundleIdentifier` and `dedupe_by_bundle_id` deliberately keeps every such row, so
    /// matching on it picked whichever of them sorted first — and `uninstall --list` publishes the
    /// value, which is exactly what an agent would read off a listing and pass back.
    #[test]
    fn the_unknown_sentinel_matches_nothing_while_a_real_bundle_id_still_matches() {
        let mut inv = inventory();
        assert!(inv.len() >= 2);
        for r in inv.iter_mut().take(2) {
            r.bundle_id = UNKNOWN_BUNDLE_ID.to_string();
        }
        let res = match_apps_by_name(&inv, &[UNKNOWN_BUNDLE_ID]);
        assert!(
            res.matched.is_empty(),
            "`unknown` identifies no application: {res:?}"
        );
        assert_eq!(res.unmatched, vec![UNKNOWN_BUNDLE_ID.to_string()]);

        // The pass itself is intact for a real id.
        let real = inv
            .iter()
            .find(|r| r.bundle_id != UNKNOWN_BUNDLE_ID)
            .expect("the golden has a row with a real bundle id")
            .clone();
        let res = match_apps_by_name(&inv, &[&real.bundle_id]);
        assert_eq!(res.matched.len(), 1, "{res:?}");
        assert_eq!(res.matched[0].pass, MatchPass::Identifier);
    }

    /// An identifier that identifies more than one app is reported as a sweep rather than silently
    /// resolved to the first — the pass used to be a `position()`, which cannot say that at all.
    #[test]
    fn an_identifier_matching_several_rows_is_reported_rather_than_picking_one() {
        let mut inv = inventory();
        assert!(inv.len() >= 2);
        inv[0].uninstall_name = "shared-token".to_string();
        inv[1].uninstall_name = "shared-token".to_string();
        let res = match_apps_by_name(&inv, &["shared-token"]);
        assert_eq!(res.matched.len(), 2, "{res:?}");
        assert_eq!(res.swept.len(), 1, "the caller can refuse this: {res:?}");
        assert_eq!(res.swept[0].names.len(), 2);
    }

    #[test]
    fn an_exact_match_wins_over_a_substring_and_takes_only_one_app() {
        let mut inv = inventory();
        assert!(inv.len() >= 2);
        inv[0].name = "Mail".to_string();
        inv[1].name = "Mailplane".to_string();
        let res = match_apps_by_name(&inv, &["Mail"]);
        assert_eq!(
            res.matched.len(),
            1,
            "an exact hit breaks out before the substring pass ever runs: {res:?}"
        );
        assert_eq!(res.matched[0].row.name, "Mail");
    }
}
