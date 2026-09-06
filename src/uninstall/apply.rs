//! The `uninstall` orchestration — everything between the parsed argv and the envelope: resolve
//! the names against the inventory, refuse what the oracle refuses, remove each app's bundle and
//! then its leftovers through the shared rails, record the audit trail, and build the payload.
//! `cli.rs` parses and wraps; nothing here knows what an envelope or a flag is (BUR-126 moved it
//! out of `cli.rs`, where it had grown to ~800 lines).
//!
//! Every subprocess goes through the injected [`crate::uninstall::bundle::Runner`], and the
//! filesystem work through `crate::clean::execute`, so the whole command is driven by fakes in
//! `cli.rs`'s tests without a real `/Applications` or a real `brew`.

use crate::json::escape as esc;

/// What the caller asked for, already parsed: the app names/bundle ids, whether to act, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub terms: Vec<&'a str>,
    pub apply: bool,
    pub permanent: bool,
}

/// Uninstall the named apps — the whole of the command after argv and before the envelope.
///
/// `Ok((data, exit_code))` is the payload the caller wraps as `data`; `Err(message)` is a refusal
/// the caller wraps as an error envelope with exit 1 (no name given, a protected system component,
/// no match, or the confirmation gate). The subprocess runner is injected because this can run
/// `brew uninstall --cask --zap`, which deletes an application and, via the cask's zap stanza, an
/// unbounded set of other paths: every brew decision is drivable from a fake, so no test is one
/// bad fixture away from running it for real. Production passes
/// [`crate::uninstall::bundle::system_runner`].
pub fn uninstall(
    request: &Request<'_>,
    inventory: &[crate::uninstall::list::AppRow],
    home: &str,
    run: crate::uninstall::bundle::Runner,
) -> Result<(String, i32), String> {
    use crate::clean::{
        format::bytes_to_human,
        protect::{should_protect_from_uninstall, ProtectionMode},
    };
    use crate::uninstall::bundle;
    let terms: &[&str] = &request.terms;
    if terms.is_empty() {
        return Err(
            "uninstall needs an app name or bundle id (see `uninstall --list`)".to_string(),
        );
    }
    // The oracle's app-level gate (`bin/uninstall.sh:438` → `should_protect_from_uninstall`), which
    // makes a system-critical app ineligible before anything is listed, let alone removed. Refused
    // for the dry run as well as for `--apply`: a listing that promises leftovers the tool will then
    // refuse to touch is the same class of lie as the silent no-op this command just came out of.
    //
    // Checked on the raw argument, BEFORE resolution, and deliberately so: `list::build_row` already
    // drops protected bundles from the inventory, so `uninstall com.apple.finder` would otherwise
    // resolve to nothing and come back as a generic "no matching applications", which tells the
    // caller the app is not installed rather than that the engine refuses to touch it.
    //
    // The oracle reaches the same refusal a different way — the gate runs during its scan, so a
    // protected app never enters `apps_data` and its matcher simply warns. It can afford that
    // because it only ever matches DISPLAY NAMES; this engine also accepts bundle ids
    // (`SoftwareModel.previewSource` sends one), and "Finder is not installed" would be a lie
    // where "Finder is protected" is the truth. Naming a protected app the way the oracle's own
    // matcher would — `uninstall Finder` — still lands on the plain no-match answer, matching bash.
    if let Some(protected) = terms
        .iter()
        .find(|t| should_protect_from_uninstall(t))
        .copied()
    {
        return Err(format!(
            "{protected} is a protected system component and cannot be uninstalled"
        ));
    }

    let resolution = crate::uninstall::resolve::match_apps_by_name(inventory, terms);
    if resolution.is_empty() {
        // The oracle's exact wording and exit code (`bin/uninstall.sh:1395-1396`). Kept verbatim
        // because `UninstallGuard.matchedApps` looks for this sentence to mean "mo matched nothing",
        // and answering it with a matched-set of `[]` is what makes the app's preflight fail closed.
        return Err(format!(
            "No matching applications found. ({})",
            resolution.unmatched.join(", ")
        ));
    }

    let apply = request.apply;
    let permanent = request.permanent;

    // A broad term such as `uninstall e` can match many applications because the substring sweep
    // has no `break` and no cap. That sweep is FAITHFUL
    // (`bin/uninstall.sh:1153-1178`, and `tests/uninstall.bats:1439` pins multi-match as intended),
    // so the fix cannot be to narrow it. What the port dropped is the other half of the oracle's
    // behaviour: having matched, bash prints a numbered list with the match count and BLOCKS on
    // `Proceed with uninstallation? [y/N]` (`:1400-1420`). Nothing is removed until a human types
    // `y`; anything else, INCLUDING EOF on a non-interactive stdin, falls to `Aborted.`.
    //
    // This engine is one-shot JSON and cannot prompt, so the honest equivalent of a `[y/N]` whose
    // default is No, asked of a caller that cannot answer, is to not act.
    //
    // **The gate reads the SWEEP, not a grouping of the resolved set**, and the difference is a hole
    // wide enough to delete an application through. `resolution.matched` is deduplicated by inventory
    // position, so grouping it by `query` counted what each term NEWLY CONTRIBUTED rather than what
    // it SWEPT — and naming one app explicitly beside a broad term that hits that app plus one more
    // gave every group a length of 1. Measured, on two apps sharing the prefix `Qxzy`:
    //
    // ```text
    // uninstall qxzy --dry-run                       matched 2, requires_confirmation TRUE
    // uninstall "Qxzy One" qxzy --dry-run            matched 2, requires_confirmation FALSE
    // uninstall "Qxzy One" qxzy --apply --permanent  exit 0, ok:true, BOTH bundles deleted
    // ```
    //
    // `resolve::Resolution::swept` counts the hits before the dedup can hide one, which is the number
    // bash's `Matched N app(s):` is a readout of. A term that reached exactly one app resolves 1:1 and
    // is unaffected — that is every argv the app sends (`SoftwareModel.previewSource` sends a bundle
    // id, `removeSelected` sends one `uninstall_name` per selected row).
    //
    // Refused rather than gated behind a new acknowledgement flag: re-issuing the command with the
    // apps named is itself the acknowledgement, and it is the one the oracle asks for — bash shows
    // you THAT LIST and makes you agree to THAT LIST. A `--yes` flag would let the same one-character
    // argv through with one more token, which is not a confirmation, it is a keystroke.
    let ambiguous = &resolution.swept;
    if apply {
        if let Some(sweep) = ambiguous.first() {
            // Exit 1, where bash's abort path is `echo "Aborted."; return 0` (`:1418-1420`). A
            // deliberate deviation, and the reason is the same one that makes this gate exist: bash's
            // 0 is honest because a human was asked and CHOSE not to proceed, so the program did what
            // it was told. Nobody chose this. Reporting success for a removal that never happened is
            // the silent no-op this migration exists to stop, and `ok:false` is what tells a caller
            // apart from a run that removed nothing because there was nothing to remove.
            return Err(format!(
                        "'{}' matched {} apps ({}). The original lists them and asks \
                         `Proceed with uninstallation? [y/N]` before removing anything; this engine \
                         cannot ask, so it refuses. Re-run with the apps named, or without --apply \
                         to see the full list.",
                        sweep.query,
                        sweep.names.len(),
                        sweep.names.join(", ")
                    ));
        }
        // The same gate stated as an INVARIANT over the resolved set, which is the thing that must
        // hold however resolution is written later: every accepted term identifies at most one app,
        // so a run can never act on more applications than the caller named. The gate above is the
        // mechanism; this is the property, and it fails closed if some future pass grows a fan-out
        // that forgets to record a sweep.
        if resolution.matched.len() > terms.len() {
            return Err(format!(
                "{} names resolved to {} applications ({}). The original lists them and \
                         asks `Proceed with uninstallation? [y/N]`; this engine cannot ask, so it \
                         refuses to remove more applications than it was named. Re-run without \
                         --apply to see the full list.",
                terms.len(),
                resolution.matched.len(),
                resolution
                    .matched
                    .iter()
                    .map(|m| m.row.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    // Terms that resolved to nothing are reported, not dropped: the oracle warns per term and
    // carries on, so a three-app request where one name was a typo still uninstalls the other two —
    // and the caller has to be able to tell that from a clean three-for-three run.
    let unmatched = resolution
        .unmatched
        .iter()
        .map(|u| esc(u))
        .collect::<Vec<_>>()
        .join(",");

    // Per app, in resolution order: the BUNDLE and the leftovers, in that order, because that is the
    // order the oracle removes them in and the leftovers are gated on the bundle
    // (`batch.sh:756-840`). `leftover_paths` interpolates the bundle id into real paths, so a row
    // whose id is not reverse-DNS shaped — no CFBundleIdentifier at all (`list` records
    // [`UNKNOWN_BUNDLE_ID`]), or one carrying `/`, `..` or whitespace — is enumerated as zero
    // leftovers and the refusal is reported in `warnings`, rather than the sweep being pointed at
    // `~/Library/Caches/unknown` or outside `~/Library` altogether (`uninstall::leftover_refusal`,
    // the port of `mole_is_reverse_dns_bundle_id`).
    //
    // The cask token is READ OFF THE INVENTORY rather than re-detected: `list::build_row` already
    // resolves it (`list.rs:954-956`) through the full four-stage port of `get_brew_cask_name`, and a
    // second detector for the same fact is a second thing to keep in agreement.
    let mut leftover_refusals: Vec<String> = Vec::new();
    let plans: Vec<(&crate::uninstall::resolve::Matched, bundle::Plan)> = resolution
        .matched
        .iter()
        .map(|m| {
            let leftovers = match crate::uninstall::leftover_refusal(&m.row.bundle_id) {
                Some(reason) => {
                    leftover_refusals.push(format!(
                        "{}: leftovers not enumerated — {reason}",
                        m.row.name
                    ));
                    Vec::new()
                }
                None => crate::uninstall::find_leftovers(home, &m.row.bundle_id),
            };
            let cask = (m.row.source == "Homebrew").then_some(m.row.uninstall_name.as_str());
            let target = bundle::inspect(&m.row.path, cask, ProtectionMode::Uninstall);
            (
                m,
                bundle::Plan {
                    bundle: target,
                    leftovers,
                },
            )
        })
        .collect();

    // The elevated-launch trap, reported rather than silently producing an empty leftover list. See
    // `bundle::elevated_home_warning`: under `do shell script … with administrator privileges` the
    // engine's `$HOME` is `/var/root`, so the bundle comes away while the user's real support files
    // are never even looked at.
    let mut warnings: Vec<String> = bundle::elevated_home_warning(home).into_iter().collect();
    warnings.extend(leftover_refusals);
    // A `.app` that is a SYMLINK. Removing it unlinks the name and leaves the application installed
    // (verified — `remove_dir_all` does not follow, and that is correct), so "removed" here means
    // something different from what it means everywhere else in this report and has to say so.
    // `bundle::inspect` sizes such a bundle by the link rather than by its target for the same
    // reason: sizing through it promised, and then claimed as freed, bytes belonging to an app that
    // is still there.
    for (_, plan) in &plans {
        if let Some(target) = &plan.bundle.symlink_target {
            warnings.push(format!(
                "{} is a symbolic link to {target}. Removing it deletes the link only; the \
                 application itself stays installed, and only the link's own bytes are counted.",
                plan.bundle.path
            ));
        }
    }
    let warnings_json = warnings
        .iter()
        .map(|w| esc(w))
        .collect::<Vec<_>>()
        .join(",");

    /// The identity of one resolved app, repeated in each per-app report entry: what was asked for,
    /// what it resolved to, where that app lives, and HOW the two were connected.
    ///
    /// `matched_by` is the last of those and it is not decoration: `exact` and `identifier` mean the
    /// caller named this application, `substring` means a sweep reached it. An agent that sent a
    /// bundle id and reads `substring` back has learnt that its identifier did not resolve and
    /// something looser did — which is the fact the confirmation gate is built on, exposed so a
    /// caller can apply its own judgement rather than only being told yes or no.
    fn app_identity(m: &crate::uninstall::resolve::Matched) -> String {
        use crate::uninstall::resolve::MatchPass;
        format!(
            "\"query\":{},\"name\":{},\"bundle_id\":{},\"path\":{},\"matched_by\":{}",
            esc(&m.query),
            esc(&m.row.name),
            esc(&m.row.bundle_id),
            esc(&m.row.path),
            esc(match m.pass {
                MatchPass::Exact => "exact",
                MatchPass::Identifier => "identifier",
                MatchPass::Substring => "substring",
            })
        )
    }

    if !apply {
        // `items` and `total_human` stay flattened across every resolved app and keep their shape:
        // `UninstallPreview.fromEngineEnvelope` reads exactly those two and nothing else, so a
        // restructure here would empty the GUI's leftover review with no error anywhere. Each item
        // gains `bundle_id` so a multi-app listing is still attributable per app, and `kind` so an
        // application is distinguishable from a support file.
        //
        // THE BUNDLE IS IN `items[]`, FIRST, per app. That is the whole point of the dry run now:
        // the apply removes the application, so the preview has to name it or the user is
        // authorising something they were not shown. `UninstallPreview.classify`
        // (`UninstallPreview.swift:107-109`) already maps a `.app` path to its `.application` kind,
        // so the GUI renders it correctly without a decoder change.
        let mut items: Vec<String> = Vec::new();
        let mut apps: Vec<String> = Vec::new();
        let mut total = 0u64;
        let mut external: Vec<String> = Vec::new();
        let mut removes_applications = 0usize;
        let mut requires_admin = false;
        for (m, plan) in &plans {
            let app_total = plan.preview_bytes();
            total += app_total;
            for (kind, c) in plan.preview_items() {
                items.push(format!(
                    "{{\"path\":{},\"label\":{},\"size\":{},\"size_human\":{},\"bundle_id\":{},\"kind\":{}}}",
                    esc(&c.path),
                    esc(&c.label),
                    c.size,
                    esc(&bytes_to_human(c.size)),
                    esc(&m.row.bundle_id),
                    esc(kind)
                ));
            }
            let b = &plan.bundle;
            if b.present && b.refusal.is_none() {
                removes_applications += 1;
                requires_admin |= b.needs_admin;
            }
            let action = match &b.action {
                bundle::BundleAction::Delete => "delete",
                bundle::BundleAction::BrewZap(_) => "brew_zap",
            };
            // The `--zap` declaration. `batch.sh:585` warns about this in the oracle's own preview
            // ("Homebrew apps will be fully cleaned, --zap removes configs and data") because the
            // stanza deletes paths no enumeration can predict. Naming the exact command is the only
            // honest way to preview an unbounded delete.
            if let bundle::BundleAction::BrewZap(token) = &b.action {
                if b.present {
                    external.push(format!(
                        "{{\"bundle_id\":{},\"name\":{},\"command\":{},\"note\":{}}}",
                        esc(&m.row.bundle_id),
                        esc(&m.row.name),
                        esc(&format!("brew uninstall --cask --zap {token}")),
                        esc(
                            "Homebrew removes this app; --zap also deletes configuration and data \
                             the cask declares, which are not enumerated above."
                        )
                    ));
                }
            }
            let leftover_bytes: u64 = plan.leftovers.iter().map(|c| c.size).sum();
            let application = format!(
                "{{\"path\":{},\"present\":{},\"size\":{},\"size_human\":{},\"needs_admin\":{},\"action\":{},\"cask\":{},\"refusal\":{},\"symlink\":{},\"symlink_target\":{}}}",
                esc(&b.path),
                b.present,
                b.size,
                esc(&bytes_to_human(b.size)),
                b.needs_admin,
                esc(action),
                match &b.action {
                    bundle::BundleAction::BrewZap(t) => esc(t),
                    bundle::BundleAction::Delete => "null".to_string(),
                },
                b.refusal.as_deref().map_or("null".to_string(), esc),
                b.symlink_target.is_some(),
                b.symlink_target
                    .as_deref()
                    .map_or("null".to_string(), esc)
            );
            apps.push(format!(
                "{{{},\"item_count\":{},\"leftover_bytes\":{},\"total_bytes\":{},\"total_human\":{},\"application\":{}}}",
                app_identity(m),
                // Unchanged meaning: the SUPPORT-FILE count. The bundle is not folded into it —
                // `application` below is where it lives, and `total_bytes` is the sum of both, which
                // is what the oracle's `total_kb = app_size_kb + related_size_kb` (`batch.sh:521`)
                // is. Leaving `item_count` alone and adding `leftover_bytes` beside it makes the
                // decomposition explicit instead of silently redefining a field a caller may read.
                plan.leftovers.len(),
                leftover_bytes,
                app_total,
                esc(&bytes_to_human(app_total)),
                application
            ));
        }
        // `matched_count` and `requires_confirmation` are the dry run's half of the gate above: the
        // engine cannot print `Matched 66 app(s):` and wait, but it CAN hand the caller the same two
        // facts before the caller commits to `--apply`. `apps[]` already carried every resolved
        // name — a caller COULD have counted it, and nothing made it. Naming the count and the
        // verdict is what turns "available in the payload" into "hard to miss", and it is what lets
        // a GUI reproduce the oracle's numbered list + prompt rather than inventing its own rule.
        // Additive: `UninstallPreview.fromEngineEnvelope` reads `items` and `total_human` by key
        // (`UninstallPreview.swift:143-151`), so new keys beside them change nothing it sees.
        let ambiguous_json = ambiguous
            .iter()
            .map(|sweep| {
                format!(
                    "{{\"query\":{},\"matched\":{},\"names\":[{}]}}",
                    esc(&sweep.query),
                    sweep.names.len(),
                    sweep
                        .names
                        .iter()
                        .map(|n| esc(n))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let data = format!(
            "{{\"dry_run\":true,\"total_bytes\":{},\"total_human\":{},\"items\":[{}],\"apps\":[{}],\"unmatched\":[{}],\"matched_count\":{},\"requires_confirmation\":{},\"ambiguous\":[{}],\"removes_applications\":{},\"requires_admin\":{},\"external_commands\":[{}],\"warnings\":[{}]}}",
            total,
            esc(&bytes_to_human(total)),
            items.join(","),
            apps.join(","),
            unmatched,
            plans.len(),
            !ambiguous.is_empty(),
            ambiguous_json,
            removes_applications,
            requires_admin,
            external.join(","),
            warnings_json
        );
        return Ok((data, 0));
    }

    // **THE AUDIT RECORD.** `clean`, `purge` and `installer` each open one and the command that
    // deletes APPLICATIONS did not, so a `--permanent` or a `--zap` left no record anywhere of what
    // it removed. The oracle has no such gap: `mole_delete` appends
    // `<ts>\t<mode>\t<size_kb>\t<status>\t<path>` to `~/Library/Logs/mole/deletions.log` for every
    // path it touches (`file_ops.sh:491-596`), including the ones it REFUSES — `rejected` at `:523`
    // exists precisely so an audit trail can tell refused-by-policy from never-attempted.
    //
    // Opened on the apply path only, which is where this port differs from bash and deliberately:
    // `mole_delete` also writes a `dry-run` record, but no engine command logs a preview and adding
    // one here would put `uninstall` alone out of step with its three siblings. What a dry run
    // changes on disk is nothing, and that is the fact the log exists to record.
    let log = crate::history::write::SessionLog::start_under("uninstall", Some(home));
    let mode = crate::clean::execute::RemovalMode::from_permanent(permanent);
    let mut removed: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut protected: Vec<String> = Vec::new();
    let mut apps: Vec<String> = Vec::new();
    let mut freed = 0u64;
    let mut moved_to_trash = 0u64;
    let mut failed = false;
    let mut logged_items = 0u64;
    let mut applications_removed = 0usize;
    let mut applications_refused = 0usize;
    let mut applications_failed = 0usize;
    for (m, plan) in &plans {
        // 1. THE BUNDLE, FIRST — `batch.sh:756-838`.
        let state = remove_bundle(plan, permanent, run);
        log_bundle_removal(&log, mode, &plan.bundle, &state);
        if matches!(state, bundle::BundleState::Removed { .. }) {
            logged_items += 1;
        }
        if let bundle::BundleState::Removed { via, bytes } = &state {
            // A Trash move frees nothing until the Trash is emptied (RULEBOOK §3m); brew and
            // `--permanent` unlink.
            if *via == bundle::RemovedVia::Trash {
                moved_to_trash += bytes;
            } else {
                freed += bytes;
            }
            applications_removed += 1;
            removed.push(format!(
                "{{\"path\":{},\"size\":{},\"bundle_id\":{},\"kind\":{}}}",
                esc(&plan.bundle.path),
                bytes,
                esc(&m.row.bundle_id),
                esc(bundle::KIND_APPLICATION)
            ));
        }
        match &state {
            bundle::BundleState::Refused { reason } => {
                applications_refused += 1;
                protected.push(esc(&plan.bundle.path));
                errors.push(format!(
                    "{{\"path\":{},\"error\":{},\"bundle_id\":{},\"kind\":{}}}",
                    esc(&plan.bundle.path),
                    esc(reason),
                    esc(&m.row.bundle_id),
                    esc(bundle::KIND_APPLICATION)
                ));
            }
            bundle::BundleState::Failed { reason, .. } => {
                applications_failed += 1;
                errors.push(format!(
                    "{{\"path\":{},\"error\":{},\"bundle_id\":{},\"kind\":{}}}",
                    esc(&plan.bundle.path),
                    esc(reason),
                    esc(&m.row.bundle_id),
                    esc(bundle::KIND_APPLICATION)
                ));
            }
            _ => {}
        }

        // 2. THE LEFTOVERS, GATED ON THE BUNDLE — `batch.sh:840`'s `if [[ -z "$reason" ]]`. An app
        //    whose bundle could not be removed keeps its support files, because half-uninstalling an
        //    app you could not uninstall leaves it broken rather than merely present. Surprising, and
        //    reproduced deliberately; see `bundle`'s module docs.
        let gate_open = bundle::Plan::leftovers_follow_the_bundle(&state);
        let outcome = if gate_open {
            crate::clean::execute::execute_clean(
                &plan.leftovers,
                &[],
                permanent,
                ProtectionMode::Uninstall,
            )
        } else {
            crate::clean::execute::CleanOutcome::default()
        };
        crate::history::write::log_clean_items(&log, mode, &outcome);
        logged_items += outcome.removed.len() as u64;
        freed += outcome.freed_bytes;
        moved_to_trash += outcome.moved_to_trash_bytes;
        failed |= !outcome.errors.is_empty() || !gate_open;
        for c in &outcome.removed {
            // `bytes()`, not the planned size: what this run can prove it freed. Uninstall's
            // leftovers never go through a tool delegate, so in practice every entry here is a real
            // removal — but reading the accounting field keeps the invariant
            // `sum(removed[].size) == freed_bytes` true here too, instead of resting on that
            // "in practice".
            removed.push(format!(
                "{{\"path\":{},\"size\":{},\"bundle_id\":{},\"kind\":{}}}",
                esc(&c.path),
                c.bytes(),
                esc(&m.row.bundle_id),
                esc(bundle::KIND_LEFTOVER)
            ));
        }
        for e in &outcome.errors {
            errors.push(format!(
                "{{\"path\":{},\"error\":{},\"bundle_id\":{},\"kind\":{}}}",
                esc(&e.path),
                esc(&e.error),
                esc(&m.row.bundle_id),
                esc(bundle::KIND_LEFTOVER)
            ));
        }
        for p in &outcome.protected {
            protected.push(esc(p));
        }

        // 3. The per-app verdict. "The leftovers went but the bundle did not" is NOT a success, and
        //    used to report as one — `status` is the field that makes that impossible to miss.
        //
        //    Keyed off the STATE, not off `gate_open`. `Refused` and `Failed` both close the gate,
        //    so keying off the gate reported "refused" for a bundle that this engine tried and could
        //    not remove — `EPERM` presented to the user as a policy decision. `UninstallGuard`
        //    already distinguishes the two in its own wording (`refused` = "the engine refused",
        //    `failed` = "could not be removed"), so it was being handed the wrong one of the two
        //    sentences it has.
        let status = match &state {
            bundle::BundleState::Refused { .. } => "refused",
            bundle::BundleState::Failed { .. } => "failed",
            _ if outcome.errors.is_empty() && outcome.protected.is_empty() => "removed",
            _ => "partial",
        };
        let (bundle_freed, bundle_moved) = match &state {
            bundle::BundleState::Removed { via, bytes } if *via == bundle::RemovedVia::Trash => {
                (0, *bytes)
            }
            bundle::BundleState::Removed { bytes, .. } => (*bytes, 0),
            _ => (0, 0),
        };
        let app_freed = outcome.freed_bytes + bundle_freed;
        let app_moved = outcome.moved_to_trash_bytes + bundle_moved;
        let (via, reason, suggestion) = match &state {
            bundle::BundleState::Removed { via, .. } => (Some(via.word()), None, None),
            bundle::BundleState::Absent => (None, None, None),
            bundle::BundleState::Refused { reason } => (None, Some(reason.clone()), None),
            bundle::BundleState::Failed { reason, suggestion } => {
                (None, Some(reason.clone()), suggestion.clone())
            }
        };
        let application = format!(
            "{{\"path\":{},\"state\":{},\"via\":{},\"bytes\":{},\"reason\":{},\"suggestion\":{}}}",
            esc(&plan.bundle.path),
            esc(state.word()),
            via.map_or("null".to_string(), esc),
            match &state {
                bundle::BundleState::Removed { bytes, .. } => *bytes,
                _ => 0,
            },
            reason.as_deref().map_or("null".to_string(), esc),
            suggestion.as_deref().map_or("null".to_string(), esc)
        );
        // The accounting decomposes EXACTLY, and it is spelled out rather than left to be inferred:
        //   freed_bytes + moved_to_trash_bytes
        //     == application.bytes + leftover_freed_bytes + leftover_moved_to_trash_bytes
        //   (under `--permanent` or brew the `moved_to_trash` terms are 0; on the default Trash path
        //   the `freed` terms are — a Trash move frees no space, RULEBOOK §3m)
        //   removed[] for this app == (0 or 1 application) + removed_count leftovers
        // `removed_count` keeps its historical meaning — SUPPORT FILES — because a caller may
        // already read it, and `leftover_freed_bytes` is added beside it so the split is stated. The
        // alternative (silently folding the bundle into `removed_count`) would redefine a field
        // in place, which is the one thing the output contract forbids.
        apps.push(format!(
            "{{{},\"status\":{},\"application\":{},\"removed_count\":{},\"leftover_freed_bytes\":{},\"leftover_moved_to_trash_bytes\":{},\"error_count\":{},\"protected_count\":{},\"freed_bytes\":{},\"freed_human\":{},\"moved_to_trash_bytes\":{},\"moved_to_trash_human\":{},\"leftovers_attempted\":{}}}",
            app_identity(m),
            esc(status),
            application,
            outcome.removed.len(),
            outcome.freed_bytes,
            outcome.moved_to_trash_bytes,
            outcome.errors.len(),
            outcome.protected.len(),
            app_freed,
            esc(&bytes_to_human(app_freed)),
            app_moved,
            esc(&bytes_to_human(app_moved)),
            gate_open
        ));
    }
    // `protected` is reported, not silently dropped. Under `ProtectionMode::Uninstall` the set
    // should be near-empty — the oracle's uninstall skips nothing beyond system-critical components
    // — but "near-empty" is a claim about behaviour, and dropping the field is precisely how a
    // total feature failure stayed invisible: `uninstall --apply` returned `removed:[], errors:[]`,
    // exit 0, for four different real bundle IDs while deleting nothing. A caller that sees an empty
    // `removed` can now tell "there was nothing to remove" from "the engine declined to remove it",
    // and the field matches `clean`'s own `outcome_to_json` shape.
    log.end(logged_items, (freed + moved_to_trash) / 1024);
    // `failed` is the exit code, ON THE WIRE. The envelope stays `ok:true` for a run that reached
    // the removal phase, and that is a decision rather than an oversight:
    //
    //  - **The oracle agrees.** `bin/uninstall.sh:1425` is `batch_uninstall_applications; return 0`,
    //    and `_batch_execute_removals` reports per-app failures through `failed_count` /
    //    `failed_items` (`batch.sh:1049-1088`) without ever changing that status. bash's success
    //    signal is not where a partial uninstall is recorded; the per-item report is. Exiting 1 here
    //    is already stricter than the oracle.
    //  - **Flipping `ok` would DESTROY the per-app account for its one consumer.**
    //    `UninstallGuard.readOutcome` (`UninstallGuard.swift:339-345`) requires `envelope.ok` before
    //    it will decode `apps[]`, and `SoftwareView.swift:1205-1206` is what turns that into the
    //    "Uninstall finished partly" alert naming each app, its reason and the engine's suggestion.
    //    On `ok:false` it returns nil and the run falls to the generic branch, which has no
    //    classified message to find. That path already reads the exit code AND
    //    `BurrowEnvelope.reportsFailure` (`SoftwareView.swift:1196-1197`), so it does not need the
    //    flag; it needs the payload.
    //
    // What was genuinely missing is a machine-readable "this run did not do everything it was asked"
    // for a reader that cannot see the exit code — a stdout pipe, an MCP tool result. That is this
    // field, and it equals the exit status by construction.
    let data = format!(
        "{{\"dry_run\":false,\"failed\":{failed},\"freed_bytes\":{},\"freed_human\":{},\"moved_to_trash_bytes\":{},\"moved_to_trash_human\":{},\"applications_removed\":{applications_removed},\"applications_refused\":{applications_refused},\"applications_failed\":{applications_failed},\"warnings\":[{warnings_json}],\"removed\":[{}],\"errors\":[{}],\"protected\":[{}],\"apps\":[{}],\"unmatched\":[{}]}}",
        freed,
        esc(&bytes_to_human(freed)),
        moved_to_trash,
        esc(&bytes_to_human(moved_to_trash)),
        removed.join(","),
        errors.join(","),
        protected.join(","),
        apps.join(","),
        unmatched
    );
    Ok((data, i32::from(failed)))
}

/// Record one bundle's fate to the mole history logs, in the shape `mole_delete` writes
/// (`file_ops.sh:491-596`).
///
/// The status vocabulary is the oracle's, and the mapping is its own: `ok` for a removal
/// (`:568`, `:594`), `rejected` for a path a rail declined (`:523` — logged so an audit trail can
/// tell refused-by-policy from never-attempted), `error` for one it tried and could not remove
/// (`:592-593`). A bundle that was already ABSENT is logged NOWHERE, matching `mole_delete`'s
/// `[[ ! -e "$path" && ! -L "$path" ]] && return 0` at `:511-513`, which returns before any log
/// write: nothing was deleted, so there is nothing to record.
///
/// `brew` is a fourth `mode`, alongside the oracle's `trash`/`permanent`. bash never reaches
/// `mole_delete` for a cask and so records nothing at all for the single most destructive thing this
/// command does; a `--zap` has to leave a trace, and it must not claim to be a Trash move, because
/// the `deletions.log` `mode` column is exactly what a reader consults to answer "can I get this
/// back".
pub fn log_bundle_removal(
    log: &crate::history::write::SessionLog,
    mode: crate::clean::execute::RemovalMode,
    target: &crate::uninstall::bundle::BundleTarget,
    state: &crate::uninstall::bundle::BundleState,
) {
    use crate::uninstall::bundle::{BundleState, RemovedVia};
    match state {
        BundleState::Removed { via, bytes } => {
            let mode = match via {
                RemovedVia::Brew => "brew",
                _ => mode.word(),
            };
            log.operation(
                "REMOVED",
                &target.path,
                &crate::clean::format::bytes_to_human(*bytes),
            );
            log.deletion(mode, bytes / 1024, "ok", &target.path);
        }
        BundleState::Refused { reason } => {
            log.operation("SKIPPED", &target.path, reason);
            log.deletion(mode.word(), 0, "rejected", &target.path);
        }
        BundleState::Failed { reason, .. } => {
            log.operation("FAILED", &target.path, reason);
            log.deletion(mode.word(), target.size / 1024, "error", &target.path);
        }
        // Nothing was there and nothing was deleted — `mole_delete` returns before it logs.
        BundleState::Absent => {}
    }
}

/// Remove ONE app's `.app` bundle — the port of `batch.sh:756-838`, which is a three-way branch and
/// not a delete.
///
/// The plain-delete arm goes through `execute_clean` rather than calling `fs::remove_dir_all`
/// directly, and that is the point: the bundle is a path like any other and must pass all three
/// protection rails, including `validate_path_for_deletion`, and must honour the same
/// Trash-or-permanent switch. A private removal path for the one thing in this command that deletes
/// an application is exactly the shape a reviewer should refuse.
///
/// `Removal::Removed` from a remover is not taken at face value: `execute_clean` re-`stat`s and
/// downgrades to `Freed::Unverified` when the path is still there, and that case is reported here as
/// a FAILURE rather than as a removal, because "the Trash move returned zero and the app is still in
/// /Applications" must never render as "removed".
pub fn remove_bundle(
    plan: &crate::uninstall::bundle::Plan,
    permanent: bool,
    run: crate::uninstall::bundle::Runner,
) -> crate::uninstall::bundle::BundleState {
    use crate::clean::protect::ProtectionMode;
    use crate::uninstall::bundle::{BrewOutcome, BundleAction, BundleState, RemovedVia};

    // `mole_delete` returns 0 for a path that is not there (`file_ops.sh:511-513`), so `reason` stays
    // empty and the leftover sweep still runs. Absence is a success, not a failure. FIRST, because
    // that is the order `mole_delete` resolves it in: the `[[ ! -e && ! -L ]]` early return at
    // `:511-513` sits above `validate_path_for_deletion` at `:522`.
    if !plan.bundle.present {
        return BundleState::Absent;
    }

    // **THE REFUSAL THE PREVIEW PUBLISHED, HONOURED BY EVERY ARM.** This used to be checked by
    // exactly one of the two: `Delete` goes through `execute_clean`, which re-runs the rail per item,
    // while `BrewZap` went straight to `brew uninstall --cask --zap <token>`, which checks nothing.
    // So a dry run could report `refusal: "path validation failed…"`, `removes_applications: 0`,
    // `total_bytes: 0` — and the apply would zap the cask anyway, plus everything the zap stanza
    // declares. Measured on a scratch bundle at a control-character path resolving to an installed
    // cask.
    //
    // bash's brew arm skips `validate_path_for_deletion` too, and that RAIL SKIP is faithful — but
    // bash never computes a refusal for that path, so its preview promises nothing and cannot
    // contradict itself. This port added the preview-time refusal; consulting it everywhere is what
    // makes the preview a statement about the apply rather than about one of its branches.
    if let Some(reason) = &plan.bundle.refusal {
        return BundleState::Refused {
            reason: reason.clone(),
        };
    }

    // The plain delete, shared by the `Delete` arm and by brew's one permitted fallback.
    let hand_delete = |fallback_reason: Option<&str>| -> BundleState {
        let outcome = crate::clean::execute::execute_clean(
            &[plan.bundle.candidate()],
            &[],
            permanent,
            ProtectionMode::Uninstall,
        );
        if !outcome.protected.is_empty() {
            return BundleState::Refused {
                reason: plan
                    .bundle
                    .refusal
                    .clone()
                    .unwrap_or_else(|| format!("protected path skipped: {}", plan.bundle.path)),
            };
        }
        if let Some(err) = outcome.errors.first().map(|e| e.error.as_str()) {
            let (reason, suggestion) =
                crate::uninstall::bundle::diagnose(err, plan.bundle.needs_admin);
            return BundleState::Failed {
                reason: fallback_reason.map_or(reason, str::to_string),
                suggestion,
            };
        }
        match outcome.removed.first() {
            // `bytes()` is 0 for `Freed::Unverified`, which is `execute_clean`'s way of saying the
            // remover claimed success and the path is still on disk. That is a failure here.
            Some(item) if item.is_auditable_deletion() => BundleState::Removed {
                via: if permanent {
                    RemovedVia::Permanent
                } else {
                    RemovedVia::Trash
                },
                bytes: item.bytes(),
            },
            Some(_) => BundleState::Failed {
                reason: "removal reported success but the application bundle is still on disk"
                    .to_string(),
                suggestion: None,
            },
            // `execute_clean` drops a candidate that vanished between planning and removal without
            // reporting anything (`execute.rs:234-266`, bash's `[[ -e "$path" ]]` filter). Same
            // answer as the pre-check above: absent, and the leftovers still run.
            None => BundleState::Absent,
        }
    };

    match &plan.bundle.action {
        BundleAction::Delete => hand_delete(None),
        BundleAction::BrewZap(token) => {
            match crate::uninstall::bundle::uninstall_cask(&plan.bundle, token, run) {
                BrewOutcome::Removed { bytes } => BundleState::Removed {
                    via: RemovedVia::Brew,
                    bytes,
                },
                BrewOutcome::Failed { reason, suggestion } => {
                    BundleState::Failed { reason, suggestion }
                }
                // `batch.sh:777-780` — brew has forgotten the cask, so the hand-delete is permitted, and
                // its failure gets the oracle's own wording.
                BrewOutcome::FallBackToDelete => {
                    hand_delete(Some("brew cleanup incomplete, manual removal failed"))
                }
            }
        }
    }
}
