# burrow-engine

The Burrow core — the engine that powers everything Burrow.

```
burrow-engine   this repo: the Rust library where Burrow's real logic lives
   ├── burrow-cli    the CLI that wraps the engine (agents, scripts, CI)
   └── Burrow        the GUIs (macOS, Windows) that wrap the engine
```

This Rust library and binary implement Burrow's command logic and shared JSON contracts.
The historical bash/Go implementation lives in
[`burrow-digger`](https://github.com/caezium/burrow-digger).

Burrow-owned code uses [FSL-1.1-ALv2](LICENSE.md). Adapted upstream portions and build
dependencies retain their own notices in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
This public snapshot uses anonymized contract fixtures; their origin and preserved
invariants are documented in [FIXTURE_PROVENANCE.md](FIXTURE_PROVENANCE.md).

## Design rules

1. **Near-zero dependencies.** Everything that links the engine inherits its dependency tree, so
   the tree is `std` plus two sanctioned, documented exceptions, each justified in `Cargo.toml`
   beside its declaration:
   - `image` (PNG/JPEG decoding, default features off) — `photos` has to decode pixels for its
     perceptual hash, and no subprocess does that cleanly.
   - `windows-sys`, **target-scoped** under `[target.'cfg(windows)'.dependencies]` — `net` on
     Windows attributes connections to processes through IP Helper. A macOS or Linux build
     does not compile or link it.

   Everything else is a subprocess plus a hand-written parser, or a direct `extern "C"` into
   the system library (`geteuid`, `host_processor_info`). Adding a third crate is a design
   decision, not a convenience, and needs the same paragraph in `Cargo.toml`.

2. **Pure first.** Logic lives in pure, unit-tested modules. Anything that spawns a process does
   so through an *injected runner* (`platform::Runner` / `TimedRunner`, `net::Runner`,
   `dupes::FclonesRunner`, `uninstall::bundle::Runner`), so every decision — argv, budgets,
   fallback order, what a failure means — is driven by a fake in tests and the real spawn is one
   thin function. `src/cli.rs` is argv parsing plus the envelope and nothing else; a command's
   orchestration lives in its own module (`uninstall::apply`, `clean::execute`, `purge`, …).
   Process plumbing itself (`run_command*`, `CommandFailure`) is `platform`'s.

3. **Three wire shapes, all defined in this crate.**
   - **The envelope** for every buffered result:
     `{ok, burrow_cli, engine, command, data | error{kind, message}}` (`src/envelope.rs`). One
     contract, defined here and nowhere else.
   - **NDJSON event lines** for `clean --stream` (with or without `--plan`), `purge --stream`, `optimize --stream`,
     `status --watch` and `analyze --progress`: one JSON object per line, flushed as it happens,
     ending in a terminal line. `clean`/`purge` share one vocabulary
     (`would_remove` … `done{dry_run:true,…}`; `removed`/`failed`/`protected` … `done{…}`),
     `optimize` mirrors it (`would_run`/`task` … `done`), `status --watch` emits the buffered
     `data` object per tick, and `analyze --progress` emits `{type:"progress",…}` ticks then
     `{type:"result", data}`. The serializers are pure (`clean::stream`, `optimize`,
     `analyze::json`); `cli.rs` only writes and flushes.
   - **The bare JSON array** of `uninstall --list` — oracle-defined (`bin/uninstall.sh` prints a
     top-level array and the app's `MoleClient.parseApps` decodes exactly that), so it is the one
     command that is *not* enveloped.

   Every hand-written `to_json` escapes strings through the crate's single escaper
   (`json::escape`); field names are checked character by character against the goldens under
   `src/**/*.golden.json`. Their public copies preserve captured structures and safety verdicts
   while replacing private identities, as documented in `FIXTURE_PROVENANCE.md`. Never
   regenerate expected results from the engine under test to make a failing test pass.

   Run `python3 scripts/check_fixtures.py` and `cargo test` to check the published contracts.
   The fixture provenance records the historical reference implementations; tests must preserve
   the established field names, omission behavior and NDJSON event vocabulary.

## `clean --plan <file>`

`clean` scans; `clean --plan <file>` does not. The GUI runs the dry run, shows every candidate,
lets the user untick some, writes what is left to a file, and hands the file to the engine —
so what gets removed is what was reviewed, not what a second scan happens to find.

- `<file>` is UTF-8 text, one absolute path per line; blank lines and `#` comments are ignored.
- The engine removes **only** the listed paths, in file order, each through the same guarded
  remover as `clean --apply` (protection tables, whitelist, `validate_path_for_deletion`,
  Trash or `--permanent`, verified absence). Neither planner runs.
- A listed path is refused unless the clean target table could have enumerated it on this
  machine (component-wise against the same table `clean` scans, resolved against the same
  home): reported as `protected` with reason `not_a_clean_target`. A covered path the planner's
  own rails would have skipped is refused with reason `protected`.
- Without `--apply` (or with `--dry-run`) it is a dry run over the same list with the same
  refusals; `--apply --dry-run` is the usual contradiction. `--stream` emits the same NDJSON
  lines as the scan's stream, with refusals as `{"event":"protected","path":…,"reason":…}`.
- Output is the scan's shape plus
  `"plan": {"file", "listed", "refused", "missing", "refusals": [{"path", "reason"}]}`.
  History and byte accounting are the ones `clean --apply` writes.

## Environment

| Variable | Effect |
|---|---|
| `BURROW_HOME` | The **user's** home, highest precedence over `HOME`/`USERPROFILE`. The app's privileged helper sets it when it launches the engine elevated, because under `sudo` `HOME` is root's and every `~`-relative scan would answer for `/var/root`; a resolved root home *without* it is refused rather than cleaned. |
| `BURROW_PRIVILEGED` | `1` when the privileged helper launched the engine. With it (or an effective uid of 0) helper binaries — `fclones`, `brctl`, `trash`, and the developer tools `clean` may spawn (`uv`, `go`, `pnpm`, `pip3`, …) — are resolved only from trusted locations, never from `PATH`. |
| `BURROW_TOOLS_DIR` | An extra directory helpers may be taken from in privileged mode — honoured only when it lies inside the engine binary's own directory (the app bundle's `Resources/`). |
| `BURROW_WATCH_FRAMES` | Bounds `status --watch` to N frames (tests and scripts); unset means until stdout closes. |

## Reviewed Sweep plans

`purge --plan <file>` and `installer --plan <file>` accept an absolute path per line, with
blank lines and `#` comments ignored. The plan source must be a regular, non-symlink
UTF-8 file no larger than 8 MiB and contain at most 4,096 paths. They preview only the listed candidates; `--apply`
executes the same list. A plan never expands to newly discovered files. Each path must still
match that command's current configured scan roots, depth, classification and protection rules;
symlinked child namespaces and malformed or empty plans are refused. The app additionally pins
reviewed file identities and refuses stale plans before launching the engine.
