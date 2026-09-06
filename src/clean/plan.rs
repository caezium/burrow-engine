//! The clean DRY-RUN planner — decide what *would* be removed, without removing anything.
//!
//! Safety-first port of digger's `safe_clean` gating: a candidate is cleanable only when it exists,
//! is NOT protected by [`super::protect::should_protect_path`] (the unconditional 7-stage filter),
//! and is NOT protected by the whitelist ([`super::whitelist::is_path_whitelisted`]). This module is
//! deliberately non-destructive — it produces the plan (paths + sizes) that a later, separate step
//! would act on. The path/whitelist logic is pure and injectable; existence + sizing is the only IO.

use super::protect::{should_protect_path, ProtectionMode};
use super::whitelist::{glob_match, has_glob, is_path_whitelisted};
use crate::analyze::scanner::dir_size;
use std::collections::HashSet;
use std::path::Path;

/// A clean target: a `~`-relative or absolute PATTERN (may contain `*`/`?`, see [`expand_pattern`])
/// and the human label shown for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanTarget {
    pub path: &'static str,
    pub label: &'static str,
}

/// The universal cache/log targets every Mac has — the safe, high-value core of `clean`. App- and
/// tool-specific targets (Xcode, Homebrew, browsers, …) are additive data layered on later.
///
/// Ported directly against `~/Desktop/burrow-engine/lib/clean/{dev,user}.sh` (read in full for this
/// slice — the two files RULEBOOK-adjacent planning called "the bulk" of the ~130-150-target gap).
/// Three corrections to the PRE-EXISTING 5 entries came out of that read, not just additions — see
/// the doc comments on each for the oracle evidence:
///
/// 1. `~/Library/Caches` and `~/Library/Logs` are now `/*` (children-only), matching
///    `clean_user_essentials` (`user.sh`) exactly — the old whole-directory form deleted the
///    directory itself and any dotfiles inside it, which the oracle never does.
/// 2. `~/Library/Saved Application State` is likewise now `/*`, matching `clean_app_caches`
///    (`user.sh:796`).
/// 3. The bare `~/.cache` ("Unix cache") wholesale target is REMOVED — grepped every one of the 12
///    `lib/clean/*.sh` files and `bin/clean.sh` for any blanket `~/.cache` sweep; there is none. The
///    oracle only ever touches SPECIFIC named subdirectories under `~/.cache` (uv, poetry, ruff,
///    mypy, huggingface, torch, …), each ported below as its own target. The old entry had no oracle
///    backing at all and was strictly WIDER than anything bash does — it could sweep an unrelated
///    tool's cache that bash deliberately never touches. This is the one non-additive change in this
///    slice; flagged prominently for review rather than silently folded in.
///
/// Every `label` is the `description` argument of the `safe_clean` call it ports, copied verbatim.
/// That is a correctness constraint now, not a style one: the label is both the per-item text and the
/// grouping key behind `Categories` (see `render_plan_text`'s `category_count`), so a paraphrase
/// silently splits or merges a category. Three had drifted and are corrected here — `User app cache`
/// (`lib/clean/user.sh:56`, was "User caches"), `User app logs` (`:59`, was "User logs") and
/// `Saved application states` (`:796`, was the singular). All 235 others were diffed against the
/// oracle's description strings and match exactly. The ONE label with no `safe_clean` description to
/// match is `Crash reports`, because bash reaches that directory through `safe_find_delete`
/// (`user.sh:712-715`) instead, preserving its regular-file and age filters as described below.
///
/// CrashReporter is expanded into regular files older than the configured retention period,
/// matching `safe_find_delete`; its directory and recent reports are never deletion candidates.
///
/// What is NOT in this table, and why (full detail in the port report, not restated per-entry
/// here): anything requiring `sudo`/elevation (this `clean` has no elevated code path at all —
/// Xcode's DocumentationCache/system CoreSimulator/simulator-runtime-volume pruning, all of
/// `system.sh`); anything that is a "keep the N most recent, skip the active one" version-pruning
/// family (Xcode DeviceSupport, JetBrains Toolbox, Claude Desktop bundled Claude Code, AI-agent CLI
/// versions, Chrome/Edge/Brave/EdgeUpdater old browser versions) — a different primitive, not a flat
/// target; anything gated on "is this OTHER app currently running" (Firefox, Dropbox, Google Drive,
/// OneDrive, UTM, Antigravity/Gemini, Chrome DevTools MCP, Codex, gradle daemon, and the deeper
/// per-profile Application-Support caches of Chrome/Arc/Brave/Vivaldi/QQ Browser that are skipped
/// specifically while those browsers run) — no process-liveness primitive exists yet, and guessing
/// wrong here risks corrupting a live app's cache, which is worse than not cleaning it; anything
/// needing bundle-ID/app-name cross-referencing against the installed-app inventory (the dynamic
/// `~/Library/Containers/*`, `~/Library/Group Containers/*`, and generic
/// `~/Library/Application Support/*` sweeps) — safety-relevant protection logic (`is_critical_system_
/// component`, `should_protect_data`) that doesn't exist in this engine yet, so globbing those
/// directly would be an unguarded widening; the AI-agent-worktree cleanup (off by default in the
/// oracle too — `MOLE_AGENT_WORKTREES` unset never deletes anything, so skipping it changes nothing
/// for a default run); Finder `.DS_Store` tree cleanup (an unbounded home-wide recursive walk, a
/// distinct feature); incomplete-download cleanup (needs an `lsof`-based "is this file still being
/// written" guard); Mail Downloads and Darwin user runtime/temp cleanup (age-filtered + guarded, not
/// glob-shaped); Spotify cache (has a real offline-music safety check worth preserving exactly, not
/// guessing at); `launch_services.sh` (unregisters LaunchServices DB entries, deletes no files at
/// all — doesn't fit this table's model). Tool-delegated dev caches (corepack, uv, pnpm, bun, go,
/// mise, conda, nix, pip) are NOT here either — they need env-var guards and a "prefer the tool's
/// own cache-clean" preference this static table can't express, so they live in
/// [`super::tool_delegate`] and are merged in at the call site instead.
pub const UNIVERSAL_TARGETS: &[CleanTarget] = &[
    CleanTarget {
        path: "~/Library/Caches/*",
        label: "User app cache",
    },
    CleanTarget {
        path: "~/Library/Logs/*",
        label: "User app logs",
    },
    CleanTarget {
        path: "~/Library/Application Support/CrashReporter",
        label: "Crash reports",
    },
    CleanTarget {
        path: "~/Library/Saved Application State/*",
        label: "Saved application states",
    },
    // -- dev.sh: clean_dev_npm (residual dirs untouched by `npm cache clean --force`, always swept
    // regardless of whether npm itself is installed) + Yarn/tnpm.
    CleanTarget {
        path: "~/.npm/_cacache/*",
        label: "npm cache directory",
    },
    CleanTarget {
        path: "~/.npm/_npx/*",
        label: "npm npx cache",
    },
    CleanTarget {
        path: "~/.npm/_logs/*",
        label: "npm logs",
    },
    CleanTarget {
        path: "~/.npm/_prebuilds/*",
        label: "npm prebuilds",
    },
    CleanTarget {
        path: "~/.tnpm/_cacache/*",
        label: "tnpm cache directory",
    },
    CleanTarget {
        path: "~/.tnpm/_logs/*",
        label: "tnpm logs",
    },
    CleanTarget {
        path: "~/.yarn/cache/*",
        label: "Yarn cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Yarn/*",
        label: "Yarn v1 cache",
    },
    // -- dev.sh: clean_dev_rust / clean_dev_ruby / clean_dev_perl
    CleanTarget {
        path: "~/.cargo/registry/cache/*",
        label: "Rust cargo cache",
    },
    CleanTarget {
        path: "~/.cargo/git/*",
        label: "Cargo git cache",
    },
    CleanTarget {
        path: "~/.rustup/downloads/*",
        label: "Rust downloads cache",
    },
    CleanTarget {
        path: "~/.rbenv/cache/*",
        label: "rbenv download cache",
    },
    CleanTarget {
        path: "~/.gem/specs/*",
        label: "gem spec cache",
    },
    CleanTarget {
        path: "~/.gem/ruby/*/cache/*.gem",
        label: "gem package cache",
    },
    CleanTarget {
        path: "~/.bundle/cache/*",
        label: "Ruby Bundler cache",
    },
    CleanTarget {
        path: "~/.cpan/build/*",
        label: "CPAN build artifacts",
    },
    CleanTarget {
        path: "~/.cpan/sources/*",
        label: "CPAN source cache",
    },
    // -- dev.sh: clean_dev_docker (BuildX only — the daemon-managed store itself is skipped by
    // default in the oracle too) / clean_dev_cloud
    CleanTarget {
        path: "~/.docker/buildx/cache/*",
        label: "Docker BuildX cache",
    },
    CleanTarget {
        path: "~/.kube/cache/*",
        label: "Kubernetes cache",
    },
    CleanTarget {
        path: "~/.local/share/containers/storage/tmp/*",
        label: "Container storage temp",
    },
    CleanTarget {
        path: "~/.aws/cli/cache/*",
        label: "AWS CLI cache",
    },
    CleanTarget {
        path: "~/.config/gcloud/logs/*",
        label: "Google Cloud logs",
    },
    CleanTarget {
        path: "~/.azure/logs/*",
        label: "Azure CLI logs",
    },
    // -- dev.sh: clean_dev_frontend
    CleanTarget {
        path: "~/.cache/typescript/*",
        label: "TypeScript cache",
    },
    CleanTarget {
        path: "~/.cache/electron/*",
        label: "Electron cache",
    },
    CleanTarget {
        path: "~/.cache/node-gyp/*",
        label: "node-gyp cache",
    },
    CleanTarget {
        path: "~/.node-gyp/*",
        label: "node-gyp build cache",
    },
    CleanTarget {
        path: "~/.turbo/cache/*",
        label: "Turbo cache",
    },
    CleanTarget {
        path: "~/.vite/cache/*",
        label: "Vite cache",
    },
    CleanTarget {
        path: "~/.cache/vite/*",
        label: "Vite global cache",
    },
    CleanTarget {
        path: "~/.cache/webpack/*",
        label: "Webpack cache",
    },
    CleanTarget {
        path: "~/.parcel-cache/*",
        label: "Parcel cache",
    },
    CleanTarget {
        path: "~/.cache/eslint/*",
        label: "ESLint cache",
    },
    CleanTarget {
        path: "~/.cache/prettier/*",
        label: "Prettier cache",
    },
    // -- dev.sh: clean_dev_mobile (the non-sudo, non-version-pruned subset — DeviceSupport pruning,
    // the DocumentationCache/system-CoreSimulator/runtime-volume sudo pruning, and XCTestDevices are
    // all excluded per this module's doc comment)
    CleanTarget {
        path: "~/Library/Developer/CoreSimulator/Profiles/Runtimes/*/Contents/Resources/RuntimeRoot/System/Library/Caches/*",
        label: "Simulator runtime cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Google/AndroidStudio*/*",
        label: "Android Studio cache",
    },
    CleanTarget {
        path: "~/.android/build-cache/*",
        label: "Android build cache",
    },
    CleanTarget {
        path: "~/.android/cache/*",
        label: "Android SDK cache",
    },
    CleanTarget {
        path: "~/Library/Developer/Xcode/UserData/IB Support/*",
        label: "Xcode Interface Builder cache",
    },
    CleanTarget {
        path: "~/.cache/swift-package-manager/*",
        label: "Swift package manager cache",
    },
    CleanTarget {
        path: "~/Library/Caches/org.swift.swiftpm/*",
        label: "Swift package manager library cache",
    },
    CleanTarget {
        path: "~/.expo/expo-go/*",
        label: "Expo Go cache",
    },
    CleanTarget {
        path: "~/.expo/android-apk-cache/*",
        label: "Expo Android APK cache",
    },
    CleanTarget {
        path: "~/.expo/ios-simulator-app-cache/*",
        label: "Expo iOS simulator app cache",
    },
    CleanTarget {
        path: "~/.expo/native-modules-cache/*",
        label: "Expo native modules cache",
    },
    CleanTarget {
        path: "~/.expo/schema-cache/*",
        label: "Expo schema cache",
    },
    CleanTarget {
        path: "~/.expo/template-cache/*",
        label: "Expo template cache",
    },
    CleanTarget {
        path: "~/.expo/versions-cache/*",
        label: "Expo versions cache",
    },
    // -- dev.sh: clean_dev_jvm (Maven itself is a separate `maven.sh` module, folded in here as a
    // plain target since it is unconditional and guard-free beyond the whitelist — see maven.sh's
    // own comment that ~/.m2/repository sits in the DEFAULT whitelist, so this target is inert
    // unless a user explicitly un-protects it, exactly matching the oracle's documented behavior).
    // Gradle daemon/workers are excluded (gated on `gradle_daemon_running`, a process-liveness check
    // this port doesn't have yet).
    CleanTarget {
        path: "~/.m2/repository/*",
        label: "Maven local repository",
    },
    CleanTarget {
        path: "~/.sbt/boot/*",
        label: "SBT boot cache",
    },
    CleanTarget {
        path: "~/.sbt/launchers/*",
        label: "SBT launcher cache",
    },
    CleanTarget {
        path: "~/.ivy2/cache/*",
        label: "Ivy cache",
    },
    CleanTarget {
        path: "~/.gradle/caches/build-cache-*/*",
        label: "Gradle build cache",
    },
    CleanTarget {
        path: "~/.gradle/notifications/*",
        label: "Gradle notifications cache",
    },
    // -- dev.sh: clean_dev_other_langs / clean_dev_cicd / clean_dev_database / clean_dev_api_tools
    CleanTarget {
        path: "~/.composer/cache/*",
        label: "PHP Composer cache (legacy)",
    },
    CleanTarget {
        path: "~/Library/Caches/composer/*",
        label: "PHP Composer cache",
    },
    CleanTarget {
        path: "~/.nuget/packages/*",
        label: "NuGet packages cache",
    },
    CleanTarget {
        path: "~/.cache/bazel/*",
        label: "Bazel cache",
    },
    CleanTarget {
        path: "~/.cache/zig/*",
        label: "Zig cache",
    },
    CleanTarget {
        path: "~/Library/Caches/deno/*",
        label: "Deno cache",
    },
    CleanTarget {
        path: "~/.cache/terraform/*",
        label: "Terraform cache",
    },
    CleanTarget {
        path: "~/.grafana/cache/*",
        label: "Grafana cache",
    },
    CleanTarget {
        path: "~/.prometheus/data/wal/*",
        label: "Prometheus WAL cache",
    },
    CleanTarget {
        path: "~/.jenkins/workspace/*/target/*",
        label: "Jenkins workspace cache",
    },
    CleanTarget {
        path: "~/.cache/gitlab-runner/*",
        label: "GitLab Runner cache",
    },
    CleanTarget {
        path: "~/.github/cache/*",
        label: "GitHub Actions cache",
    },
    CleanTarget {
        path: "~/.circleci/cache/*",
        label: "CircleCI cache",
    },
    CleanTarget {
        path: "~/.sonar/*",
        label: "SonarQube cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.sequel-ace.sequel-ace/*",
        label: "Sequel Ace cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.eggerapps.Sequel-Pro/*",
        label: "Sequel Pro cache",
    },
    CleanTarget {
        path: "~/Library/Caches/redis-desktop-manager/*",
        label: "Redis Desktop Manager cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.navicat.*",
        label: "Navicat cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.dbeaver.*",
        label: "DBeaver cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.redis.RedisInsight",
        label: "Redis Insight cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.postmanlabs.mac/*",
        label: "Postman cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.konghq.insomnia/*",
        label: "Insomnia cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.tinyapp.TablePlus/*",
        label: "TablePlus cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.getpaw.Paw/*",
        label: "Paw API cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.charlesproxy.charles/*",
        label: "Charles Proxy cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.proxyman.NSProxy/*",
        label: "Proxyman cache",
    },
    // -- dev.sh: clean_dev_misc (the subset with no process-liveness guard — Codex/Antigravity/Chrome
    // DevTools MCP caches are excluded per this module's doc comment)
    CleanTarget {
        path: "~/Library/Caches/com.unity3d.*/*",
        label: "Unity cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.mongodb.compass/*",
        label: "MongoDB Compass cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.figma.Desktop/*",
        label: "Figma cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.github.GitHubDesktop/*",
        label: "GitHub Desktop cache",
    },
    CleanTarget {
        path: "~/Library/Caches/SentryCrash/*",
        label: "Sentry crash reports",
    },
    CleanTarget {
        path: "~/Library/Caches/KSCrash/*",
        label: "KSCrash reports",
    },
    CleanTarget {
        path: "~/Library/Caches/com.crashlytics.data/*",
        label: "Crashlytics data",
    },
    CleanTarget {
        path: "~/Library/Application Support/Antigravity/Cache/*",
        label: "Antigravity cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Antigravity/Code Cache/*",
        label: "Antigravity code cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Antigravity/GPUCache/*",
        label: "Antigravity GPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Antigravity/DawnGraphiteCache/*",
        label: "Antigravity Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Antigravity/DawnWebGPUCache/*",
        label: "Antigravity WebGPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Filo/production/Cache/*",
        label: "Filo cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Filo/production/Code Cache/*",
        label: "Filo code cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Filo/production/GPUCache/*",
        label: "Filo GPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Filo/production/DawnGraphiteCache/*",
        label: "Filo Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Filo/production/DawnWebGPUCache/*",
        label: "Filo WebGPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/Cache/*",
        label: "Claude cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/Code Cache/*",
        label: "Claude code cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/GPUCache/*",
        label: "Claude GPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/DawnGraphiteCache/*",
        label: "Claude Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/DawnWebGPUCache/*",
        label: "Claude WebGPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/sentry/*",
        label: "Claude sentry cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Claude/pending-uploads/*",
        label: "Claude pending uploads",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/Cache/*",
        label: "Qoder cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/CachedData/*",
        label: "Qoder cached data",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/CachedExtensionVSIXs/*",
        label: "Qoder extension cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/Code Cache/*",
        label: "Qoder code cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/GPUCache/*",
        label: "Qoder GPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/DawnGraphiteCache/*",
        label: "Qoder Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/DawnWebGPUCache/*",
        label: "Qoder WebGPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Qoder/logs/*",
        label: "Qoder logs",
    },
    CleanTarget {
        path: "~/.cache/prisma/*",
        label: "Prisma cache",
    },
    CleanTarget {
        path: "~/.cache/opencode/*",
        label: "OpenCode cache",
    },
    CleanTarget {
        path: "~/.local/share/opencode/snapshot/*",
        label: "OpenCode snapshots",
    },
    CleanTarget {
        path: "~/.local/share/opencode/log/*",
        label: "OpenCode logs",
    },
    CleanTarget {
        path: "~/Library/Caches/ms-playwright/*",
        label: "Playwright browsers",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.wondershare.Installer/*",
        label: "Wondershare installer payload",
    },
    // -- dev.sh: clean_dev_shell
    CleanTarget {
        path: "~/.gitconfig.lock",
        label: "Git config lock",
    },
    CleanTarget {
        path: "~/.gitconfig.bak*",
        label: "Git config backup",
    },
    CleanTarget {
        path: "~/.oh-my-zsh/cache/*",
        label: "Oh My Zsh cache",
    },
    CleanTarget {
        path: "~/.config/fish/fish_history.bak*",
        label: "Fish shell backup",
    },
    CleanTarget {
        path: "~/.bash_history.bak*",
        label: "Bash history backup",
    },
    CleanTarget {
        path: "~/.zsh_history.bak*",
        label: "Zsh history backup",
    },
    CleanTarget {
        path: "~/.cache/pre-commit/*",
        label: "pre-commit cache",
    },
    // -- dev.sh: clean_dev_network
    CleanTarget {
        path: "~/.cache/curl/*",
        label: "curl cache",
    },
    CleanTarget {
        path: "~/.cache/wget/*",
        label: "wget cache",
    },
    CleanTarget {
        path: "~/Library/Caches/curl/*",
        label: "macOS curl cache",
    },
    CleanTarget {
        path: "~/Library/Caches/wget/*",
        label: "macOS wget cache",
    },
    // -- dev.sh: clean_dev_elixir / clean_dev_haskell / clean_dev_ocaml
    CleanTarget {
        path: "~/.hex/cache/*",
        label: "Hex cache",
    },
    CleanTarget {
        path: "~/.cabal/packages/*",
        label: "Cabal install cache",
    },
    CleanTarget {
        path: "~/.opam/download-cache/*",
        label: "Opam cache",
    },
    // -- dev.sh: clean_developer_tools tail (Homebrew's OWN cache dir + lock files — the
    // `brew cleanup`/`brew autoremove` TOOL DELEGATION itself is a separate primitive, not a path,
    // and is not in this port; see the port report)
    CleanTarget {
        path: "~/Library/Caches/Homebrew/*",
        label: "Homebrew cache",
    },
    CleanTarget {
        path: "/opt/homebrew/var/homebrew/locks/*",
        label: "Homebrew lock files",
    },
    CleanTarget {
        path: "/usr/local/var/homebrew/locks/*",
        label: "Homebrew lock files",
    },
    // -- user.sh: clean_user_essentials -> _clean_recent_items (static named files; no glob)
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl2",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentHosts.sfl2",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentHosts.sfl",
        label: "Recent items list",
    },
    CleanTarget {
        path: "~/Library/Preferences/com.apple.recentitems.plist",
        label: "Recent items preferences",
    },
    // -- user.sh: clean_support_app_data (Messages preview/sticker caches only — CrashReporter's
    // age-filtered sweep, the idleassetsd age-filtered sweep and its sudo system-level twin are
    // excluded per this module's doc comment)
    CleanTarget {
        path: "~/Library/Messages/StickerCache/*",
        label: "Messages sticker cache",
    },
    CleanTarget {
        path: "~/Library/Messages/Caches/Previews/Attachments/*",
        label: "Messages preview attachment cache",
    },
    CleanTarget {
        path: "~/Library/Messages/Caches/Previews/StickerCache/*",
        label: "Messages preview sticker cache",
    },
    // -- user.sh: clean_app_caches (macOS system + sandboxed app caches; the dynamic
    // `~/Library/Containers/*` and `~/Library/Group Containers/*` sweeps are excluded — they need
    // the bundle-ID protection primitives this engine doesn't have yet, see the port report)
    CleanTarget {
        path: "~/Library/Caches/com.apple.photoanalysisd",
        label: "Photo analysis cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.akd",
        label: "Apple ID cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.WebKit.Networking/*",
        label: "WebKit network cache",
    },
    CleanTarget {
        path: "~/Library/DiagnosticReports/*",
        label: "Diagnostic reports",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.QuickLook.thumbnailcache",
        label: "QuickLook thumbnails",
    },
    CleanTarget {
        path: "~/Library/Caches/Quick Look/*",
        label: "QuickLook cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.iconservices*",
        label: "Icon services cache",
    },
    CleanTarget {
        path: "~/Library/IdentityCaches/*",
        label: "Identity caches",
    },
    CleanTarget {
        path: "~/Library/Suggestions/*",
        label: "Siri suggestions cache",
    },
    CleanTarget {
        path: "~/Library/Calendars/Calendar Cache",
        label: "Calendar cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/AddressBook/Sources/*/Photos.cache",
        label: "Address Book photo cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.wallpaper.agent/Data/Library/Caches/*",
        label: "Wallpaper agent cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.mediaanalysisd/Data/Library/Caches/*",
        label: "Media analysis cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.mediaanalysisd/Data/tmp/*",
        label: "Media analysis temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.AppStore/Data/Library/Caches/*",
        label: "App Store cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.configurator.xpc.InternetService/Data/tmp/*",
        label: "Apple Configurator temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.wallpaper.extension.aerials/Data/tmp/*",
        label: "Wallpaper aerials temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.geod/Data/tmp/*",
        label: "Geod temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.stocks/Data/Library/Caches/*",
        label: "Stocks cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/com.apple.wallpaper/aerials/thumbnails/*",
        label: "Wallpaper aerials thumbnails",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.helpd/*",
        label: "macOS Help system cache",
    },
    CleanTarget {
        path: "~/Library/Caches/GeoServices/*",
        label: "Maps geo tile cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.AvatarUI.AvatarPickerMemojiPicker/Data/Library/Caches/*",
        label: "Memoji picker cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.AMPArtworkAgent/Data/Library/Caches/*",
        label: "Music album art cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data/Library/Caches/*",
        label: "CoreDevice service cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.NeptuneOneExtension/Data/Library/Caches/*",
        label: "Apple Intelligence extension cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.apple.AppleMediaServicesUI.UtilityExtension/Data/tmp/*",
        label: "Apple Media Services temp files",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.AppleMediaServices/*",
        label: "Apple Media Services cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.duetexpertd/*",
        label: "Duet Expert cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.parsecd/*",
        label: "Parsecd cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.python/*",
        label: "Apple Python cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.e5rt.e5bundlecache/*",
        label: "Apple Intelligence runtime cache",
    },
    // -- user.sh: clean_browsers (unguarded top-level caches only — Firefox is excluded here because
    // the oracle skips it entirely while Firefox is running, and the deeper per-profile
    // Application-Support caches of Chrome/Arc/Brave/Vivaldi/QQ Browser are excluded for the same
    // "skipped while running" reason; Helium/Yandex have no such guard in the oracle and are ported
    // in full)
    CleanTarget {
        path: "~/Library/Caches/com.apple.Safari/*",
        label: "Safari cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Google/Chrome/*",
        label: "Chrome cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Chromium/*",
        label: "Chromium cache",
    },
    CleanTarget {
        path: "~/.cache/puppeteer/*",
        label: "Puppeteer browser cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.microsoft.edgemac/*",
        label: "Edge cache",
    },
    CleanTarget {
        path: "~/Library/Caches/company.thebrowser.Browser/*",
        label: "Arc cache",
    },
    CleanTarget {
        path: "~/Library/Caches/company.thebrowser.dia/*",
        label: "Dia cache",
    },
    CleanTarget {
        path: "~/Library/Caches/BraveSoftware/Brave-Browser/*",
        label: "Brave cache",
    },
    CleanTarget {
        path: "~/Library/Caches/net.imput.helium/*",
        label: "Helium cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/*/GPUCache/*",
        label: "Helium GPU cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/component_crx_cache/*",
        label: "Helium component cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/extensions_crx_cache/*",
        label: "Helium extensions cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/GrShaderCache/*",
        label: "Helium shader cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/GraphiteDawnCache/*",
        label: "Helium Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/ShaderCache/*",
        label: "Helium shader cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/net.imput.helium/*/Application Cache/*",
        label: "Helium app cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Yandex/YandexBrowser/*",
        label: "Yandex cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Yandex/YandexBrowser/ShaderCache/*",
        label: "Yandex shader cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Yandex/YandexBrowser/GrShaderCache/*",
        label: "Yandex GR shader cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Yandex/YandexBrowser/GraphiteDawnCache/*",
        label: "Yandex Dawn cache",
    },
    CleanTarget {
        path: "~/Library/Application Support/Yandex/YandexBrowser/*/GPUCache/*",
        label: "Yandex GPU cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.operasoftware.Opera/*",
        label: "Opera cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.vivaldi.Vivaldi/*",
        label: "Vivaldi cache",
    },
    CleanTarget {
        path: "~/Library/Caches/Comet/*",
        label: "Comet cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.kagi.kagimacOS/*",
        label: "Orion cache",
    },
    CleanTarget {
        path: "~/Library/Caches/zen/*",
        label: "Zen cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.tencent.QQBrowser3/*",
        label: "QQ Browser cache",
    },
    // -- user.sh: clean_cloud_storage (unguarded only — Dropbox/Google Drive/OneDrive are skipped
    // while running in the oracle, excluded here for the same reason as Firefox above)
    CleanTarget {
        path: "~/Library/Caches/com.baidu.netdisk",
        label: "Baidu Netdisk cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.alibaba.teambitiondisk",
        label: "Alibaba Cloud cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.box.desktop",
        label: "Box cache",
    },
    // -- user.sh: clean_office_applications (entirely guard-free in the oracle)
    CleanTarget {
        path: "~/Library/Caches/com.microsoft.Word",
        label: "Microsoft Word cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Word/Data/Library/Caches/*",
        label: "Microsoft Word container cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Word/Data/tmp/*",
        label: "Microsoft Word temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Word/Data/Library/Logs/*",
        label: "Microsoft Word container logs",
    },
    CleanTarget {
        path: "~/Library/Caches/com.microsoft.Excel",
        label: "Microsoft Excel cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Excel/Data/Library/Caches/*",
        label: "Microsoft Excel container cache",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Excel/Data/tmp/*",
        label: "Microsoft Excel temp files",
    },
    CleanTarget {
        path: "~/Library/Containers/com.microsoft.Excel/Data/Library/Logs/*",
        label: "Microsoft Excel container logs",
    },
    CleanTarget {
        path: "~/Library/Caches/com.microsoft.Powerpoint",
        label: "Microsoft PowerPoint cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.microsoft.Outlook/*",
        label: "Microsoft Outlook cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.iWork.*",
        label: "Apple iWork cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.kingsoft.wpsoffice.mac",
        label: "WPS Office cache",
    },
    CleanTarget {
        path: "~/Library/Caches/org.mozilla.thunderbird/*",
        label: "Thunderbird cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.mail/*",
        label: "Apple Mail cache",
    },
    // -- user.sh: clean_virtualization_tools (unguarded only — UTM is skipped while running in the
    // oracle and excluded here for the same reason as Firefox above)
    CleanTarget {
        path: "~/Library/Caches/com.vmware.fusion",
        label: "VMware Fusion cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.parallels.*",
        label: "Parallels cache",
    },
    CleanTarget {
        path: "~/VirtualBox VMs/.cache",
        label: "VirtualBox cache",
    },
    CleanTarget {
        path: "~/Library/Caches/lima/download/by-url-sha256/*",
        label: "Lima download cache",
    },
    CleanTarget {
        path: "~/.vagrant.d/tmp/*",
        label: "Vagrant temporary files",
    },
    // -- user.sh: clean_cached_device_firmware (the 3 shallow `~/Library/iTunes/*` dirs only — the
    // recursive Apple-Configurator-2 group-container variant needs an unbounded-depth walk this
    // single-level glob mechanism doesn't do, and is excluded)
    CleanTarget {
        path: "~/Library/iTunes/iPhone Software Updates/*.ipsw",
        label: "Cached device firmware",
    },
    CleanTarget {
        path: "~/Library/iTunes/iPad Software Updates/*.ipsw",
        label: "Cached device firmware",
    },
    CleanTarget {
        path: "~/Library/iTunes/iPod Software Updates/*.ipsw",
        label: "Cached device firmware",
    },
    // -- user.sh: clean_apple_silicon_caches (no arch check needed — these paths simply don't exist
    // on Intel Macs, so existence-gating alone reproduces the oracle's `IS_M_SERIES` guard)
    CleanTarget {
        path: "/Library/Apple/usr/share/rosetta/rosetta_update_bundle",
        label: "Rosetta 2 cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.rosetta.update",
        label: "Rosetta 2 user cache",
    },
    CleanTarget {
        path: "~/Library/Caches/com.apple.amp.mediasevicesd",
        label: "Apple Silicon media service cache",
    },
];

/// A path in the plan: what would be cleaned, its label, and its size in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanCandidate {
    pub path: String,
    pub label: String,
    pub size: u64,
}

/// Expand a target's leading `~` to `home` (pure). Only a LEADING `~/` or bare `~` is special —
/// every target in this table is either `~`-anchored or already absolute, matching bash's own
/// tilde expansion (the only form `lib/clean/*.sh` ever uses).
fn expand(path: &str, home: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if path == "~" {
        home.to_string()
    } else {
        path.to_string()
    }
}

/// The target whose pattern COVERS `path` — the check `clean --plan` runs on every listed path
/// before it will remove it (see [`super::plan_file`]). A plan file is otherwise an
/// arbitrary-deletion API: whoever can write one line into it can name any path on the disk. So a
/// listed path is accepted only when it lies at or under something this target table could
/// enumerate on this machine — component by component, the same way [`expand_pattern`] walks a
/// pattern, except against the path's own text rather than against real directory entries.
///
/// Derived from the SAME table [`plan_clean`] uses, resolved against the same home, so the set of
/// places a plan may reach is exactly the set of places a scan may reach — and grows and shrinks
/// with the table rather than with a second list that would drift from it. The most specific
/// pattern (most components, then most literal components) wins, because its label is the one the
/// scan would have attached to the same path.
///
/// Textual and pure on purpose: it does not consult the filesystem, so `a/../b` cannot be argued
/// into a root by resolving it — a `..` or `.` component, or a relative path, is simply not a
/// clean target.
pub fn covering_target<'a>(
    path: &str,
    targets: &'a [CleanTarget],
    home: &str,
) -> Option<&'a CleanTarget> {
    targets
        .iter()
        .filter(|t| pattern_covers(&expand(t.path, home), path))
        .max_by_key(|t| {
            let parts = t.path.split('/').filter(|c| !c.is_empty());
            let (mut all, mut literal) = (0usize, 0usize);
            for c in parts {
                all += 1;
                if !has_glob(c) {
                    literal += 1;
                }
            }
            (all, literal)
        })
}

/// Does `path` lie at or under a path `expanded_pattern` could match? Every pattern component must
/// match the corresponding path component — literally, or by glob with bash's no-hidden-match rule
/// (see [`expand_pattern`]) — and the path may then go on for any number of further components,
/// which is what "under" means. `~/Library/Caches/*` covers `~/Library/Caches/foo` and
/// `~/Library/Caches/foo/bar`; it covers neither `~/Library/Caches` itself (the sweep removes
/// children, never the directory) nor `~/Library/Caches/.hidden`.
fn pattern_covers(expanded_pattern: &str, path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let got: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if got.iter().any(|c| *c == "." || *c == "..") {
        return false;
    }
    let pat: Vec<&str> = expanded_pattern
        .split('/')
        .filter(|c| !c.is_empty())
        .collect();
    if pat.is_empty() || got.len() < pat.len() {
        return false;
    }
    pat.iter().zip(&got).all(|(p, g)| {
        if has_glob(p) {
            (p.starts_with('.') || !g.starts_with('.')) && glob_match(p, g)
        } else {
            p == g
        }
    })
}

/// Expand a `~`-relative pattern into every EXISTING concrete filesystem path it matches, mirroring
/// bash's own pathname expansion for a `safe_clean` call: a pattern with no `*`/`?` is a single
/// literal path (unchanged from before this existed); a pattern containing `*`/`?` in one or more
/// path COMPONENTS — `~/Library/Caches/*` ("children of Caches"), `~/Library/Caches/com.foo.*`
/// ("siblings matching a bundle-id prefix"), `~/.gem/ruby/*/cache/*.gem` (two independent glob
/// components) — is expanded one path level at a time against real directory entries.
///
/// Bash's default (`dotglob` unset — verified nowhere set in `lib/clean/*.sh`; the one place that
/// DOES need hidden matches, `cache_top_level_entry_count_capped`, explicitly opts in with
/// `shopt -s nullglob dotglob`, confirming the default everywhere else) never matches a
/// dotfile/hidden entry with `*`/`?` unless the pattern segment ITSELF starts with `.`. This mirrors
/// that per COMPONENT, not just at the leaf.
///
/// Every matched entry is a WHOLE removal target — bash has no separate "children vs whole" concept
/// beyond glob expansion followed by removing each match, so a trailing bare `*` (`dir/*`, "empty
/// dir but keep it") and a mid-path glob (`AndroidStudio*/*`, "clean inside every matching sibling")
/// are the SAME mechanism, not two flags on a target.
///
/// A missing/unreadable directory at any glob component contributes zero matches (fails closed, no
/// panic) — mirroring bash's own `[[ -d ]]`-gated `safe_clean` calls. Matches at each level are
/// sorted for determinism (bash's own order depends on filesystem enumeration + `LC_ALL=C`, which
/// this doesn't try to replicate byte-for-byte — the CONTRACT is the matched SET, and no gate in
/// this migration depends on array order, see RULEBOOK §3d/§6).
pub fn expand_pattern(pattern: &str, home: &str) -> Vec<String> {
    let expanded = expand(pattern, home);
    if !has_glob(&expanded) {
        return vec![expanded];
    }

    let mut bases: Vec<String> = vec![String::new()];
    for part in expanded.split('/') {
        if part.is_empty() {
            continue; // leading '/' or a doubled slash — never a real path component
        }
        if !has_glob(part) {
            for base in bases.iter_mut() {
                base.push('/');
                base.push_str(part);
            }
            continue;
        }
        let wants_dot = part.starts_with('.');
        let mut next = Vec::new();
        for base in &bases {
            let dir = if base.is_empty() { "/" } else { base.as_str() };
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue; // parent doesn't exist / unreadable: this branch matches nothing
            };
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| (wants_dot || !name.starts_with('.')) && glob_match(part, name))
                .collect();
            names.sort();
            for name in names {
                next.push(format!("{base}/{name}"));
            }
        }
        bases = next;
    }
    bases.retain(|p| Path::new(p).exists());
    bases
}

const CRASH_REPORTER_TARGET: &str = "~/Library/Application Support/CrashReporter";

fn expand_clean_target(target: &CleanTarget, home: &str) -> Vec<String> {
    if target.path != CRASH_REPORTER_TARGET {
        return expand_pattern(target.path, home);
    }
    fn walk(path: &Path, found: &mut Vec<String>) {
        let Ok(md) = path.symlink_metadata() else {
            return;
        };
        if md.is_symlink() {
            return;
        }
        if md.is_dir() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    walk(&entry.path(), found);
                }
            }
        } else if let Some(path) = path.to_str() {
            if crash_report_retention_allows(path) {
                found.push(path.to_string());
            }
        }
    }
    let mut found = Vec::new();
    walk(Path::new(&expand(target.path, home)), &mut found);
    found.sort();
    found
}

/// Applies to exact-plan entries too, so a recent report cannot bypass retention by naming it.
pub(crate) fn crash_report_retention_allows(path: &str) -> bool {
    let root = "/Library/Application Support/CrashReporter";
    if !path.ends_with(root) && !path.contains(&format!("{root}/")) {
        return true;
    }
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    let days = std::env::var("MOLE_SUPPORT_CACHE_AGE_DAYS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    // find -mtime +N compares complete 24-hour periods and requires strictly more than N.
    md.modified()
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|elapsed| elapsed.as_secs() / 86_400 > days)
}

/// The expanded, unprotected target paths — the pure-of-DELETION heart of the planner (its only IO
/// is [`expand_pattern`]'s read-only directory listing for glob targets — never a write), so the
/// safety gating is unit-testable. One [`CleanTarget`] can expand to zero, one, or many candidates.
///
/// Both of `safe_clean`'s filters live here, in the order bash applies them (`bin/clean.sh:600-612`:
/// `should_protect_path` first, then `is_path_whitelisted`), and this is the ONLY place they are
/// applied to static targets — deliberately, because the alternative does not work. The defect this
/// fixes was 27 individual targets planning paths the oracle never deletes, but ALSO the coarse
/// sweeps: `~/Library/Caches/*` expands to 132 children on the machine this was measured on, 116 of
/// which the oracle protects, and no edit to any target list can express that. One filter over every
/// expanded candidate fixes both at once and cannot be missed by the 245th target somebody adds
/// next week.
///
/// Order note: the protection filter runs BEFORE [`plan_clean`] sizes anything, so a protected path
/// is never walked by `dir_size` either — the same reason bash checks before it stats.
pub fn cleanable_paths(
    targets: &[CleanTarget],
    home: &str,
    whitelist: &[&str],
) -> Vec<(String, String)> {
    targets
        .iter()
        .flat_map(|t| {
            expand_clean_target(t, home)
                .into_iter()
                .map(move |path| (path, t.label.to_string()))
        })
        .filter(|(path, _)| {
            // `bin/clean.sh` never exports `MOLE_UNINSTALL_MODE`, so the planner for `clean` is
            // always the cleanup regime. Stated explicitly rather than defaulted — see
            // [`super::protect::ProtectionMode`].
            !should_protect_path(path, ProtectionMode::Cleanup)
                && !is_path_whitelisted(path, whitelist)
        })
        .collect()
}

/// `Some(size in bytes)` when `path` exists (directory sizes via [`dir_size`], files via their raw
/// length), `None` when it doesn't. Factored out of [`plan_clean`] so [`super::tool_delegate`] can
/// size a resolved tool-cache path with the exact same rule, instead of re-deriving it.
pub(crate) fn size_if_exists(path: &str) -> Option<u64> {
    let p = Path::new(path);
    // `[[ -e "$path" ]]` (`bin/clean.sh:614`) — resolves through symlinks, so a DANGLING link is
    // not a candidate at all, in bash or here.
    if !p.exists() {
        return None;
    }
    // A SYMLINK is measured as itself, never as what it points at. `get_cleanup_path_size_kb`
    // (`bin/clean.sh:471-491`) tests `-L` FIRST and answers with `stat -f%z`, which on macOS is
    // `lstat` (the `stat` command follows only with `-L`), i.e. the length of the stored target
    // path — a few dozen bytes. Its own comment says so: "a symlink reports 0 directly". The
    // batch-sizing path agrees, gating `du` on `[[ -d "$path" && ! -L "$path" ]]` (`:721`).
    //
    // This is load-bearing and not a rounding detail. `rm -rf` on a symlink unlinks the LINK; the
    // target keeps its bytes. Sizing through the link (`Path::is_dir` follows) billed a user the
    // full weight of a cache directory that is still sitting on disk — and a `~/Library/Caches`
    // entry symlinked to an external disk is an ordinary setup, not a contrived one.
    let meta = std::fs::symlink_metadata(p).ok()?;
    if meta.file_type().is_symlink() {
        return Some(meta.len());
    }
    Some(if meta.is_dir() {
        dir_size(p) as u64
    } else {
        meta.len()
    })
}

/// Port of `mole_normalize_path` (`lib/core/common.sh:35-39`), verbatim including its one odd edge:
/// `"${path%/}"` strips exactly ONE trailing slash, and when that leaves the string EMPTY (the path
/// was `/`, or was already empty) the ORIGINAL is returned instead. So `/a/` → `/a`, `/a//` → `/a/`
/// (one slash, not all of them), `/` → `/`. Not a general normalizer, and deliberately not made into
/// one — it is one half of an identity function whose other half is the filesystem.
fn normalize_path(path: &str) -> &str {
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    if trimmed.is_empty() {
        path
    } else {
        trimmed
    }
}

/// What `mole_path_identity` returns: device+inode when the filesystem could answer, the normalized
/// path string when it could not. Both arms are compared for equality, exactly as bash compares the
/// `inode:%d:%i` / `path:%s` strings it prints — the prefix in bash exists so an inode identity can
/// never collide with a path identity, which the two variants give for free here.
///
/// `Inode` is unix-only, and its absence elsewhere is the honest shape rather than a convenience:
/// `dev`/`ino` come from `stat(2)`, and the Windows equivalent (volume serial + file index) is
/// still behind the unstable `windows_by_handle` feature, so there is no stable-Rust way to answer
/// the same question. See [`path_identity`] for what the fallback costs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PathIdentity {
    #[cfg(unix)]
    Inode {
        dev: u64,
        ino: u64,
    },
    Path(String),
}

/// Port of `mole_path_identity` (`lib/core/common.sh:43-60`):
///
/// ```text
/// mole_path_identity() {
///     normalized=$(mole_normalize_path "$path")
///     if [[ -e "$normalized" || -L "$normalized" ]]; then
///         if command -v stat …; then
///             fs_id=$(stat -L -f '%d:%i' "$normalized" 2>/dev/null || stat -f '%d:%i' … || true)
///             if [[ "$fs_id" =~ ^[0-9]+:[0-9]+$ ]]; then printf 'inode:%s\n' "$fs_id"; return 0; fi
///         fi
///     fi
///     printf 'path:%s\n' "$normalized"
/// }
/// ```
///
/// Three details that are the whole point of porting it rather than writing "dedupe by path":
///
/// 1. `-e || -L` means a path that exists OR is a symlink (including a BROKEN one, which fails `-e`)
///    gets asked for an inode. `symlink_metadata().is_ok()` is exactly that test — `lstat` succeeds
///    for any directory entry that is there at all.
/// 2. `stat -L` FOLLOWS the symlink, with a plain `stat` fallback for when following fails (a broken
///    link). So two names for the same bytes — a symlink and its target, `//`, a trailing slash, a
///    case-variant on a case-insensitive volume — collapse to ONE identity, and a dangling symlink
///    still gets its own. That is `fs::metadata` then `fs::symlink_metadata`, in that order.
/// 3. When `stat` cannot answer at all the identity DEGRADES to the normalized path string rather
///    than failing or being treated as "same as everything else". A path that does not exist takes
///    this arm too — which never matters for `clean` because bash registers a target only after
///    `[[ -e "$path" ]]` passes (`bin/clean.sh:614`), and this port only calls it after
///    [`size_if_exists`] has done the same.
///
/// OFF UNIX (Windows, and the Linux CI leg is unaffected since it *is* unix) every path takes arm 3
/// — the `path:` fallback — because there is no `stat`-equivalent identity to ask for. This is not a
/// `cfg` that invents an answer: it is precisely the branch bash itself takes when `command -v stat`
/// fails, so the degraded behaviour is the oracle's own, not something new. What it costs is
/// specific and worth stating: two spellings of the same bytes (a symlink and its target, a doubled
/// slash, a case-variant on a case-insensitive volume) no longer collapse, so `total_bytes` can
/// double-count a directory reachable by two names. That errs toward reporting MORE than will be
/// freed, never toward dropping a real target, which is the same direction bash's own fallback errs
/// in. Nothing here is silently different: the identity is still computed, still deduped, and still
/// keyed on the same normalized string bash prints.
fn path_identity(path: &str) -> PathIdentity {
    let normalized = normalize_path(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let p = Path::new(normalized);
        if p.symlink_metadata().is_ok() {
            if let Ok(md) = std::fs::metadata(p) {
                return PathIdentity::Inode {
                    dev: md.dev(),
                    ino: md.ino(),
                };
            }
            if let Ok(md) = p.symlink_metadata() {
                return PathIdentity::Inode {
                    dev: md.dev(),
                    ino: md.ino(),
                };
            }
        }
    }
    PathIdentity::Path(normalized.to_string())
}

/// Port of `register_dry_run_cleanup_target` (`bin/clean.sh:163-174`) as a whole-list operation:
///
/// ```text
/// register_dry_run_cleanup_target() {
///     identity=$(mole_path_identity "$path")
///     if … mole_identity_in_list "$identity" "${DRY_RUN_SEEN_IDENTITIES[@]}"; then return 1; fi
///     DRY_RUN_SEEN_IDENTITIES+=("$identity"); return 0
/// }
/// ```
///
/// called as `register_dry_run_cleanup_target "$path" || continue` (`bin/clean.sh:616`) — so the
/// FIRST candidate for an identity is kept and every later one is dropped, and `DRY_RUN_SEEN_IDENTITIES`
/// is a script-global reset once per run (`:975`), not per `safe_clean` call. This keeps that: first
/// wins, order otherwise preserved, and the scope is the whole candidate list rather than one target's
/// expansion.
///
/// Why it exists: `~/Library/Caches/*` sweeps every child of `~/Library/Caches`, and 72 further
/// targets name paths inside that same directory — 14 of them whole directories that the sweep already
/// produced byte-for-byte. Without this the same inode is measured twice and `total_bytes` reports
/// bytes that will only ever be freed once. Keyed on IDENTITY and not on the path string because two
/// spellings can be the same bytes (a symlink, a doubled slash, a trailing slash, a case-variant on
/// APFS-insensitive) and a string compare misses every one of them.
///
/// What it deliberately does NOT collapse, because bash does not either: CONTAINMENT. `~/Library/Caches/foo`
/// and `~/Library/Caches/foo/bar` are different inodes, so both survive here and the child's bytes are
/// counted inside the parent's total as well. bash's own containment collapse lives in
/// `normalize_paths_for_cleanup` (`bin/clean.sh:327`), which runs on ONE `safe_clean` call's argument
/// list — never across calls — and this planner has no per-call grouping to hang it on.
pub fn dedupe_by_identity(plan: Vec<CleanCandidate>) -> Vec<CleanCandidate> {
    let mut seen: HashSet<PathIdentity> = HashSet::with_capacity(plan.len());
    plan.into_iter()
        .filter(|c| seen.insert(path_identity(&c.path)))
        .collect()
}

/// Which half of `bin/clean.sh` the caller is running. This is not a reporting preference — it
/// decides whether the identity registry above runs at all, and the oracle fences it behind
/// `DRY_RUN`:
///
/// ```text
/// if [[ -e "$path" ]]; then
///     if [[ "$DRY_RUN" == "true" ]]; then
///         register_dry_run_cleanup_target "$path" || continue
///     fi
///     existing_paths+=("$path")
/// fi
/// ```
///
/// — `bin/clean.sh:614-618`, and `lib/clean/caches.sh:404-408` repeats it verbatim. Those are the
/// only two call sites of `register_dry_run_cleanup_target` in the tree, so a real `mo clean` run
/// has NO registry: every aliased spelling of a path reaches `safe_remove` and is deleted. The only
/// filter a real run applies is `normalize_paths_for_cleanup` (`bin/clean.sh:327`), which compares
/// strings and path prefixes, so two names for one inode both survive it.
///
/// Why the difference has teeth rather than being a cosmetic mismatch. Dropping a candidate from a
/// REPORT loses a line; dropping it from the destructive path leaves bytes on disk that the run then
/// bills the user for, because deleting the survivor does not always free the identity's bytes:
///
/// - **A symlink and its target.** Both resolve to one inode, so first-wins keeps whichever the
///   target table names first. If that is the LINK, `rm -rf`/`remove_dir_all` unlinks the link and
///   the target's bytes stay — and the target, having been deduped away, is not a candidate on this
///   run or on any later run of the same plan.
/// - **A hardlink pair.** Same inode, two directory entries. Unlinking one frees nothing while the
///   other still references it; bash deletes both and the bytes actually go.
///
/// So the dedup belongs to the dry run only, exactly where bash puts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanMode {
    /// Reporting only, nothing is deleted — `register_dry_run_cleanup_target` is live.
    DryRun,
    /// `--apply`: the list is about to be handed to the executor — no registry, like bash.
    Apply,
}

/// [`dedupe_by_identity`] under the `DRY_RUN` fence quoted on [`PlanMode`] — the single place that
/// decision is made, so a caller states its mode instead of a planner guessing.
///
/// Callers apply this to the list they are actually about to use. `src/cli.rs` merges
/// [`plan_clean`]'s output with `tool_delegate::resolve_candidates`' before anything consumes it,
/// and bash's registry is a whole-RUN global (`DRY_RUN_SEEN_IDENTITIES`, reset once at
/// `bin/clean.sh:975`) rather than a per-planner one, so the merged list is the right scope.
pub fn dedupe_for(plan: Vec<CleanCandidate>, mode: PlanMode) -> Vec<CleanCandidate> {
    match mode {
        PlanMode::DryRun => dedupe_by_identity(plan),
        PlanMode::Apply => plan,
    }
}

/// Build the plan: every cleanable target that actually exists, with its size. Purely reports —
/// deletes nothing. Non-existent targets are skipped; empty when nothing is cleanable.
///
/// `mode` decides whether identity-deduping runs, and it must match what the caller is about to do
/// with the list — see [`PlanMode`] for the `DRY_RUN` fence this ports and for why handing a deduped
/// list to the EXECUTOR strands bytes on disk. In [`PlanMode::DryRun`] each distinct set of bytes
/// appears once; in [`PlanMode::Apply`] every spelling the target table produces is kept, exactly as
/// a real `mo clean` run keeps them.
///
/// The dedup runs AFTER the existence filter, which is where bash puts it too: `safe_clean` calls
/// `register_dry_run_cleanup_target` inside the `if [[ -e "$path" ]]` arm (`bin/clean.sh:614-618`),
/// so a path that is not there registers nothing and cannot shadow a real candidate later.
///
/// Deduping here as well as at the merge point is deliberate redundancy, not a leftover: this
/// function is a complete plan for a caller that has nothing to merge, and the cost of the second
/// pass over an already-clean list is one `stat` per candidate.
pub fn plan_clean(
    targets: &[CleanTarget],
    home: &str,
    whitelist: &[&str],
    mode: PlanMode,
) -> Vec<CleanCandidate> {
    dedupe_for(
        cleanable_paths(targets, home, whitelist)
            .into_iter()
            .filter_map(|(path, label)| {
                let size = size_if_exists(&path)?;
                Some(CleanCandidate { path, label, size })
            })
            .collect(),
        mode,
    )
}

use crate::json::escape as esc;

const RULE: &str = "======================================================================";

/// Human-readable report text alongside the structured fields (contract-conformance: see
/// `crate::purge::render_dry_run_text`'s doc for why this exists). Unlike purge's summary line,
/// this ONE matters to the real parser: `bin/clean.sh`'s dry-run summary is `Potential space: …
/// | Items: … | Categories: …`, and `mergeSummaryFields` in the app's `TaskReport.swift`
/// (origin/main) keys on the literal phrase "potential space" — verified by running the
/// `clean.golden.json` capture through the real, unmodified parser (Gate 1 harness): it returns
/// `space="585.5MB" items="647" categories="27"`, i.e. `sawSummary=true`. So the wording here is
/// not decorative — match it exactly or the MCP `summary` field and the GUI report card stay
/// empty exactly like the bug this migration exists to fix.
///
/// `Items` and `Categories` are two DIFFERENT counters in the shipping script and this prints them
/// as such. `files_cleaned` (Items) accumulates `total_count`, one per individual path a `safe_clean`
/// call handled (`bin/clean.sh:962`); `total_items` (Categories) accumulates `+ 1` per `safe_clean`
/// CALL that removed anything (`:964`). That is why the capture reads 647 items / 27 categories and
/// not 647/647 — 27 calls covered 647 paths. Printing `plan.len()` for both was a straight
/// mis-port, unrelated to the double-counting [`dedupe_by_identity`] fixes.
///
/// The grouping key here is the candidate's LABEL, because the label IS the `description` argument
/// each `safe_clean` call passes. One residual, stated rather than hidden: bash counts CALLS, so two
/// calls sharing a description count twice, while this counts the description once. The target table
/// has 238 entries and 227 distinct labels, so the ceiling on that gap is 11 — against the 410 the
/// old one-per-item form was out by.
fn category_count(plan: &[CleanCandidate]) -> usize {
    plan.iter()
        .map(|c| c.label.as_str())
        .collect::<HashSet<_>>()
        .len()
}

fn render_plan_text(plan: &[CleanCandidate], total: u64) -> String {
    let mut out = String::new();
    out.push_str("Clean Your Mac\n\n");
    out.push_str("Dry Run Mode, Preview only, no deletions\n\n");
    if plan.is_empty() {
        out.push_str("Nothing to clean.\n");
    } else {
        out.push_str("➤ Cleanup\n");
        for c in plan {
            out.push_str(&format!(
                "  → {}, {} dry\n",
                c.label,
                super::format::bytes_to_human(c.size)
            ));
        }
    }
    out.push('\n');
    out.push_str(RULE);
    out.push('\n');
    out.push_str("Dry run complete - no changes made\n");
    if total > 0 {
        out.push_str(&format!(
            "Potential space: {} | Items: {} | Categories: {}\n",
            super::format::bytes_to_human(total),
            plan.len(),
            category_count(plan)
        ));
        out.push_str("Use mo clean --whitelist to add protection rules\n");
    } else {
        out.push_str("Nothing to clean.\n");
    }
    out.push_str(RULE);
    out
}

/// Serialize a dry-run plan to JSON (zero-dep):
/// `{dry_run:true, total_bytes, total_human, items:[…], text:S}`.
/// `dry_run` is always true here — this module never deletes. `text` is additive — every
/// prior field is untouched — see [`render_plan_text`].
///
/// [`dedupe_by_identity`] runs unconditionally here, over whatever list it is handed. That is safe
/// precisely because this function is dry-run-only — it hard-codes `"dry_run":true` and this module
/// never deletes — so it is on the side of the [`PlanMode`] fence where bash's registry is live.
/// Nothing on the destructive path may call it.
///
/// It runs here even though callers dedupe too, because this is the single point every buffered dry
/// run passes through and the headline `total_bytes` must not double-count whoever assembled the
/// list. The overlap is real: `src/cli.rs` MERGES [`plan_clean`]'s output with a second planner's
/// (`tool_delegate::resolve_candidates`), and `~/Library/Caches/go-build` is both a child of the
/// `~/Library/Caches/*` sweep and a resolved go target. The operation is idempotent, so a second
/// pass over an already-clean list costs one `stat` per candidate and changes nothing.
pub fn plan_to_json(plan: &[CleanCandidate]) -> String {
    exact_plan_to_json(&dedupe_by_identity(plan.to_vec()))
}

/// An exact file lists every path that apply will consider, including distinct hard-link names.
/// Its buffered review must preserve those same entries as the streamed review.
pub(crate) fn exact_plan_to_json(plan: &[CleanCandidate]) -> String {
    let total: u64 = plan.iter().map(|c| c.size).sum();
    let items = plan
        .iter()
        .map(|c| {
            format!(
                "{{\"path\":{},\"label\":{},\"size\":{},\"size_human\":{}}}",
                esc(&c.path),
                esc(&c.label),
                c.size,
                esc(&super::format::bytes_to_human(c.size))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let text = render_plan_text(plan, total);
    format!(
        "{{\"dry_run\":true,\"total_bytes\":{},\"total_human\":{},\"items\":[{}],\"text\":{}}}",
        total,
        esc(&super::format::bytes_to_human(total)),
        items,
        esc(&text)
    )
}

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
    use crate::json::Json;
    use std::fs;

    #[test]
    fn expands_tilde_to_home() {
        assert_eq!(
            expand("~/Library/Caches", "/Users/me"),
            "/Users/me/Library/Caches"
        );
        assert_eq!(expand("~", "/Users/me"), "/Users/me");
        assert_eq!(expand("/abs/path", "/Users/me"), "/abs/path");
    }

    #[test]
    fn no_clean_target_uses_a_glob_where_chars_and_bytes_disagree() {
        // The precondition that keeps `whitelist::glob_match`'s one deliberate divergence on the
        // safe side of the line. Under `LC_ALL=C` bash 3.2 matches BYTES, so `[[ é == ? ]]` is false
        // and `[[ é == [é] ]]` is false; this engine matches `char`s and answers true to both. That
        // makes it match MORE than bash on any non-ASCII path — which is extra PROTECTION at
        // `is_path_whitelisted` and `should_protect_path`, and extra DELETION here, where a matched
        // directory entry is a removal candidate. `*` and plain literals behave identically either
        // way, so the divergence is unreachable from this table as long as no target uses `?` or a
        // bracket. Adding one is not forbidden — it just has to come with a byte-oriented matcher,
        // and this fails rather than letting it land quietly.
        for t in UNIVERSAL_TARGETS {
            assert!(
                !t.path.contains('?') && !t.path.contains('['),
                "{:?} needs a matcher that counts bytes, not chars — see whitelist.rs's header",
                t.path
            );
        }
    }

    // -- expand_pattern: real scratch fixtures throughout, per RULEBOOK's "test destructive
    // behaviour against throwaway fixtures under a scratch HOME" — no hand-typed shape, every
    // assertion is checked against files this test itself created.

    fn glob_scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "burrow_expand_pattern_{}_{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn literal_pattern_with_no_glob_chars_is_a_single_path_regardless_of_existence() {
        // Matches `expand`'s old contract exactly — a plain target still degrades to "does it
        // exist" at plan time, not here.
        assert_eq!(
            expand_pattern("~/Library/Caches/CrashReporter", "/Users/me"),
            vec!["/Users/me/Library/Caches/CrashReporter".to_string()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn trailing_star_expands_to_non_hidden_children_only() {
        let home = glob_scratch("children");
        let dir = home.join("Library/Caches");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("visible_a"), b"a").unwrap();
        fs::write(dir.join("visible_b"), b"b").unwrap();
        fs::write(dir.join(".hidden"), b"h").unwrap(); // must survive — no dotglob

        let home_str = home.to_str().unwrap();
        let mut got = expand_pattern("~/Library/Caches/*", home_str);
        got.sort();
        assert_eq!(
            got,
            vec![
                format!("{home_str}/Library/Caches/visible_a"),
                format!("{home_str}/Library/Caches/visible_b"),
            ],
            "a bare trailing '*' must never match a dotfile — bash's own default (no dotglob)"
        );
        // The directory itself is never a match of its own children-glob.
        assert!(!got
            .iter()
            .any(|p| p == &format!("{home_str}/Library/Caches")));
    }

    #[cfg(unix)]
    #[test]
    fn mid_path_glob_matches_sibling_directories_and_still_expands_the_tail() {
        // Mirrors real targets like `~/Library/Caches/com.unity3d.*/*` and
        // `~/Library/Caches/Google/AndroidStudio*/*`.
        let home = glob_scratch("mid_glob");
        let a = home.join("Library/Caches/com.example.foo");
        let b = home.join("Library/Caches/com.example.bar");
        let unrelated = home.join("Library/Caches/org.other.thing");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        fs::create_dir_all(&unrelated).unwrap();
        fs::write(a.join("data"), b"a").unwrap();
        fs::write(b.join("data"), b"b").unwrap();
        fs::write(unrelated.join("data"), b"x").unwrap();

        let home_str = home.to_str().unwrap();
        let mut got = expand_pattern("~/Library/Caches/com.example.*/data", home_str);
        got.sort();
        assert_eq!(
            got,
            vec![
                format!("{home_str}/Library/Caches/com.example.bar/data"),
                format!("{home_str}/Library/Caches/com.example.foo/data"),
            ],
            "the mid-path glob must match only its own siblings, and the literal tail must still \
             be appended per match: {got:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn two_independent_glob_components_both_expand() {
        // Mirrors `~/.gem/ruby/*/cache/*.gem`.
        let home = glob_scratch("double_glob");
        let v1 = home.join(".gem/ruby/3.2.0/cache");
        let v2 = home.join(".gem/ruby/3.3.0/cache");
        fs::create_dir_all(&v1).unwrap();
        fs::create_dir_all(&v2).unwrap();
        fs::write(v1.join("foo-1.0.gem"), b"x").unwrap();
        fs::write(v1.join("readme.txt"), b"not a gem").unwrap();
        fs::write(v2.join("bar-2.0.gem"), b"y").unwrap();

        let home_str = home.to_str().unwrap();
        let mut got = expand_pattern("~/.gem/ruby/*/cache/*.gem", home_str);
        got.sort();
        assert_eq!(
            got,
            vec![
                format!("{home_str}/.gem/ruby/3.2.0/cache/foo-1.0.gem"),
                format!("{home_str}/.gem/ruby/3.3.0/cache/bar-2.0.gem"),
            ],
            "readme.txt must not match the *.gem leaf glob: {got:?}"
        );
    }

    #[test]
    fn a_missing_parent_directory_contributes_no_matches_and_never_panics() {
        let home = glob_scratch("missing_parent");
        let home_str = home.to_str().unwrap();
        // Nothing under Library/Caches exists at all.
        assert!(expand_pattern("~/Library/Caches/*", home_str).is_empty());
        assert!(expand_pattern("~/Library/Caches/com.foo.*/data", home_str).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_pattern_segment_that_itself_starts_with_a_dot_does_match_dotfiles() {
        // e.g. `~/.gitconfig.bak*` — the glob char is on a segment that ALREADY starts with '.',
        // so it must match dotfile siblings, unlike a bare unqualified '*'.
        let home = glob_scratch("dot_prefixed_glob");
        fs::write(home.join(".gitconfig.bak"), b"1").unwrap();
        fs::write(home.join(".gitconfig.bak.1"), b"2").unwrap();
        fs::write(home.join(".gitconfig"), b"kept").unwrap(); // must NOT match

        let home_str = home.to_str().unwrap();
        let mut got = expand_pattern("~/.gitconfig.bak*", home_str);
        got.sort();
        assert_eq!(
            got,
            vec![
                format!("{home_str}/.gitconfig.bak"),
                format!("{home_str}/.gitconfig.bak.1"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn glob_matches_are_whitelist_checked_individually_through_cleanable_paths() {
        // Proves expand_pattern's multi-match output composes correctly with the EXISTING
        // whitelist filter — each expanded match is checked on its own, not the pattern as a whole.
        let home = glob_scratch("glob_whitelist");
        let dir = home.join("Library/Caches");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("keep_me"), b"1").unwrap();
        fs::write(dir.join("clean_me"), b"2").unwrap();

        let home_str = home.to_str().unwrap();
        let targets = &[CleanTarget {
            path: "~/Library/Caches/*",
            label: "caches",
        }];
        let protect = format!("{home_str}/Library/Caches/keep_me");
        let out = cleanable_paths(targets, home_str, &[protect.as_str()]);
        let paths: Vec<&str> = out.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&format!("{home_str}/Library/Caches/clean_me").as_str()));
        assert!(!paths.contains(&format!("{home_str}/Library/Caches/keep_me").as_str()));
    }

    #[test]
    fn whitelisted_targets_are_dropped_before_the_plan() {
        let targets = &[
            CleanTarget {
                path: "~/Library/Caches",
                label: "caches",
            },
            CleanTarget {
                path: "~/Library/Logs",
                label: "logs",
            },
        ];
        // The user protects their Caches → only Logs remains cleanable.
        let out = cleanable_paths(targets, "/Users/me", &["/Users/me/Library/Caches"]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "/Users/me/Library/Logs");
        // Protecting a child (ancestor rule) also drops the parent target.
        let out2 = cleanable_paths(targets, "/Users/me", &["/Users/me/Library/Logs/keep.log"]);
        assert!(out2.iter().all(|(p, _)| p != "/Users/me/Library/Logs"));
    }

    #[test]
    fn plan_reports_existing_targets_with_sizes_and_deletes_nothing() {
        let home = std::env::temp_dir().join(format!("burrow_clean_plan_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let caches = home.join("Library/Caches");
        fs::create_dir_all(&caches).unwrap();
        fs::write(caches.join("blob.bin"), vec![b'x'; 4096]).unwrap();
        // "~/Library/Logs" is NOT created → must be skipped (non-existent).

        let targets = &[
            CleanTarget {
                path: "~/Library/Caches",
                label: "caches",
            },
            CleanTarget {
                path: "~/Library/Logs",
                label: "logs",
            },
        ];
        let plan = plan_clean(targets, home.to_str().unwrap(), &[], PlanMode::DryRun);
        assert_eq!(plan.len(), 1, "only the existing target is planned");
        assert_eq!(plan[0].label, "caches");
        assert!(plan[0].size >= 4096);
        // The planner is non-destructive — the target still exists afterwards.
        assert!(
            caches.join("blob.bin").exists(),
            "plan_clean must not delete anything"
        );
        let _ = fs::remove_dir_all(&home);
    }

    /// Sum every regular file under `root` — what the filesystem says is really there, which is the
    /// only honest yardstick for a number the user reads as "you will get this back".
    #[cfg(unix)]
    fn bytes_on_disk(root: &Path) -> u64 {
        let mut total = 0;
        let Ok(entries) = fs::read_dir(root) else {
            return 0;
        };
        for e in entries.flatten() {
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            if md.is_dir() {
                total += bytes_on_disk(&e.path());
            } else if md.is_file() {
                total += md.len();
            }
        }
        total
    }

    /// The real target table's own entries under `~/Library/Caches` — the coarse children sweep plus
    /// every specific sub-path, taken from [`UNIVERSAL_TARGETS`] at run time rather than retyped, so
    /// the fixture below keeps testing the overlap that actually ships even after somebody adds the
    /// 239th target.
    #[cfg(unix)]
    fn caches_targets() -> Vec<CleanTarget> {
        UNIVERSAL_TARGETS
            .iter()
            .filter(|t| t.path.starts_with("~/Library/Caches"))
            .cloned()
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn the_reported_total_equals_the_bytes_actually_on_disk_when_two_targets_name_one_directory() {
        // THE LOAD-BEARING TEST for double counting. The table pairs a coarse `~/Library/Caches/*`
        // sweep with 72 specific sub-paths in the same directory, 14 of them whole directories the
        // sweep already produced byte-for-byte. Every one of those pairs used to be added twice.
        //
        // Nothing about the expected number is written down here: the fixture is built from the
        // shipping table's own whole-directory entries, and the expectation is measured off the
        // filesystem afterwards by `bytes_on_disk`. If a target is renamed or the protection rails
        // change which entries survive, this still measures the right thing.
        let home =
            std::env::temp_dir().join(format!("burrow_clean_overlap_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let caches = home.join("Library/Caches");
        fs::create_dir_all(&caches).unwrap();

        let targets = caches_targets();
        // Materialize every whole-directory sub-target. Each is ALSO a child of `~/Library/Caches`,
        // so `~/Library/Caches/*` names it too — one directory, two candidates.
        let mut planted = Vec::new();
        for t in &targets {
            let Some(rest) = t.path.strip_prefix("~/Library/Caches/") else {
                continue;
            };
            if rest.contains('*') || rest.contains('/') {
                continue;
            }
            let d = caches.join(rest);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("blob"), vec![b'x'; 1024]).unwrap();
            planted.push(d);
        }
        assert!(
            !planted.is_empty(),
            "the table must still have whole-directory sub-targets to overlap"
        );

        let home_str = home.to_str().unwrap();
        // Most of those names are ones the protection rails refuse, and a refused path's bytes stay
        // on disk — so leaving them in place would make "what is on disk" the wrong yardstick for
        // "what the plan may claim". Ask the rails which survive and delete the rest, and then the
        // two quantities are directly comparable: every byte left under `Caches` is a byte the plan
        // is entitled to promise, exactly once.
        let survivors: std::collections::HashSet<String> = cleanable_paths(&targets, home_str, &[])
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        for d in &planted {
            if !survivors.contains(d.to_str().unwrap()) {
                fs::remove_dir_all(d).unwrap();
            }
        }
        assert!(
            planted.iter().any(|d| survivors.contains(d.to_str().unwrap())),
            "at least one whole-directory sub-target must survive the rails, or there is no overlap left to test"
        );

        // Pre-dedup: the raw expansion is where the collision is visible. At least one path has to
        // appear twice or the fixture is not testing anything.
        let raw = cleanable_paths(&targets, home_str, &[]);
        let distinct: std::collections::HashSet<&str> =
            raw.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            distinct.len() < raw.len(),
            "fixture sanity: the expansion must contain a real duplicate ({} paths, {} distinct)",
            raw.len(),
            distinct.len()
        );

        let actual = bytes_on_disk(&caches);
        assert!(actual > 0, "fixture sanity: the fixture holds real bytes");

        // What the total looked like before the dedup: every expanded candidate sized and summed,
        // which is precisely what `plan_clean` used to hand to `plan_to_json`. It has to be strictly
        // larger than the disk, or this fixture would pass with the defect still in place.
        let undeduped: u64 = raw
            .iter()
            .filter_map(|(p, _)| size_if_exists(p))
            .sum::<u64>();
        assert!(
            undeduped > actual,
            "fixture sanity: without the dedup this over-reports ({undeduped} vs {actual} on disk)"
        );

        let plan = plan_clean(&targets, home_str, &[], PlanMode::DryRun);
        let reported: u64 = plan.iter().map(|c| c.size).sum();
        assert_eq!(
            reported, actual,
            "the plan promises bytes that are not there: {plan:#?}"
        );

        // …and the serialized total, which is what the caller actually reads, agrees.
        let j = Json::parse(&plan_to_json(&plan)).expect("must be valid JSON");
        assert_eq!(j.get("total_bytes").and_then(Json::as_u64), Some(actual));

        let _ = fs::remove_dir_all(&home);
    }

    // Creates a symlink to build the fixture, so it can only run where symlinks are
    // unprivileged: `std::os::unix::fs::symlink`. The BEHAVIOUR it pins (identity dedup collapsing
    // two spellings of one directory) is unix-only for the same reason — see `path_identity`.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_second_spelling_of_one_directory_is_still_one_directory() {
        // Identity, not string equality. Two candidates whose paths share no common text at all
        // resolve through `stat -L` to the same device+inode, and `bin/clean.sh:616` collapses them.
        // A `HashSet<String>` over the paths would keep both and double the total.
        let root =
            std::env::temp_dir().join(format!("burrow_clean_symlink_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let real = root.join("real_cache");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("blob"), vec![b'x'; 3072]).unwrap();
        let link = root.join("aliased");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let size = bytes_on_disk(&real);
        let c = |p: &Path| CleanCandidate {
            path: p.to_string_lossy().into_owned(),
            label: "User caches".into(),
            size,
        };
        let deduped = dedupe_by_identity(vec![c(&real), c(&link)]);
        assert_eq!(deduped.len(), 1, "{deduped:#?}");
        assert_eq!(
            deduped[0].path,
            real.to_string_lossy(),
            "the first spelling wins, matching `register_dry_run_cleanup_target … || continue`"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Creates a symlink to build the fixture, so it can only run where symlinks are
    // unprivileged: `std::os::unix::fs::symlink`. The BEHAVIOUR it pins (identity dedup collapsing
    // two spellings of one directory) is unix-only for the same reason — see `path_identity`.
    #[cfg(unix)]
    #[test]
    fn the_registry_is_a_dry_run_behaviour_and_the_apply_plan_keeps_every_spelling() {
        // `register_dry_run_cleanup_target` is reachable only through
        // `if [[ "$DRY_RUN" == "true" ]]` (`bin/clean.sh:614-618`; `lib/clean/caches.sh:404-408`
        // repeats it), so a real run has no registry and hands `safe_remove` every spelling. Two
        // names for one inode differ from two different directories in exactly one way that
        // matters — deleting the survivor does not free the other's bytes — so the destructive
        // plan must contain both. See `PlanMode`.
        let home = std::env::temp_dir().join(format!("burrow_plan_mode_{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let caches = home.join("Library/Caches");
        let real = caches.join("zz_realdir");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("blob"), vec![b'x'; 4096]).unwrap();
        std::os::unix::fs::symlink(&real, caches.join("aa_aliasdir")).unwrap();

        let targets = &[CleanTarget {
            path: "~/Library/Caches/*",
            label: "User app cache",
        }];
        let home_str = home.to_str().unwrap();

        let preview = plan_clean(targets, home_str, &[], PlanMode::DryRun);
        assert_eq!(
            preview.len(),
            1,
            "the preview counts one directory once: {preview:#?}"
        );
        assert!(
            preview[0].path.ends_with("aa_aliasdir"),
            "first-wins keeps the lexically first spelling, like `… || continue`: {preview:#?}"
        );

        let apply = plan_clean(targets, home_str, &[], PlanMode::Apply);
        let paths: Vec<&str> = apply.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(apply.len(), 2, "{apply:#?}");
        assert!(
            paths.iter().any(|p| p.ends_with("aa_aliasdir")),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|p| p.ends_with("zz_realdir")),
            "the target the symlink resolves to is still its own candidate: {paths:?}"
        );

        // And the gate itself, applied to an arbitrary list the way `src/cli.rs` applies it to the
        // merged one: same input, two answers, chosen by the caller and nothing else.
        let merged = apply.clone();
        assert_eq!(dedupe_for(merged.clone(), PlanMode::Apply).len(), 2);
        assert_eq!(dedupe_for(merged, PlanMode::DryRun).len(), 1);
        let _ = fs::remove_dir_all(&home);
    }

    // Creates a symlink to build the fixture (`std::os::unix::fs::symlink`), and the behaviour it
    // pins is `lstat`-vs-`stat` sizing — a unix distinction with no Windows spelling.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_sized_as_the_link_never_as_what_it_points_at() {
        // `get_cleanup_path_size_kb` (`bin/clean.sh:471-491`) tests `-L` first and answers from
        // `stat -f%z` — `lstat` on macOS, so the stored target path's length — and its own comment
        // says "a symlink reports 0 directly". The batch sizing path gates `du` the same way, on
        // `[[ -d "$path" && ! -L "$path" ]]` (`:721`). Both expected values below are read off the
        // filesystem, not written down.
        let root = std::env::temp_dir().join(format!("burrow_plan_symsize_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let real = root.join("real_cache");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("blob"), vec![b'x'; 200 * 1024]).unwrap();
        let link = root.join("aliased");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let link_len = fs::symlink_metadata(&link).unwrap().len();
        assert_eq!(
            size_if_exists(link.to_str().unwrap()),
            Some(link_len),
            "sizing through the link bills a directory that unlinking the link leaves standing"
        );
        assert_eq!(
            size_if_exists(real.to_str().unwrap()),
            Some(bytes_on_disk(&real)),
            "the real directory is still measured with the directory walk"
        );
        // A DANGLING link fails `[[ -e "$path" ]]` in bash and is not a candidate here either.
        fs::remove_dir_all(&real).unwrap();
        assert_eq!(size_if_exists(link.to_str().unwrap()), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_path_that_is_not_there_falls_back_to_its_normalized_string() {
        // `mole_path_identity`'s last line: with no `stat` answer the identity is `path:$normalized`,
        // and `mole_normalize_path` strips exactly ONE trailing slash. So two spellings of the same
        // absent path still collapse, two genuinely different absent paths still do not, and nothing
        // absent can ever be mistaken for something present.
        let c = |p: &str| CleanCandidate {
            path: p.into(),
            label: "l".into(),
            size: 7,
        };
        let out = dedupe_by_identity(vec![
            c("/no/such/burrow-xyz"),
            c("/no/such/burrow-xyz/"),
            c("/no/such/burrow-abc"),
        ]);
        assert_eq!(out.len(), 2, "{out:#?}");
        assert_eq!(out[0].path, "/no/such/burrow-xyz");
        assert_eq!(out[1].path, "/no/such/burrow-abc");
    }

    #[test]
    fn plan_json_totals_and_marks_dry_run() {
        let plan = vec![
            CleanCandidate {
                path: "/a".into(),
                label: "A".into(),
                size: 1_500_000,
            },
            CleanCandidate {
                path: "/b".into(),
                label: "B".into(),
                size: 500_000,
            },
        ];
        let j = plan_to_json(&plan);
        assert!(j.contains("\"dry_run\":true"));
        assert!(j.contains("\"total_bytes\":2000000"));
        assert!(j.contains("\"total_human\":\"2.0MB\""));
        assert!(
            j.contains("\"path\":\"/a\",\"label\":\"A\",\"size\":1500000,\"size_human\":\"1.5MB\"")
        );
        assert!(j.contains("\"text\":\""), "text field is present: {j}");

        let empty = plan_to_json(&[]);
        assert!(empty.contains("\"dry_run\":true"));
        assert!(empty.contains("\"total_bytes\":0"));
        assert!(empty.contains("\"total_human\":\"0B\""));
        assert!(empty.contains("\"items\":[]"));
        assert!(
            empty.contains("\"text\":\""),
            "text field is present: {empty}"
        );
    }

    // -- text field: matched against bin/clean.sh's real dry-run wording and the actual Swift
    // parser's behavior. Unlike purge, clean's summary line IS recognised by `mergeSummaryFields`
    // (TaskReport.swift, origin/main): it keys on the literal phrase "potential space", confirmed
    // by running clean.golden.json through the real parser via the repoint-redo Gate 1 harness
    // (`space="585.5MB" items="647" categories="27"`, sawSummary=true).

    #[test]
    fn plan_text_matches_clean_sh_wording_when_candidates_exist() {
        let plan = vec![
            CleanCandidate {
                path: "/a".into(),
                label: "User caches".into(),
                size: 1_500_000,
            },
            CleanCandidate {
                path: "/b".into(),
                label: "User logs".into(),
                size: 500_000,
            },
        ];
        let total: u64 = plan.iter().map(|c| c.size).sum();
        let text = render_plan_text(&plan, total);
        assert!(text.contains("Dry Run Mode"));
        assert!(text.contains("Dry run complete - no changes made"));
        // bin/clean.sh: `stats="Potential space: $(colorize_human_size "$freed")"` then
        // `stats+=" | Items: $files_cleaned"` then `stats+=" | Categories: $total_items"`.
        assert!(
            text.contains("Potential space: 2.0MB | Items: 2 | Categories: 2"),
            "matches bin/clean.sh's dry-run summary line: {text}"
        );
        assert!(text.contains("User caches"));
        assert!(text.contains("User logs"));
    }

    #[test]
    fn categories_counts_descriptions_not_paths() {
        // `bin/clean.sh` keeps two counters and they are not the same number: `files_cleaned`
        // (Items) gains one per PATH handled (`:962`), `total_items` (Categories) gains one per
        // `safe_clean` CALL that removed anything (`:964`). The description argument to
        // `safe_clean` is what this port carries as a candidate's label, so three paths swept under
        // one description are three items in one category — never three categories.
        let c = |p: &str, label: &str| CleanCandidate {
            path: p.into(),
            label: label.into(),
            size: 1000,
        };
        let plan = vec![
            c("/a", "User caches"),
            c("/b", "User caches"),
            c("/c", "User caches"),
            c("/d", "User logs"),
        ];
        let total: u64 = plan.iter().map(|x| x.size).sum();
        let text = render_plan_text(&plan, total);
        assert!(
            text.contains("| Items: 4 | Categories: 2"),
            "four paths under two descriptions: {text}"
        );
    }

    #[test]
    fn plan_text_matches_clean_sh_wording_when_nothing_to_clean() {
        let text = render_plan_text(&[], 0);
        assert!(text.contains("Nothing to clean."));
        assert!(!text.contains("Potential space"));
    }

    // check_tests: no-golden — `covering_target` is the plan-file gate (BUR-142), which no oracle
    // has; the anchor is the target table itself, read through the same `expand` the planner uses.
    #[test]
    fn a_plan_path_is_a_clean_target_only_at_or_under_what_the_table_could_enumerate() {
        let home = "/Users/me";
        let covers = |p: &str| covering_target(p, UNIVERSAL_TARGETS, home).map(|t| t.label);
        // Children of a `/*` sweep, and anything beneath them.
        assert_eq!(
            covers("/Users/me/Library/Caches/foo"),
            Some("User app cache")
        );
        assert_eq!(
            covers("/Users/me/Library/Caches/foo/bar"),
            Some("User app cache")
        );
        // A literal target names itself.
        assert_eq!(
            covers("/Users/me/Library/Application Support/CrashReporter"),
            Some("Crash reports")
        );
        // The most specific pattern wins the label: a row that names the entry literally beats
        // the sweep beside it, and a deeper sweep beats a shallower one.
        assert_eq!(
            covers("/Users/me/Library/Caches/com.redis.RedisInsight"),
            Some("Redis Insight cache")
        );
        assert_eq!(
            covers("/Users/me/Library/Caches/Yarn/v6"),
            Some("Yarn v1 cache")
        );
        // The swept directory itself is not a candidate — the sweep removes children.
        assert_eq!(covers("/Users/me/Library/Caches"), None);
        assert_eq!(covers("/Users/me/Library"), None);
        assert_eq!(covers("/Users/me"), None);
        // Hidden entries never match a bare `*`, exactly as `expand_pattern` never lists them.
        assert_eq!(covers("/Users/me/Library/Caches/.hidden"), None);
        // Outside every root.
        assert_eq!(covers("/Users/me/Documents/thesis"), None);
        assert_eq!(covers("/Users/other/Library/Caches/foo"), None);
        assert_eq!(covers("/System/Library/Caches/foo"), None);
        // Textual traversal and relative spellings are not targets, whatever they resolve to.
        assert_eq!(covers("/Users/me/Library/Caches/../../Documents"), None);
        assert_eq!(covers("/Users/me/Library/Caches/./foo"), None);
        assert_eq!(covers("Library/Caches/foo"), None);
        assert_eq!(covers(""), None);
    }

    #[test]
    fn a_trailing_glob_in_a_dotfile_target_does_not_widen_the_root_to_the_whole_home() {
        // `~/.bash_history.bak*` has its glob in the LAST component; a prefix-based root would have
        // been `~` itself, which covers everything. Component matching keeps it to the file.
        let home = "/Users/me";
        assert!(covering_target("/Users/me/.bash_history.bak1", UNIVERSAL_TARGETS, home).is_some());
        assert_eq!(
            covering_target("/Users/me/.ssh", UNIVERSAL_TARGETS, home),
            None
        );
        assert_eq!(
            covering_target("/Users/me/Documents", UNIVERSAL_TARGETS, home),
            None
        );
    }
}
