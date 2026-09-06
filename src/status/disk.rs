//! Disk-partition filtering — decide which mounted volumes count as real local disks worth
//! reporting. Ported from digger's `cmd/status/metrics_disk.go` (`shouldSkipDiskPartition` + its
//! skip tables). The actual partition enumeration (gopsutil) is the native collector, added later;
//! this is the pure classification it feeds each partition through.

/// Mount points to skip — macOS system volumes and the device tree, which either duplicate the
/// root volume's bytes or aren't user-facing storage.
const SKIP_MOUNTS: &[&str] = &[
    "/System/Volumes/VM",
    "/System/Volumes/Preboot",
    "/System/Volumes/Update",
    "/System/Volumes/xarts",
    "/System/Volumes/Hardware",
    "/System/Volumes/Data",
    "/dev",
];

/// Filesystem types to skip — network shares and virtual/FUSE filesystems that can mirror the root
/// volume and show up as duplicate internal disks.
const SKIP_FSTYPES: &[&str] = &[
    "afpfs", "autofs", "cifs", "devfs", "fuse", "fuseblk", "fusefs", "macfuse", "nfs", "osxfuse",
    "procfs", "smbfs", "tmpfs", "webdav",
];

/// One mounted partition — the fields the skip decision reads (subset of gopsutil's PartitionStat).
#[derive(Debug, Clone, Default)]
pub struct Partition {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
}

/// True when a partition should NOT be reported as a local disk. Mirrors digger's rule order:
/// loop devices, the mount/fstype skip tables, the system + private mount prefixes, any `fuse`
/// variant, and (on macOS) any non-`/dev/` device — which filters sshfs/macFUSE mirrors of root.
pub fn should_skip_disk_partition(part: &Partition) -> bool {
    if part.device.starts_with("/dev/loop") {
        return true;
    }
    if SKIP_MOUNTS.contains(&part.mountpoint.as_str()) {
        return true;
    }
    if part.mountpoint.starts_with("/System/Volumes/") || part.mountpoint.starts_with("/private/") {
        return true;
    }
    let fstype = part.fstype.to_lowercase();
    if SKIP_FSTYPES.contains(&fstype.as_str()) || fstype.contains("fuse") {
        return true;
    }
    // macOS: a real local disk comes from /dev; a non-/dev device is a network/FUSE mirror.
    if cfg!(target_os = "macos") && !part.device.is_empty() && !part.device.starts_with("/dev/") {
        return true;
    }
    false
}

/// Read the first present of `keys` from a `diskutil info -plist` document as a u64 — each key is
/// `<key>NAME</key>…<integer>VALUE</integer>`. Tries keys in order (so callers pass most-specific
/// first). `Err` when the matched value doesn't parse; a key that's simply absent is skipped.
pub fn extract_plist_uint(plist: &str, keys: &[&str]) -> Result<u64, String> {
    for key in keys {
        let marker = format!("<key>{key}</key>");
        let Some((_, rest)) = plist.split_once(&marker) else {
            continue;
        };
        let Some((_, rest)) = rest.split_once("<integer>") else {
            continue;
        };
        let Some((value, _)) = rest.split_once("</integer>") else {
            continue;
        };
        return value
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("failed to parse {key}: {e}"));
    }
    Err("no matching plist key found".into())
}

/// Reconcile a filesystem-reported total against diskutil's: when they differ by more than 1 GiB
/// (statfs can under-report APFS container size), trust diskutil. The IO (running diskutil) is the
/// caller's; this is the pure decision, so `diskutil_total` is injected (`None` when unavailable).
pub fn correct_disk_total_bytes(raw_total: u64, diskutil_total: Option<u64>) -> u64 {
    if raw_total == 0 {
        return raw_total;
    }
    match diskutil_total {
        Some(d) if d != 0 && raw_total.abs_diff(d) > (1 << 30) => d,
        _ => raw_total,
    }
}

/// A mounted volume's usage, in bytes. Distinct from the health score's minimal DiskStatus.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiskUsage {
    pub device: String,
    pub mount: String,
    pub fstype: String,
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub used_percent: f64,
    /// True when `used`/`used_percent`/`free` are the RAW, uncorrected statfs/`df` reading —
    /// i.e. [`correct_apfs_disk_usage`]'s tier 1 (Finder) and tier 2 (diskutil) both declined or
    /// were unavailable, so the APFS sealed-snapshot-vs-container bug (this module's boxed
    /// warning on [`correct_apfs_disk_usage`] — `used_percent` low by ~40x on the root volume)
    /// could be silently present in this row. Defaults `false` (trustworthy): the common case,
    /// and the structurally correct answer for every non-APFS volume, which never enters the
    /// correction pipeline at all (see `correct_apfs_usages` in `snapshot.rs`). An ADDITIVE field
    /// (RULEBOOK RULE 1: Swift `Codable` ignores unknown keys) — never a replacement for an
    /// existing one, and never omitted, so a consumer never needs special-case decoding to read
    /// it. `correct_apfs_usages` (this field's only writer) deliberately does NOT recompute `free`
    /// as `total - used` when this is `true` — see that function's doc comment for why: doing so
    /// would make `used + free == total` trivially true always, defeating the exact invariant
    /// (`value_diff.py`'s `invariants_status`) built to catch this class of bug with no oracle.
    pub uncorrected: bool,
    /// Whether this is an external/removable disk. Defaults false (internal) — callers that don't
    /// populate it (e.g. tests exercising unrelated fields) get the safe default rather than a
    /// misleading "external".
    pub external: bool,
}

/// Parse `df -k` output (macOS layout: `Filesystem 1024-blocks Used Available Capacity iused ifree
/// %iused Mounted-on`). Sizes are KiB → bytes; `used_percent` is computed from used/total (more
/// precise than the integer Capacity column). The mount path is everything from column 9 on, so a
/// space in it survives. Header and malformed lines are skipped. fstype is left empty (fill via
/// [`apply_fstypes`]).
pub fn parse_df_k(df_output: &str) -> Vec<DiskUsage> {
    let mut disks = Vec::new();
    for line in df_output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 || fields[0] == "Filesystem" {
            continue;
        }
        let (Ok(total_kb), Ok(used_kb), Ok(avail_kb)) = (
            fields[1].parse::<u64>(),
            fields[2].parse::<u64>(),
            fields[3].parse::<u64>(),
        ) else {
            continue;
        };
        let total = total_kb * 1024;
        let used = used_kb * 1024;
        let used_percent = if total > 0 {
            used as f64 * 100.0 / total as f64
        } else {
            0.0
        };
        disks.push(DiskUsage {
            device: fields[0].to_string(),
            mount: fields[8..].join(" "),
            fstype: String::new(),
            total,
            used,
            free: avail_kb * 1024,
            used_percent,
            uncorrected: false, // provisional — `correct_apfs_usages` sets this for real once the APFS correction tiers run
            external: false, // filled in later by `collect_disk_external` (needs a live diskutil call)
        });
    }
    disks
}

/// Map mount point → filesystem type from `mount` output (`DEVICE on MOUNT (fstype, opts…)`).
pub fn parse_mount_fstypes(mount_output: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in mount_output.lines() {
        let Some((_, rest)) = line.split_once(" on ") else {
            continue;
        };
        let Some((mount, paren)) = rest.split_once(" (") else {
            continue;
        };
        let fstype = paren.split([',', ')']).next().unwrap_or("").trim();
        if !mount.is_empty() && !fstype.is_empty() {
            map.insert(mount.to_string(), fstype.to_string());
        }
    }
    map
}

/// Fill each disk's fstype from the mount map, then drop the partitions [`should_skip_disk_partition`]
/// rejects — reuniting the `df` sizes with the fstype needed for network/FUSE filtering.
pub fn apply_fstypes(
    disks: Vec<DiskUsage>,
    fstypes: &std::collections::HashMap<String, String>,
) -> Vec<DiskUsage> {
    disks
        .into_iter()
        .map(|mut d| {
            if let Some(ft) = fstypes.get(&d.mount) {
                d.fstype = ft.clone();
            }
            d
        })
        .filter(|d| {
            !should_skip_disk_partition(&Partition {
                device: d.device.clone(),
                mountpoint: d.mount.clone(),
                fstype: d.fstype.clone(),
            })
        })
        .collect()
}

/// Strip a partition suffix down to its base physical device — `disk3s1s1` -> `disk3` — so one
/// `diskutil info` lookup can be cached across every partition of the same physical disk. Ported
/// from digger's `baseDeviceName`. Non-`/dev/diskN...` devices (network shares, etc.) pass through
/// unchanged (there's no partition suffix to strip).
pub fn base_device_name(device: &str) -> &str {
    let d = device.strip_prefix("/dev/").unwrap_or(device);
    if !d.starts_with("disk") {
        return d;
    }
    match d.get(4..).and_then(|rest| rest.find('s')) {
        Some(i) => &d[..4 + i],
        None => d,
    }
}

/// Whether a disk is external, from `diskutil info <device>` output. Checks the `Internal:` line
/// first (older macOS: "No" makes it external), falling back to `Device Location:` (macOS 26
/// dropped the `Internal:` line and emits only this one: "External" makes it external). `None`
/// when neither line is present, so the caller falls back to the `/Volumes/` mount-path heuristic
/// digger uses when `diskutil` itself fails. Matches digger's `isExternalDisk` substring checks
/// exactly (`strings.Contains`, not an exact-match parse of the value).
pub fn parse_diskutil_external(output: &str) -> Option<bool> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Internal:") {
            return Some(trimmed.contains("No"));
        }
        if trimmed.starts_with("Device Location:") {
            return Some(trimmed.contains("External"));
        }
    }
    None
}

/// Whether `device` (e.g. `/dev/disk3s1s1`) is external — runs `diskutil info` on its base device
/// and parses the result, falling back to the `/Volumes/` mount-path heuristic when `diskutil`
/// fails or reports neither field (matches digger's `annotateDiskTypes` fallback).
///
/// FIX 7 (RULEBOOK): timeout-bounded at 1 second, matching digger's own `isExternalDisk`
/// (`metrics_disk.go:233`, `context.WithTimeout(context.Background(), time.Second)`). The unbounded
/// `run_command` this used to call blocks on a spinning-up or unresponsive external volume — exactly
/// the machine state that produces external disks to enrich in the first place. A fast measurement
/// here (this call took 0.07s while writing this) proves nothing about the worst case, the same way
/// a fast `netstat -ib` proved nothing before it hung 90+ seconds the next hour.
pub fn collect_disk_external(device: &str, mount: &str) -> bool {
    let base = base_device_name(device);
    let base = if base.is_empty() { device } else { base };
    let fallback = || mount.starts_with("/Volumes/");
    match super::collect::run_command_with_timeout(
        "diskutil",
        &["info", base],
        std::time::Duration::from_secs(1),
    ) {
        Some(out) => parse_diskutil_external(&out).unwrap_or_else(fallback),
        None => fallback(),
    }
}

/// Read `diskutil info -plist <mountpoint>`'s `TotalSize` (falling back to `DiskSize`/`Size`) for
/// [`correct_disk_total_bytes`]. `None` when the command fails/times out or no matching key is
/// found. Timeout-bounded at 3 seconds, matching digger's `getDiskutilTotalBytes`
/// (`metrics_disk.go`).
pub fn get_diskutil_total_bytes(mountpoint: &str) -> Option<u64> {
    let out = get_diskutil_info(mountpoint)?;
    extract_plist_uint(&out, &["TotalSize", "DiskSize", "Size"]).ok()
}

/// Read `diskutil info -plist <mountpoint>`'s `APFSContainerFree` for
/// [`correct_apfs_disk_usage`]'s tier 2. `None` when the command fails/times out or the key is
/// absent (e.g. a non-APFS volume). Timeout-bounded at 3 seconds, matching digger's
/// `getAPFSContainerFreeBytes` (`metrics_disk.go`).
pub fn get_apfs_container_free_bytes(mountpoint: &str) -> Option<u64> {
    let out = get_diskutil_info(mountpoint)?;
    extract_plist_uint(&out, &["APFSContainerFree"]).ok()
}

/// One shared plist fetch for the current collection pass's total/free corrections.
pub(crate) fn get_diskutil_info(mountpoint: &str) -> Option<String> {
    super::collect::run_command_with_timeout(
        "diskutil",
        &["info", "-plist", mountpoint],
        std::time::Duration::from_secs(3),
    )
}

/// Parse `osascript`'s stdout for the Finder startup-disk query above into `(free, total)` bytes.
/// Split out from [`get_finder_startup_disk_free_bytes`] purely so the FAILURE path — the one this
/// whole slice exists to make visible via `DiskUsage::uncorrected` — is directly unit-testable
/// without shelling out or touching TCC/Automation permissions: every way `osascript` can fail to
/// hand back two usable numbers (empty output, an error string on stdout, a missing separator, a
/// non-numeric field, or a non-positive reading) is exercised below by feeding this function
/// exactly the bytes `osascript` would have produced, the same way [`parse_diskutil_external`] is
/// tested against captured `diskutil` text without running `diskutil`.
fn parse_finder_startup_disk_free(out: &str) -> Option<(u64, u64)> {
    // Output format: "3.2489E+11, 4.9438E+11" or "324892202048, 494384795648" — Rust's f64 FromStr
    // accepts scientific notation natively, so no special-casing is needed for either shape.
    let (free_s, total_s) = out.trim().split_once(',')?;
    let free: f64 = free_s.trim().parse().ok()?;
    let total: f64 = total_s.trim().parse().ok()?;
    if !free.is_finite()
        || !total.is_finite()
        || free <= 0.0
        || total <= 0.0
        || free >= u64::MAX as f64
        || total >= u64::MAX as f64
    {
        return None;
    }
    Some((free as u64, total as u64))
}

/// Finder's startup-disk free/total bytes (`free`, `total`), via `osascript` — for
/// [`correct_apfs_disk_usage`]'s tier 1 (root volume only; Finder only reports the startup disk).
/// Matches Finder's own "X GB of Y GB available" figure, which is purgeable-cache- and
/// APFS-snapshot-aware in a way `statfs` isn't. `None` when the command fails/times out or the
/// output doesn't parse as two positive numbers — see [`parse_finder_startup_disk_free`] for
/// exactly which malformed shapes that covers, INCLUDING the Automation/TCC-denied case: `osascript`
/// exits non-zero on "Not authorized to send Apple events to Finder" (-1743), so
/// [`super::collect::run_command_with_timeout`]'s own `status.success()` check (not this function)
/// is what turns THAT failure into `None` — the two functions together cover every way tier 1 can
/// fail, from "the process never answered" down to "it answered with something unusable". Ported
/// from digger's `getFinderStartupDiskFreeBytes` (`metrics_disk.go`) MINUS its 2-minute cache — this
/// engine is one-shot, so there is nothing to cache across, and this is called at most once per
/// invocation (only for the mount `"/"`). Timeout-bounded at 5 seconds, matching the original —
/// well inside the GUI's 8-second `status` capture timeout, and bounded by the same kill-on-deadline
/// mechanism [`super::collect::run_command_with_timeout`]'s own tests prove against a genuinely
/// wedged child process, not merely the happy path.
pub fn get_finder_startup_disk_free_bytes() -> Option<(u64, u64)> {
    let out = super::collect::run_command_with_timeout(
        "osascript",
        &[
            "-e",
            r#"tell application "Finder" to return {free space of startup disk, capacity of startup disk}"#,
        ],
        std::time::Duration::from_secs(5),
    )?;
    parse_finder_startup_disk_free(&out)
}

/// FIX 1 (RULEBOOK) — the correction `correctAPFSDiskUsage` (`metrics_disk.go`) applies, decided
/// purely over already-fetched inputs (the IO — Finder/diskutil — is the caller's, via
/// [`get_finder_startup_disk_free_bytes`] / [`get_apfs_container_free_bytes`]).
///
/// On APFS, `df -k /` (and gopsutil's `disk.Usage`, which reads the same statfs data) reports the
/// SEALED ~12GB system snapshot's usage against the full multi-hundred-GB CONTAINER total — two
/// different denominators for the same row — so the raw `used`/`used_percent` come out ~40x too
/// low on the volume that matters most. Three-tier fallback, exactly matching the original:
///   1. Finder via osascript (startup disk / `/` only) — exact match with what Finder itself shows.
///   2. `diskutil`'s `APFSContainerFree` — corrects the APFS-snapshot double-count, but only applied
///      when it meaningfully differs (>1GiB) from the raw value, to avoid noise.
///   3. The raw (statfs-derived) `used`/`total` — unchanged, when neither correction is available.
///
/// Measured live, same machine, same second, pre-fix: oracle `used_percent=99.27` ("Good: Disk
/// Almost Full") vs this engine `used_percent=2.50` ("Excellent") — see RULEBOOK §3's boxed warning.
///
/// KNOWN FRAGILITY (flagged in review, faithful to the original, NOT rescued here): tier 2 only
/// fires when `raw_used > corrected`, i.e. it corrects raw OVER-reporting. The root-volume bug
/// above is raw UNDER-reporting, so tier 2 structurally cannot rescue it — only tier 1 (Finder) can.
/// That means the root disk's correctness depends entirely on `osascript`/Finder succeeding: in any
/// headless, SSH, sandboxed-CI, or Automation-permission-revoked context, tier 1 fails and this
/// falls through to tier 3 (raw, unchanged) — the 40x bug returns. This is inherited as-is from
/// digger (`correctAPFSDiskUsage`, `metrics_disk.go`), which has the identical asymmetry, so
/// porting it faithfully means keeping the BEHAVIOUR. What changed is that the failure no longer
/// has to stay silent: the third return value, `uncorrected`, is `true` exactly when this function
/// fell through to tier 3 (whether because neither Finder nor diskutil answered, or — the
/// structurally-unrescuable case above — diskutil answered but couldn't help). The caller
/// (`correct_apfs_usages` in `snapshot.rs`) surfaces this as an ADDITIVE `disks[].uncorrected` JSON
/// field (RULEBOOK RULE 1: an extra key can't break Swift decode) and, just as importantly, stops
/// recomputing `free` as `total - used` for that one row — see that function's doc comment for why
/// a derived `free` would otherwise make `value_diff.py`'s `used + free == total` invariant
/// trivially true always, masking precisely the regression it exists to catch with no oracle
/// needed. Nothing here fabricates a corrected number where none exists (RULEBOOK §3h) — `used`/
/// `used_percent` in the tier-3 branch are exactly what they were before this change.
///
/// Separately (also known, also left alone): non-root APFS volumes can show a small residual gap
/// against the oracle — measured live on a CoreSimulator DMG volume, ~0.26% (43MB on 17GB). Traced
/// to `df -k`'s "Used" column reporting a different raw number than the statfs read gopsutil
/// performs for that specific volume type, which lands the two engines' raw inputs on opposite
/// sides of tier 2's `raw_used > corrected` boundary. This is a raw-input-source difference, not a
/// bug in the decision logic above (verified byte-for-byte against `correctAPFSDiskUsage`) — fixing
/// it would mean reimplementing statfs instead of shelling out to `df`, which is out of scope for a
/// zero-dep, shell-out-only engine. Documented rather than papered over.
///
/// Returns `(used, used_percent, uncorrected)`.
pub fn correct_apfs_disk_usage(
    mountpoint: &str,
    total: u64,
    raw_used: u64,
    finder: Option<(u64, u64)>,
    container_free: Option<u64>,
) -> (u64, f64, bool) {
    // Tier 1: Finder (root volume only).
    if mountpoint == "/" {
        if let Some((finder_free, finder_total)) = finder {
            if finder_total > 0 && finder_free <= finder_total {
                let used = finder_total - finder_free;
                let used_percent = used as f64 / finder_total as f64 * 100.0;
                return (used, used_percent, false);
            }
        }
    }
    // Tier 2: diskutil's APFSContainerFree, only when it meaningfully (>1GiB) differs from raw.
    if let Some(container_free) = container_free {
        if container_free <= total {
            let corrected = total - container_free;
            if raw_used > corrected && raw_used - corrected > (1u64 << 30) {
                let used_percent = if total > 0 {
                    corrected as f64 / total as f64 * 100.0
                } else {
                    0.0
                };
                return (corrected, used_percent, false);
            }
        }
    }
    // Tier 3: raw statfs-derived values, unchanged — and, unlike tiers 1/2, UNCORRECTED. This is
    // the branch that can silently carry the 40x bug (see the fragility paragraph above), so the
    // caller needs to know it was taken.
    let used_percent = if total > 0 {
        raw_used as f64 / total as f64 * 100.0
    } else {
        0.0
    };
    (raw_used, used_percent, true)
}

/// Base-device dedupe: keep only the FIRST partition seen per physical base device (`disk3s1s1`
/// and a hypothetical `disk3s5` are the same physical `disk3`) — matches digger's `seenDevice`
/// map in `collectDisksWithCorrections`. Order-preserving.
pub fn dedupe_by_base_device(disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    let mut seen = std::collections::HashSet::new();
    disks
        .into_iter()
        .filter(|d| seen.insert(base_device_name(&d.device).to_string()))
        .collect()
}

/// Drop volumes under 1 GiB — matches digger's `if total < 1<<30 { continue }`. A fragment/pseudo
/// volume that small isn't worth a status row.
pub fn skip_tiny_volumes(disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    disks
        .into_iter()
        .filter(|d| d.total >= (1u64 << 30))
        .collect()
}

/// Size-based dedupe for shared pools: two mounts with the same `(fstype, total)` are treated as
/// the same underlying volume seen twice — matches digger's `seenVolume` map, keyed
/// `fmt.Sprintf("%s:%d", part.Fstype, total)`. Order-preserving.
pub fn dedupe_by_fstype_and_total(disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    let mut seen = std::collections::HashSet::new();
    disks
        .into_iter()
        .filter(|d| seen.insert((d.fstype.clone(), d.total)))
        .collect()
}

/// Final ordering + cap: internal disks before external, then largest total first, keeping only
/// the top 3 — matches digger's `collectDisksWithCorrections` tail exactly:
/// ```go
/// sort.Slice(disks, func(i, j int) bool {
///     if disks[i].External != disks[j].External { return !disks[i].External }
///     return disks[i].Total > disks[j].Total
/// })
/// if len(disks) > 3 { disks = disks[:3] }
/// ```
/// Must run AFTER `external` is populated (diskutil enrichment) — this is the third instance of
/// the sort-then-truncate pattern in this contract (network's top-3-by-rate is the other), and
/// this one is squarely this module's because the sort key (`external`) is the field this slice
/// added.
pub fn sort_and_cap_disks(mut disks: Vec<DiskUsage>) -> Vec<DiskUsage> {
    disks.sort_by(|a, b| {
        a.external
            .cmp(&b.external) // false (internal) sorts before true (external)
            .then_with(|| b.total.cmp(&a.total)) // larger total first
    });
    disks.truncate(3);
    disks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn df_k_parses_sizes_and_spaced_mount() {
        let df =
            "Filesystem   1024-blocks     Used Available Capacity iused ifree %iused Mounted on\n\
/dev/disk3s1s1 976490576 21000000 900000000 3% 500 100 1% /\n\
map -hosts             0        0         0 100% 0 0 100% /net\n\
/dev/disk4    1000000  400000   600000 40% 1 1 1% /Volumes/My Disk";
        let disks = parse_df_k(df);
        // Header + the `map -hosts` pseudo-mount (two-word device → non-numeric blocks col) are
        // skipped; the two real /dev disks parse.
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].mount, "/");
        assert_eq!(disks[0].total, 976490576 * 1024);
        assert_eq!(disks[0].used, 21000000 * 1024);
        assert!((disks[0].used_percent - (21000000.0 * 100.0 / 976490576.0)).abs() < 1e-9);
        assert_eq!(disks[1].mount, "/Volumes/My Disk", "spaced mount preserved");
    }

    #[test]
    fn mount_fstypes_and_filter() {
        let mount = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)\n\
//guest@server/share on /Volumes/share (smbfs, nodev, nosuid, mounted by x)";
        let map = parse_mount_fstypes(mount);
        assert_eq!(map.get("/"), Some(&"apfs".to_string()));
        assert_eq!(map.get("/Volumes/share"), Some(&"smbfs".to_string()));

        let disks = vec![
            DiskUsage {
                device: "/dev/disk3s1s1".into(),
                mount: "/".into(),
                ..Default::default()
            },
            DiskUsage {
                device: "//guest@server/share".into(),
                mount: "/Volumes/share".into(),
                ..Default::default()
            },
        ];
        let kept = apply_fstypes(disks, &map);
        // The smbfs share is filtered out; the apfs root stays, now carrying its fstype.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].mount, "/");
        assert_eq!(kept[0].fstype, "apfs");
    }

    fn part(device: &str, mountpoint: &str, fstype: &str) -> Partition {
        Partition {
            device: device.into(),
            mountpoint: mountpoint.into(),
            fstype: fstype.into(),
        }
    }

    #[test]
    fn keeps_local_apfs_root() {
        assert!(!should_skip_disk_partition(&part(
            "/dev/disk3s1s1",
            "/",
            "apfs"
        )));
    }

    #[test]
    fn skips_network_and_fuse_and_system_volumes() {
        // macfuse mirror (by fstype).
        assert!(should_skip_disk_partition(&part(
            "fixture-local:/",
            "/Users/alice/Library/Caches/org.example.fixture/sshfs/fixture-local",
            "macfuse"
        )));
        // SMB share (by fstype).
        assert!(should_skip_disk_partition(&part(
            "//server/share",
            "/Volumes/share",
            "smbfs"
        )));
        // System data volume (by mountpoint prefix).
        assert!(should_skip_disk_partition(&part(
            "/dev/disk3s5",
            "/System/Volumes/Data",
            "apfs"
        )));
        // loop device.
        assert!(should_skip_disk_partition(&part(
            "/dev/loop0",
            "/snap/x",
            "squashfs"
        )));
        // any *fuse* fstype variant.
        assert!(should_skip_disk_partition(&part(
            "/dev/x",
            "/mnt/x",
            "gocryptfs-fuse"
        )));
    }

    #[test]
    fn plist_uint_prefers_first_key_and_falls_back() {
        let raw = "<plist><dict>\n<key>TotalSize</key><integer>1099511627776</integer>\n<key>DiskSize</key><integer>2199023255552</integer>\n</dict></plist>";
        assert_eq!(
            extract_plist_uint(raw, &["TotalSize", "DiskSize"]),
            Ok(1099511627776)
        );
        // TotalSize absent → fall through to DiskSize.
        let only_disk =
            "<plist><dict><key>DiskSize</key><integer>1099511627776</integer></dict></plist>";
        assert_eq!(
            extract_plist_uint(only_disk, &["TotalSize", "DiskSize", "Size"]),
            Ok(1099511627776)
        );
    }

    #[test]
    fn plist_uint_errors_on_malformed_integer() {
        let raw = "<plist><dict><key>TotalSize</key><integer>oops</integer></dict></plist>";
        assert!(extract_plist_uint(raw, &["TotalSize"]).is_err());
        assert!(extract_plist_uint("<plist/>", &["TotalSize"]).is_err()); // absent
    }

    #[test]
    fn correct_total_uses_diskutil_only_for_big_diffs() {
        // >1 GiB apart → trust diskutil.
        assert_eq!(
            correct_disk_total_bytes(2199023255552, Some(1099511627776)),
            1099511627776
        );
        // Small difference → keep the raw statfs total.
        assert_eq!(
            correct_disk_total_bytes(1_000_500_000_000, Some(1_000_000_000_000)),
            1_000_500_000_000
        );
        // No diskutil reading, or zero raw → raw unchanged.
        assert_eq!(correct_disk_total_bytes(500, None), 500);
        assert_eq!(correct_disk_total_bytes(0, Some(999)), 0);
    }

    #[test]
    fn finder_startup_disk_free_parses_both_real_output_shapes() {
        // Plain integers — captured live from `osascript` on this machine.
        assert_eq!(
            parse_finder_startup_disk_free("324892202048, 494384795648"),
            Some((324892202048, 494384795648))
        );
        // Scientific notation — the OTHER shape the real `osascript` emits for the same query
        // (AppleScript prints large reals this way); Rust's f64 parser accepts it with no
        // special-casing, so this must round-trip too, not just the plain-integer shape.
        let (free, total) = parse_finder_startup_disk_free("3.2489E+11, 4.9438E+11")
            .expect("scientific notation must parse");
        assert!((free as i64 - 324_890_000_000).abs() < 1_000_000);
        assert!((total as i64 - 494_380_000_000).abs() < 1_000_000);
    }

    #[test]
    fn finder_startup_disk_free_is_none_on_every_way_osascript_can_fail_to_answer() {
        // This is the function whose `None` becomes `correct_apfs_disk_usage`'s `finder: None` —
        // i.e. exactly the input that drives `uncorrected: true` for the root volume. Every shape
        // below is a realistic way tier 1 can come back empty-handed WITHOUT a non-zero exit code
        // (which `run_command_with_timeout`'s own `status.success()` check already handles
        // upstream — see this function's doc comment): a genuinely wedged/killed child is covered
        // separately by `run_command_with_timeout_kills_a_hanging_child_instead_of_blocking_forever`
        // in `collect.rs`, not re-tested here.
        assert_eq!(parse_finder_startup_disk_free(""), None, "empty stdout");
        for reading in [
            "NaN, 100",
            "100, NaN",
            "inf, inf",
            "-inf, 100",
            "1e30, 1e30",
        ] {
            assert_eq!(parse_finder_startup_disk_free(reading), None, "{reading}");
        }
        assert_eq!(
            parse_finder_startup_disk_free("execution error: Not authorized to send Apple events to Finder. (-1743)"),
            None,
            "an error string landing on stdout instead of the expected pair must not be parsed as a number"
        );
        assert_eq!(
            parse_finder_startup_disk_free("494384795648"),
            None,
            "no comma separator — only one value returned"
        );
        assert_eq!(
            parse_finder_startup_disk_free("not-a-number, 494384795648"),
            None,
            "non-numeric free side"
        );
        assert_eq!(
            parse_finder_startup_disk_free("324892202048, not-a-number"),
            None,
            "non-numeric total side"
        );
        assert_eq!(
            parse_finder_startup_disk_free("0, 494384795648"),
            None,
            "zero free is not a trustworthy Finder reading"
        );
        assert_eq!(
            parse_finder_startup_disk_free("324892202048, 0"),
            None,
            "zero total is not a trustworthy Finder reading"
        );
        assert_eq!(
            parse_finder_startup_disk_free("-324892202048, 494384795648"),
            None,
            "a negative reading is not trustworthy either"
        );
    }

    #[test]
    fn apfs_usage_correction_reproduces_the_live_oracle_measurement() {
        // FIX 1 (RULEBOOK): reproduces the exact live measurement in the boxed warning — same
        // machine, same second: raw statfs said used=12573351936/total=494384795648 (2.50%,
        // "Excellent"); the real oracle said used=490800472064 (99.27%, "Good: Disk Almost Full").
        // This is TIER 1 (Finder) on the real capture, not tier 2: diskutil's own
        // "Container Free 3.4 GB" would make tier 2's `rawUsed > corrected` gate FALSE here
        // (12.5GB raw is not greater than the ~490.8GB corrected figure — tier 2 only corrects
        // raw OVER-reporting, a different failure mode; see the tier-2 tests below), so on the
        // real machine it is Finder alone that fixes this specific 40x bug. If Finder/osascript
        // ever fails for the root volume, this falls through past tier 2 (which structurally
        // cannot help here) to tier 3 (raw, still wrong) — a real fragility inherited from the
        // original, not introduced by this port.
        let total = 494_384_795_648u64;
        let raw_used = 12_573_351_936u64;
        let finder_free = total - 490_800_472_064; // ~3.4GB, matching diskutil's own reading
        let (used, used_percent, uncorrected) =
            correct_apfs_disk_usage("/", total, raw_used, Some((finder_free, total)), None);
        assert_eq!(used, 490_800_472_064);
        assert!(
            (used_percent - 99.27).abs() < 0.01,
            "got {used_percent}, want ~99.27"
        );
        assert!(
            !uncorrected,
            "tier 1 (Finder) answered — this row is trustworthy"
        );
    }

    #[test]
    fn apfs_usage_correction_flags_uncorrected_when_finder_fails_on_the_root_volume() {
        // The exact fragility documented on `correct_apfs_disk_usage`: SAME numbers as the live-
        // oracle reproduction above (same machine, same bug), but Finder/osascript gives nothing —
        // headless, over SSH, sandboxed CI, or Automation/TCC permission refused. Tier 2
        // structurally cannot rescue this (it only corrects raw OVER-reporting; this bug is raw
        // UNDER-reporting), and it isn't even offered a `container_free` reading here, so this
        // must fall all the way to tier 3: the wrong 2.5%-of-a-full-disk number, silently, UNLESS
        // the caller checks `uncorrected`. This is the case the whole slice exists to make
        // detectable — the value itself does not and must not change (RULEBOOK §3h: never invent
        // a number where an honest one exists; the honest one here is "still wrong, but flagged").
        let total = 494_384_795_648u64;
        let raw_used = 12_573_351_936u64;
        let (used, used_percent, uncorrected) =
            correct_apfs_disk_usage("/", total, raw_used, None, None);
        assert_eq!(
            used, raw_used,
            "no correction fired, so `used` must stay the raw (wrong) reading, not a guess"
        );
        assert!(
            (used_percent - 2.5432319211030463).abs() < 1e-9,
            "got {used_percent}, want the exact raw_used/total ratio — the original 40x-too-low \
             bug, faithfully reproduced with no rounding smoothing it over"
        );
        assert!(
            uncorrected,
            "neither tier 1 nor tier 2 answered — the caller MUST be told this row is unverified"
        );
    }

    #[test]
    fn apfs_usage_correction_prefers_finder_on_the_root_volume() {
        // Tier 1 (Finder) wins over tier 2 (diskutil) when both are available, and only applies to
        // "/" — matches digger's `correctAPFSDiskUsage` tier order exactly.
        let (used, pct, uncorrected) = correct_apfs_disk_usage(
            "/",
            1_000_000_000_000,
            999_000_000_000, // raw (irrelevant once Finder answers)
            Some((100_000_000_000, 1_000_000_000_000)), // Finder: 100GB free of 1TB
            Some(1),         // diskutil disagrees; must be ignored
        );
        assert_eq!(used, 900_000_000_000);
        assert!((pct - 90.0).abs() < 1e-9);
        assert!(!uncorrected);
    }

    #[test]
    fn apfs_usage_correction_ignores_finder_off_the_root_volume() {
        // Finder only ever reports the STARTUP disk — a non-root APFS volume must skip tier 1 even
        // when a `finder` reading happens to be supplied, and fall through to tier 2. Tier 2
        // corrects raw OVER-reporting (rawUsed > corrected), so raw here must start out higher
        // than the diskutil-corrected figure — the opposite direction from the tier-1 scenario
        // above (which corrects raw UNDER-reporting).
        let total = 100_000_000_000u64;
        let raw_used = 50_000_000_000u64; // raw claims 50GB used
        let container_free = 70_000_000_000u64; // diskutil says 70GB free -> corrected = 30GB
        let (used, _, uncorrected) = correct_apfs_disk_usage(
            "/Volumes/External",
            total,
            raw_used,
            Some((10, 100)), // present but must be ignored — not "/"
            Some(container_free),
        );
        assert_eq!(
            used, 30_000_000_000,
            "raw (50GB) over-reported vs corrected (30GB) by >1GiB, so tier 2 must apply"
        );
        assert!(
            !uncorrected,
            "tier 2 (diskutil) answered — this row is trustworthy"
        );
    }

    #[test]
    fn apfs_usage_correction_skips_tier_2_when_the_difference_is_noise() {
        // Only applies the diskutil correction when raw over-reports by >1GiB — a smaller
        // difference is noise, not a real APFS-snapshot discrepancy, and must keep the raw value.
        let total = 100_000_000_000u64;
        let raw_used = 50_000_000_000u64;
        let corrected = raw_used - 500_000_000; // only 0.5GiB below raw — under the 1GiB bar
        let container_free = total - corrected;
        let (used, _, uncorrected) =
            correct_apfs_disk_usage("/data", total, raw_used, None, Some(container_free));
        assert_eq!(
            used, raw_used,
            "sub-1GiB difference must not override the raw value"
        );
        // This IS the tier-3 branch (neither tier 1 nor tier 2's early return fired), so it is
        // reported `uncorrected` even though the raw value happens to be fine here — the function
        // only knows whether it actively verified a row, not how lucky the raw value got. A
        // coarser-but-honest signal beats inventing a confidence tier this function has no basis
        // to compute.
        assert!(uncorrected);
    }

    #[test]
    fn apfs_usage_correction_falls_back_to_raw_when_nothing_is_available() {
        let (used, pct, uncorrected) = correct_apfs_disk_usage("/", 1000, 300, None, None);
        assert_eq!(used, 300);
        assert!((pct - 30.0).abs() < 1e-9);
        assert!(uncorrected);
        // total == 0 must not divide by zero.
        let (used, pct, uncorrected) = correct_apfs_disk_usage("/", 0, 0, None, None);
        assert_eq!(used, 0);
        assert_eq!(pct, 0.0);
        assert!(uncorrected);
    }

    #[test]
    fn base_device_name_strips_partition_suffix() {
        assert_eq!(base_device_name("/dev/disk3s1s1"), "disk3");
        assert_eq!(base_device_name("disk5s1"), "disk5");
        assert_eq!(base_device_name("/dev/disk10s2"), "disk10");
        // No partition suffix to strip: passed through unchanged (matches digger's fallback).
        assert_eq!(
            base_device_name("//guest@server/share"),
            "//guest@server/share"
        );
    }

    // Captured from `diskutil info disk3s1s1` (this machine's internal root volume) and
    // `diskutil info disk5s1` (the CoreSimulator disk image mounted at
    // /Library/Developer/CoreSimulator/Volumes/... — the SAME device the golden's second disk,
    // external:true, was captured from). Current macOS emits only `Device Location:`, not
    // `Internal:` — both branches are exercised below regardless, since older macOS still emits
    // `Internal:` and digger checks it first.
    const DISKUTIL_INTERNAL_SAMPLE: &str = "   Device Identifier:         disk3s1s1\n\
   Device Node:               /dev/disk3s1s1\n\
   Volume Name:               Macintosh HD\n\
   Mounted:                   Yes\n\
   Mount Point:               /\n\
   Device Location:           Internal\n\
   Removable Media:           Fixed\n\
   Solid State:               Yes\n";

    const DISKUTIL_EXTERNAL_SAMPLE: &str = "   Device Identifier:         disk5s1\n\
   Device Node:               /dev/disk5s1\n\
   Volume Name:               iOS_23B86\n\
   Mounted:                   Yes\n\
   Device Location:           External\n";

    const DISKUTIL_OLDER_MACOS_INTERNAL_SAMPLE: &str = "   Device Identifier:         disk0s2\n\
   Internal:                  Yes\n\
   Removable Media:           Fixed\n";

    const DISKUTIL_OLDER_MACOS_EXTERNAL_SAMPLE: &str = "   Device Identifier:         disk4s1\n\
   Internal:                  No\n\
   Removable Media:           Yes\n";

    #[test]
    fn diskutil_external_reads_device_location_on_current_macos() {
        assert_eq!(
            parse_diskutil_external(DISKUTIL_INTERNAL_SAMPLE),
            Some(false)
        );
        assert_eq!(
            parse_diskutil_external(DISKUTIL_EXTERNAL_SAMPLE),
            Some(true)
        );
    }

    #[test]
    fn diskutil_external_prefers_internal_field_when_present() {
        assert_eq!(
            parse_diskutil_external(DISKUTIL_OLDER_MACOS_INTERNAL_SAMPLE),
            Some(false)
        );
        assert_eq!(
            parse_diskutil_external(DISKUTIL_OLDER_MACOS_EXTERNAL_SAMPLE),
            Some(true)
        );
    }

    #[test]
    fn diskutil_external_none_when_neither_field_present() {
        assert_eq!(
            parse_diskutil_external("   Device Identifier: disk9\n"),
            None
        );
        assert_eq!(parse_diskutil_external(""), None);
    }

    fn du(device: &str, mount: &str, fstype: &str, total: u64) -> DiskUsage {
        DiskUsage {
            device: device.into(),
            mount: mount.into(),
            fstype: fstype.into(),
            total,
            used: total / 2,
            free: total / 2,
            used_percent: 50.0,
            uncorrected: false,
            external: false,
        }
    }

    #[test]
    fn dedupe_by_base_device_keeps_first_partition_per_physical_disk() {
        let disks = vec![
            du("/dev/disk3s1s1", "/", "apfs", 500_000_000_000),
            du(
                "/dev/disk3s5",
                "/System/Volumes/Data2",
                "apfs",
                400_000_000_000,
            ), // same base: disk3
            du("/dev/disk5s1", "/Volumes/Ext", "apfs", 100_000_000_000),
        ];
        let out = dedupe_by_base_device(disks);
        assert_eq!(out.len(), 2, "disk3s1s1 and disk3s5 share base disk3");
        assert_eq!(
            out[0].device, "/dev/disk3s1s1",
            "first partition of disk3 wins"
        );
        assert_eq!(out[1].device, "/dev/disk5s1");
    }

    #[test]
    fn skip_tiny_volumes_drops_under_1gib() {
        let disks = vec![
            du("/dev/disk1", "/a", "apfs", (1u64 << 30) - 1), // just under 1 GiB
            du("/dev/disk2", "/b", "apfs", 1u64 << 30),       // exactly 1 GiB — kept
            du("/dev/disk3", "/c", "apfs", 500_000_000_000),
        ];
        let out = skip_tiny_volumes(disks);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|d| d.total >= (1u64 << 30)));
    }

    #[test]
    fn dedupe_by_fstype_and_total_drops_size_twins() {
        let disks = vec![
            du("/dev/disk1", "/a", "apfs", 500_000_000_000),
            du("/dev/disk2", "/a/mirror", "apfs", 500_000_000_000), // same fstype:total → twin
            du("/dev/disk3", "/b", "apfs", 100_000_000_000),        // different total → kept
            du("/dev/disk4", "/c", "hfs", 500_000_000_000),         // different fstype → kept
        ];
        let out = dedupe_by_fstype_and_total(disks);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].mount, "/a", "first of the size-twins wins");
    }

    #[test]
    fn sort_and_cap_disks_prefers_internal_then_largest_then_caps_at_3() {
        let mut small_internal = du("/dev/disk1", "/small-int", "apfs", 10_000_000_000);
        small_internal.external = false;
        let mut big_external = du("/dev/disk2", "/big-ext", "apfs", 900_000_000_000);
        big_external.external = true;
        let mut big_internal = du("/dev/disk3", "/big-int", "apfs", 500_000_000_000);
        big_internal.external = false;
        let mut small_external = du("/dev/disk4", "/small-ext", "apfs", 5_000_000_000);
        small_external.external = true;
        let mut mid_internal = du("/dev/disk5", "/mid-int", "apfs", 50_000_000_000);
        mid_internal.external = false;

        let out = sort_and_cap_disks(vec![
            small_internal.clone(),
            big_external.clone(),
            big_internal.clone(),
            small_external.clone(),
            mid_internal.clone(),
        ]);
        assert_eq!(out.len(), 3, "must cap at 3 even though 5 went in");
        // Internal-before-external always wins, regardless of size: the 900GB external disk
        // ranks BELOW every internal disk, including the 10GB one.
        assert_eq!(
            out.iter().map(|d| d.mount.as_str()).collect::<Vec<_>>(),
            vec!["/big-int", "/mid-int", "/small-int"],
            "all three internal disks, largest-first, beat the 900GB external disk entirely"
        );
    }

    #[test]
    fn sort_and_cap_disks_matches_the_golden_shape_two_disks_no_truncation() {
        // The golden's own two disks: root (internal, 494GB) then the CoreSimulator image
        // (external, 17GB) — external mounted second even though disk ordering from `df` could
        // have been arbitrary.
        let mut root = du("/dev/disk3s1s1", "/", "apfs", 494_384_795_648);
        root.external = false;
        let mut sim = du(
            "/dev/disk5s1",
            "/Library/Developer/CoreSimulator/Volumes/iOS_23B86",
            "apfs",
            17_572_036_608,
        );
        sim.external = true;
        let out = sort_and_cap_disks(vec![sim, root]); // fed in reverse order on purpose
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].mount, "/");
        assert_eq!(
            out[1].mount,
            "/Library/Developer/CoreSimulator/Volumes/iOS_23B86"
        );
    }
}
