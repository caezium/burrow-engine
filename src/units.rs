//! Byte-size formatting shared across engine commands — ported verbatim (semantics + tests) from
//! digger's `internal/units/bytes.go` as the reimplementation migrates the legacy mo-fork core
//! into Rust.
//!
//! The callers intentionally use different conventions: disk figures (analyze) use SI (1000-based)
//! units to match Finder/diskutil, while live memory/counters (status) use binary (1024-based)
//! units to match Activity Monitor. Both live here so any tweak stays in one place. Zero-dep, pure.

/// Format a signed byte count using SI (1000-based) units, matching Finder/diskutil. Negative
/// inputs clamp to "0 B". Note the lowercase `k` (e.g. `1.0 kB`), matching diskutil.
pub fn bytes_si(size: i64) -> String {
    if size < 0 {
        return "0 B".to_string();
    }
    const UNIT: i64 = 1000;
    if size < UNIT {
        return format!("{size} B");
    }
    let (mut div, mut exp) = (UNIT, 0usize);
    let mut n = size / UNIT;
    while n >= UNIT {
        div *= UNIT;
        exp += 1;
        n /= UNIT;
    }
    let value = size as f64 / div as f64;
    // `*b"kMGTPE"` rather than a char array: clippy's `byte_char_slices` (new in 1.97, which is
    // what CI runs — local was 1.95 and never saw it) rejects the array form. Same six bytes, same
    // index, same `as char`; this is the compiler's own suggestion applied verbatim.
    let suffix = (*b"kMGTPE")[exp] as char;
    format!("{value:.1} {suffix}B")
}

/// Format an unsigned byte count using binary (1024-based) units with a trailing space and label
/// (e.g. `1.0 GB`). Boundary uses `>` so values at exactly 1<<n stay in the smaller unit (e.g.
/// 1024 -> "1024 B", 1<<20 -> "1024.0 KB").
pub fn bytes_bin(v: u64) -> String {
    let f = v as f64;
    if v > 1 << 40 {
        format!("{:.1} TB", f / (1u64 << 40) as f64)
    } else if v > 1 << 30 {
        format!("{:.1} GB", f / (1u64 << 30) as f64)
    } else if v > 1 << 20 {
        format!("{:.1} MB", f / (1u64 << 20) as f64)
    } else if v > 1 << 10 {
        format!("{:.1} KB", f / (1u64 << 10) as f64)
    } else {
        format!("{v} B")
    }
}

/// Format an unsigned byte count using binary units, no decimals, single-letter suffix, no space
/// (e.g. `100G`). Boundary uses `>=` so values at exactly 1<<n promote to the larger unit.
pub fn bytes_bin_short(v: u64) -> String {
    let f = v as f64;
    if v >= 1 << 40 {
        format!("{:.0}T", f / (1u64 << 40) as f64)
    } else if v >= 1 << 30 {
        format!("{:.0}G", f / (1u64 << 30) as f64)
    } else if v >= 1 << 20 {
        format!("{:.0}M", f / (1u64 << 20) as f64)
    } else if v >= 1 << 10 {
        format!("{:.0}K", f / (1u64 << 10) as f64)
    } else {
        format!("{v}")
    }
}

/// Format an unsigned byte count using binary units, one decimal, single-letter suffix, no space
/// (e.g. `1.5G`). Boundary uses `>=`, mirroring [`bytes_bin_short`].
pub fn bytes_bin_compact(v: u64) -> String {
    let f = v as f64;
    if v >= 1 << 40 {
        format!("{:.1}T", f / (1u64 << 40) as f64)
    } else if v >= 1 << 30 {
        format!("{:.1}G", f / (1u64 << 30) as f64)
    } else if v >= 1 << 20 {
        format!("{:.1}M", f / (1u64 << 20) as f64)
    } else if v >= 1 << 10 {
        format!("{:.1}K", f / (1u64 << 10) as f64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_si_matches_digger() {
        let cases: &[(i64, &str)] = &[
            (-100, "0 B"),
            (0, "0 B"),
            (512, "512 B"),
            (999, "999 B"),
            (1000, "1.0 kB"),
            (1500, "1.5 kB"),
            (10000, "10.0 kB"),
            (1_000_000, "1.0 MB"),
            (1_500_000, "1.5 MB"),
            (1_000_000_000, "1.0 GB"),
            (1_000_000_000_000, "1.0 TB"),
            (1_000_000_000_000_000, "1.0 PB"),
        ];
        for &(input, want) in cases {
            assert_eq!(bytes_si(input), want, "bytes_si({input})");
        }
    }

    #[test]
    fn bytes_bin_matches_digger() {
        let cases: &[(u64, &str)] = &[
            (0, "0 B"),
            (1, "1 B"),
            (1023, "1023 B"),
            (1 << 10, "1024 B"), // exactly 1KB stays in bytes ('>')
            ((1 << 10) + 1, "1.0 KB"),
            (1536, "1.5 KB"),
            (1 << 20, "1024.0 KB"), // exactly 1MB reads as 1024 KB
            ((1 << 20) + 1, "1.0 MB"),
            (500 << 20, "500.0 MB"),
            (1 << 30, "1024.0 MB"),
            ((1 << 30) + 1, "1.0 GB"),
            (100 << 30, "100.0 GB"),
            (1 << 40, "1024.0 GB"),
            ((1 << 40) + 1, "1.0 TB"),
            (2 << 40, "2.0 TB"),
        ];
        for &(input, want) in cases {
            assert_eq!(bytes_bin(input), want, "bytes_bin({input})");
        }
    }

    #[test]
    fn bytes_bin_short_matches_digger() {
        let cases: &[(u64, &str)] = &[
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (1 << 10, "1K"),
            ((1 << 10) - 1, "1023"),
            (1536, "2K"), // 1.5 rounds to 2 (round-half-to-even, same as Go %.0f)
            (999 << 10, "999K"),
            (1 << 20, "1M"),
            ((1 << 20) - 1, "1024K"),
            (500 << 20, "500M"),
            (1 << 30, "1G"),
            ((1 << 30) - 1, "1024M"),
            (100 << 30, "100G"),
            (1 << 40, "1T"),
            ((1 << 40) - 1, "1024G"),
            (2 << 40, "2T"),
        ];
        for &(input, want) in cases {
            assert_eq!(bytes_bin_short(input), want, "bytes_bin_short({input})");
        }
    }

    #[test]
    fn bytes_bin_compact_matches_digger() {
        let cases: &[(u64, &str)] = &[
            (0, "0"),
            (1, "1"),
            (1023, "1023"),
            (1 << 10, "1.0K"),
            (1536, "1.5K"),
            (1 << 20, "1.0M"),
            (500 << 20, "500.0M"),
            (1 << 30, "1.0G"),
            (100 << 30, "100.0G"),
            (1 << 40, "1.0T"),
            (2 << 40, "2.0T"),
        ];
        for &(input, want) in cases {
            assert_eq!(bytes_bin_compact(input), want, "bytes_bin_compact({input})");
        }
    }
}
