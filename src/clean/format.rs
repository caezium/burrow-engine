//! Human-readable size formatting for the cleaner — ported from digger's `bytes_to_human`
//! (lib/core/base.sh). SI (1000-based) with cleaner-specific rounding and decimals: GB to two
//! places, MB to one, KB rounded to a whole number, bytes verbatim. Round-half-up throughout (the
//! `+ half, integer-divide` trick), computed in u128 to avoid overflow on large byte counts.
//!
//! Distinct from `crate::units` (Finder/Activity-Monitor conventions); this matches the exact
//! strings the clean UI prints (`1.50GB`, `1.5MB`, `2KB`, `500B`).

/// Format a byte count the way the cleaner reports reclaimed space.
pub fn bytes_to_human(bytes: u64) -> String {
    let b = bytes as u128;
    if bytes >= 1_000_000_000 {
        let scaled = (b * 100 + 500_000_000) / 1_000_000_000; // round half up to 0.01 GB
        format!("{}.{:02}GB", scaled / 100, scaled % 100)
    } else if bytes >= 1_000_000 {
        let scaled = (b * 10 + 500_000) / 1_000_000; // round half up to 0.1 MB
        format!("{}.{:01}MB", scaled / 10, scaled % 10)
    } else if bytes >= 1_000 {
        format!("{}KB", (b + 500) / 1_000) // round half up to whole KB
    } else {
        format!("{bytes}B")
    }
}

/// KB → human, mirroring digger's `bytes_to_human_kb`.
pub fn kb_to_human(kb: u64) -> String {
    bytes_to_human(kb.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_digger_formatting() {
        let cases: &[(u64, &str)] = &[
            (0, "0B"),
            (500, "500B"),
            (999, "999B"),
            (1_000, "1KB"),
            (1_499, "1KB"), // rounds down
            (1_500, "2KB"), // rounds half up
            (999_499, "999KB"),
            (1_000_000, "1.0MB"),
            (1_500_000, "1.5MB"),
            (1_949_999, "1.9MB"),
            (1_950_000, "2.0MB"), // half up across the decimal
            (1_000_000_000, "1.00GB"),
            (1_234_000_000, "1.23GB"),
            (1_235_000_000, "1.24GB"), // half up to 0.01 GB
            (2_500_000_000, "2.50GB"),
        ];
        for &(bytes, want) in cases {
            assert_eq!(bytes_to_human(bytes), want, "bytes_to_human({bytes})");
        }
    }

    #[test]
    fn kb_helper_scales_by_1024() {
        assert_eq!(kb_to_human(1024 * 1024), bytes_to_human(1024 * 1024 * 1024));
        assert_eq!(kb_to_human(0), "0B");
    }
}
