//! Hardware identity — model, chip, RAM, OS version, display refresh rate. Ported from digger's
//! `cmd/status/metrics_hardware.go`. The pure parsers over `system_profiler` / `sw_vers` output are
//! here (testable); `collect_hardware` runs the commands.

use crate::units::bytes_bin;
use std::time::Duration;

/// Static hardware facts shown in status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HardwareInfo {
    pub model: String,
    pub cpu_model: String,
    pub total_ram: String,
    pub disk_size: String,
    pub os_version: String,
    pub refresh_rate: String,
}

/// The trimmed value after `Label:` on the first matching (case-insensitive) line of
/// `system_profiler` output, e.g. `parse_sp_field(out, "Chip")` → "Apple M1 Pro". `None` if absent.
pub fn parse_sp_field(output: &str, label: &str) -> Option<String> {
    let needle = format!("{}:", label.to_lowercase());
    for line in output.lines() {
        if line.to_lowercase().contains(&needle) {
            if let Some((_, value)) = line.split_once(':') {
                let v = value.trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// The integer digger's `parseInt` (`cmd/status/metrics_hardware.go:120`) reads out of a token:
/// non-numeric padding is trimmed from BOTH ends first (anything that is not a digit or `.`), then
/// the leading digit run is the answer — `"60.00"` → 60, `"120hz"` → 120, `"(60hz"` → 60, `""` → 0.
/// `system_profiler` prints a display's mode as `3024 x 1964 @ 60.00Hz` and, for some panels,
/// `(60Hz)`; without the leading trim the parenthesised form read as 0 and the refresh rate went
/// missing.
fn leading_int(s: &str) -> i64 {
    let cleaned = s
        .trim()
        .trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
    cleaned
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// The highest display refresh rate from `system_profiler SPDisplaysDataType` output, formatted like
/// `120Hz` (empty when none found). Handles `@ 60Hz`, `60.00Hz`, and `Refresh Rate: 120 Hz`; ignores
/// implausible values (≥ 500). Ported from digger's `parseRefreshRate`.
pub fn parse_refresh_rate(output: &str) -> String {
    let mut max_hz = 0i64;
    for line in output.lines() {
        let lower = line.to_lowercase();
        if !lower.contains("hz") {
            continue;
        }
        let fields: Vec<&str> = lower.split_whitespace().collect();
        for (i, field) in fields.iter().enumerate() {
            if *field == "hz" && i > 0 {
                let hz = leading_int(fields[i - 1]);
                if hz > max_hz && hz < 500 {
                    max_hz = hz;
                }
            } else if let Some(num) = field.strip_suffix("hz") {
                let num = if num.is_empty() && i > 0 {
                    fields[i - 1]
                } else {
                    num
                };
                let hz = leading_int(num);
                if hz > max_hz && hz < 500 {
                    max_hz = hz;
                }
            }
        }
    }
    if max_hz > 0 {
        format!("{max_hz}Hz")
    } else {
        String::new()
    }
}

/// Assemble hardware info from already-collected command output + sizes. Pure — the model/chip come
/// from `SPHardwareDataType`, the OS from `sw_vers -productVersion`, the refresh rate from
/// `SPDisplaysDataType`. (Chip preferred over Processor Name for Apple-silicon vs Intel.)
pub fn assemble_hardware(
    sp_hardware: &str,
    sw_vers_product: &str,
    sp_displays: &str,
    total_ram: u64,
    root_disk_total: u64,
) -> HardwareInfo {
    let cpu_model = parse_sp_field(sp_hardware, "Chip")
        .or_else(|| parse_sp_field(sp_hardware, "Processor Name"))
        .unwrap_or_default();
    let os = sw_vers_product.trim();
    HardwareInfo {
        model: parse_sp_field(sp_hardware, "Model Name").unwrap_or_default(),
        cpu_model,
        // FIX 4 (RULEBOOK): binary (1024-based), matching digger's `units.BytesBin` — NOT
        // `bytes_si` (1000-based), which is `analyze`'s convention (Finder/diskutil), not status's
        // (Activity Monitor). `bytes_si` here made a 24 GiB machine print "25.8 GB" and a 460.4 GiB
        // disk print "494.4 GB" under the health ring; `str == str` so no gate ever saw it.
        total_ram: if total_ram > 0 {
            bytes_bin(total_ram)
        } else {
            String::new()
        },
        disk_size: if root_disk_total > 0 {
            bytes_bin(root_disk_total)
        } else {
            String::new()
        },
        os_version: if os.is_empty() {
            String::new()
        } else {
            format!("macOS {os}")
        },
        refresh_rate: parse_refresh_rate(sp_displays),
    }
}

/// Collect hardware info by running `system_profiler` + `sw_vers` (macOS only) — [`collect_hardware_with`]
/// over the real, budgeted runner; off macOS nothing is spawned and the object is empty.
pub fn collect_hardware(total_ram: u64, root_disk_total: u64) -> HardwareInfo {
    if !cfg!(target_os = "macos") {
        return HardwareInfo::default();
    }
    collect_hardware_with(
        total_ram,
        root_disk_total,
        &crate::platform::run_command_with_timeout,
    )
}

/// The three probes through `run`, each bounded to the budget digger's own `collectHardware`
/// (`metrics_hardware.go`) uses for it — a wedged `system_profiler` here must degrade this ONE
/// object (already tolerant of empty-string inputs, see the tests below) rather than hang the
/// whole `status` command. Injected so the argv, the budgets and the assembly are pinned by a fake.
pub fn collect_hardware_with(
    total_ram: u64,
    root_disk_total: u64,
    run: crate::platform::TimedRunner<'_>,
) -> HardwareInfo {
    // 3s, matching `metrics_hardware.go:24`.
    let sp_hw = run(
        "system_profiler",
        &["SPHardwareDataType"],
        Duration::from_secs(3),
    )
    .unwrap_or_default();
    // 1s, matching `metrics_hardware.go:55`.
    let sw_vers = run("sw_vers", &["-productVersion"], Duration::from_secs(1)).unwrap_or_default();
    // 2s, matching `metrics_hardware.go:63` — a DIFFERENT `system_profiler` invocation (mini detail
    // level, for refresh rate only) than the one `status::collect::collect_gpu` uses (full `-json`,
    // 4s), so it gets its own, shorter budget rather than sharing that one.
    let sp_disp = run(
        "system_profiler",
        &["-detailLevel", "mini", "SPDisplaysDataType"],
        Duration::from_secs(2),
    )
    .unwrap_or_default();
    assemble_hardware(&sp_hw, &sw_vers, &sp_disp, total_ram, root_disk_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sp_field_reads_labelled_value() {
        let out = "      Model Name: MacBook Pro\n      Model Identifier: Mac14,7\n      Chip: Apple M2\n";
        assert_eq!(
            parse_sp_field(out, "Model Name").as_deref(),
            Some("MacBook Pro")
        );
        assert_eq!(parse_sp_field(out, "Chip").as_deref(), Some("Apple M2"));
        assert_eq!(parse_sp_field(out, "Nonexistent"), None);
    }

    /// Go's `parseInt` trims non-numeric padding from both ends before reading the digits; the
    /// port only read from the front, so a parenthesised rate — which `system_profiler` does print —
    /// parsed as 0.
    #[test]
    fn leading_int_trims_padding_on_both_ends_like_the_oracles_parse_int() {
        assert_eq!(leading_int("(60hz"), 60);
        assert_eq!(leading_int("(60"), 60);
        assert_eq!(leading_int("60.00"), 60);
        assert_eq!(leading_int("120hz"), 120);
        assert_eq!(leading_int("  144  "), 144);
        assert_eq!(leading_int(""), 0);
        assert_eq!(leading_int("hz"), 0);
        assert_eq!(
            leading_int(".5"),
            0,
            "Sscanf %d reads no digits before the dot"
        );
        // Through the line parser, the same way Go reaches `parseInt`: a token that still ends
        // in `hz` after the padding, and a bare `hz` token preceded by a padded number.
        assert_eq!(
            parse_refresh_rate("Resolution: 2560 x 1440 @ (60Hz"),
            "60Hz"
        );
        assert_eq!(parse_refresh_rate("Refresh Rate: (120 Hz"), "120Hz");
    }

    #[test]
    fn refresh_rate_picks_the_highest_plausible() {
        assert_eq!(
            parse_refresh_rate("Resolution: 3024 x 1964 @ 120.00Hz"),
            "120Hz"
        );
        assert_eq!(parse_refresh_rate("Refresh Rate: 60 Hz"), "60Hz");
        // Two displays → the higher wins; an implausible 1000Hz is ignored.
        assert_eq!(
            parse_refresh_rate("x @ 60Hz\ny @ 144Hz\nz @ 1000Hz"),
            "144Hz"
        );
        assert_eq!(parse_refresh_rate("no rate here"), "");
    }

    #[test]
    fn assembles_with_chip_preferred_and_os_prefix() {
        let hw = "  Model Name: Mac mini\n  Chip: Apple M2 Pro\n  Processor Name: Intel Core i7\n";
        let info = assemble_hardware(hw, "14.5\n", "@ 60Hz", 17_179_869_184, 494_384_795_648);
        assert_eq!(info.model, "Mac mini");
        assert_eq!(info.cpu_model, "Apple M2 Pro"); // Chip beats Processor Name
        assert_eq!(info.os_version, "macOS 14.5");
        assert_eq!(info.refresh_rate, "60Hz");
        assert!(info.total_ram.ends_with("GB"));
        assert!(info.disk_size.ends_with("GB"));
    }

    #[test]
    fn assemble_falls_back_to_processor_name_and_blank_os() {
        let hw = "  Processor Name: Intel Core i7\n";
        let info = assemble_hardware(hw, "", "", 0, 0);
        assert_eq!(info.cpu_model, "Intel Core i7");
        assert_eq!(info.os_version, "");
        assert_eq!(info.total_ram, "");
    }

    #[test]
    fn ram_and_disk_size_use_binary_units_matching_the_oracle_not_si() {
        // FIX 4 (RULEBOOK), anchored to the live oracle comparison recorded there: a real 24 GiB
        // machine reads "24.0 GB" from the oracle (binary/1024-based, Activity Monitor's
        // convention) and misread "25.8 GB" from this engine pre-fix (SI/1000-based, `bytes_si` —
        // `analyze`'s convention, not status's). 24 GiB = 24 * 1024^3 bytes exactly.
        let info = assemble_hardware("", "", "", 24u64 * (1 << 30), 0);
        assert_eq!(info.total_ram, "24.0 GB", "binary GiB, not the SI 25.8 GB");

        // Same live comparison's disk figure: the oracle's "460.4 GB" against this engine's
        // pre-fix "494.4 GB" — both computed from the SAME 494_384_795_648-byte total (the exact
        // root-disk total already used elsewhere in this module's disk.rs fixtures), just SI vs
        // binary division.
        let info = assemble_hardware("", "", "", 0, 494_384_795_648);
        assert_eq!(
            info.disk_size, "460.4 GB",
            "binary GiB, not the SI 494.4 GB"
        );
    }
    /// The collector over a fake runner: the three probes, their argv and digger's budgets, and
    /// the assembly of what they returned — on every platform, without a `system_profiler`.
    #[test]
    fn collect_hardware_with_runs_the_three_budgeted_probes_and_assembles_them() {
        let sp_hw = "      Model Name: MacBook Pro\n      Chip: Apple M2\n";
        let sw_vers = "14.5\n";
        let sp_disp = "          Resolution: 3024 x 1964 Retina\n          UI Looks like: 1512 x 982 @ 120.00Hz\n";
        let calls = std::cell::RefCell::new(Vec::new());
        let run = |p: &str, a: &[&str], t: Duration| -> Option<String> {
            calls.borrow_mut().push((p.to_string(), a.join(" "), t));
            match (p, a.first().copied()) {
                ("system_profiler", Some("SPHardwareDataType")) => Some(sp_hw.into()),
                ("sw_vers", _) => Some(sw_vers.into()),
                ("system_profiler", Some("-detailLevel")) => Some(sp_disp.into()),
                _ => None,
            }
        };
        let got = collect_hardware_with(16, 512, &run);
        assert_eq!(
            got,
            assemble_hardware(sp_hw, sw_vers, sp_disp, 16, 512),
            "the runner's outputs reach the assembler unchanged"
        );
        assert_eq!(
            calls.borrow().as_slice(),
            [
                (
                    "system_profiler".to_string(),
                    "SPHardwareDataType".to_string(),
                    Duration::from_secs(3)
                ),
                (
                    "sw_vers".to_string(),
                    "-productVersion".to_string(),
                    Duration::from_secs(1)
                ),
                (
                    "system_profiler".to_string(),
                    "-detailLevel mini SPDisplaysDataType".to_string(),
                    Duration::from_secs(2)
                ),
            ]
        );
        // A probe that fails degrades its fields only.
        let none = |_: &str, _: &[&str], _: Duration| -> Option<String> { None };
        assert_eq!(
            collect_hardware_with(16, 512, &none),
            assemble_hardware("", "", "", 16, 512)
        );
    }
}
