//! Mach-O universal ("fat") binary analysis — the engine port of app-slim's read-only core.
//!
//! Pure byte parsing of the fat header (big-endian), so it's fully testable without any macOS
//! framework. Reports the architecture slices and how much a thin-to-host-arch would save. The
//! actual thinning (rewrite + ad-hoc re-sign) is the deferred write step; the engine's
//! `slim-check` command is read-only.

pub const CPU_ARM64: i32 = 0x0100_000C;
pub const CPU_X86_64: i32 = 0x0100_0007;

const FAT_MAGIC: u32 = 0xCAFE_BABE; // 32-bit fat
const FAT_MAGIC_64: u32 = 0xCAFE_BABF; // 64-bit fat

/// One architecture slice of a fat Mach-O binary.
#[derive(Debug, PartialEq, Eq)]
pub struct ArchSlice {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u64,
    pub size: u64,
}

fn be_u32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn be_u64(b: &[u8], i: usize) -> u64 {
    u64::from_be_bytes([
        b[i],
        b[i + 1],
        b[i + 2],
        b[i + 3],
        b[i + 4],
        b[i + 5],
        b[i + 6],
        b[i + 7],
    ])
}

/// Parse a fat Mach-O header into its architecture slices. Errors if the bytes are not a fat
/// Mach-O (e.g. a thin single-arch binary or a non-Mach-O file).
pub fn parse_fat(bytes: &[u8]) -> Result<Vec<ArchSlice>, String> {
    if bytes.len() < 8 {
        return Err("too short for a fat header".into());
    }
    let is64 = match be_u32(bytes, 0) {
        FAT_MAGIC => false,
        FAT_MAGIC_64 => true,
        _ => return Err("not a fat Mach-O (thin binary or non-Mach-O)".into()),
    };
    let n = be_u32(bytes, 4) as usize;
    if n > 64 {
        return Err(format!("implausible arch count {n}"));
    }
    let mut slices = Vec::with_capacity(n);
    let mut off = 8usize;
    for _ in 0..n {
        if is64 {
            if off + 32 > bytes.len() {
                return Err("truncated fat_arch_64".into());
            }
            slices.push(ArchSlice {
                cputype: be_u32(bytes, off) as i32,
                cpusubtype: be_u32(bytes, off + 4) as i32,
                offset: be_u64(bytes, off + 8),
                size: be_u64(bytes, off + 16),
            });
            off += 32;
        } else {
            if off + 20 > bytes.len() {
                return Err("truncated fat_arch".into());
            }
            slices.push(ArchSlice {
                cputype: be_u32(bytes, off) as i32,
                cpusubtype: be_u32(bytes, off + 4) as i32,
                offset: be_u32(bytes, off + 8) as u64,
                size: be_u32(bytes, off + 12) as u64,
            });
            off += 20;
        }
    }
    let mut total = 0u64;
    for slice in &slices {
        slice
            .offset
            .checked_add(slice.size)
            .ok_or("fat architecture extent overflows")?;
        total = total
            .checked_add(slice.size)
            .ok_or("fat architecture sizes overflow")?;
    }
    Ok(slices)
}

/// Bytes reclaimable by keeping only `keep` cputype. 0 if `keep` is absent (keep everything).
pub fn slim_savings(slices: &[ArchSlice], keep: i32) -> u64 {
    if !slices.iter().any(|s| s.cputype == keep) {
        return 0;
    }
    slices
        .iter()
        .filter(|s| s.cputype != keep)
        .fold(0, |total, s| total.saturating_add(s.size))
}

/// The host CPU type (slice to keep when slimming on this machine).
pub fn host_cputype() -> i32 {
    if cfg!(target_arch = "aarch64") {
        CPU_ARM64
    } else {
        CPU_X86_64
    }
}

/// Serialize the read-only slim-check report to JSON (zero-dep):
/// `{path,arch_count,host_keep_cputype,potential_savings_bytes,slices:[{cputype,cpusubtype,offset,size}]}`.
pub fn slim_check_json(path: &str, slices: &[ArchSlice]) -> String {
    use crate::json::escape as esc;
    let keep = host_cputype();
    let items = slices
        .iter()
        .map(|s| {
            format!(
                "{{\"cputype\":{},\"cpusubtype\":{},\"offset\":{},\"size\":{}}}",
                s.cputype, s.cpusubtype, s.offset, s.size
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"path\":{},\"arch_count\":{},\"host_keep_cputype\":{},\"potential_savings_bytes\":{},\"slices\":[{}]}}",
        esc(path),
        slices.len(),
        keep,
        slim_savings(slices, keep),
        items
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 32-bit fat header with the given (cputype, size) arches.
    fn fat32(arches: &[(i32, u32)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        b.extend_from_slice(&(arches.len() as u32).to_be_bytes());
        for (i, (ct, size)) in arches.iter().enumerate() {
            b.extend_from_slice(&(*ct as u32).to_be_bytes()); // cputype
            b.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
            b.extend_from_slice(&((0x1000 * (i as u32 + 1)).to_be_bytes())); // offset
            b.extend_from_slice(&size.to_be_bytes()); // size
            b.extend_from_slice(&14u32.to_be_bytes()); // align
        }
        b
    }

    #[test]
    fn parses_two_arch_fat() {
        let bytes = fat32(&[(CPU_ARM64, 5000), (CPU_X86_64, 3000)]);
        let slices = parse_fat(&bytes).unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].cputype, CPU_ARM64);
        assert_eq!(slices[0].size, 5000);
        assert_eq!(slices[1].cputype, CPU_X86_64);
        assert_eq!(slices[1].size, 3000);
    }

    #[test]
    fn savings_keeps_host_drops_rest() {
        let slices = parse_fat(&fat32(&[(CPU_ARM64, 5000), (CPU_X86_64, 3000)])).unwrap();
        assert_eq!(slim_savings(&slices, CPU_ARM64), 3000); // drop x86_64
        assert_eq!(slim_savings(&slices, CPU_X86_64), 5000); // drop arm64
    }

    #[test]
    fn savings_zero_when_keep_absent() {
        let slices = parse_fat(&fat32(&[(CPU_ARM64, 5000)])).unwrap();
        assert_eq!(slim_savings(&slices, CPU_X86_64), 0); // would-keep arch not present
    }

    #[test]
    fn thin_binary_is_not_fat() {
        // 0xFEEDFACF = thin 64-bit Mach-O magic
        let mut b = 0xFEED_FACFu32.to_be_bytes().to_vec();
        b.extend_from_slice(&[0u8; 8]);
        assert!(parse_fat(&b).is_err());
    }

    #[test]
    fn slim_check_json_shape() {
        let slices = parse_fat(&fat32(&[(CPU_ARM64, 5000)])).unwrap();
        let j = slim_check_json("/bin/foo", &slices);
        assert!(j.contains("\"path\":\"/bin/foo\""));
        assert!(j.contains("\"arch_count\":1"));
        assert!(j.contains("\"slices\":[{\"cputype\":16777228,"));
    }
}
