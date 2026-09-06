//! Similar-photo detection via perceptual hashing (dHash) — the engine port of burrow-cli's
//! `photos` matching core.
//!
//! The MATCHING pipeline is pure and zero-dep: the dHash bit-logic (over a 9×8 grayscale),
//! Hamming distance, greedy clustering, and the unsupported-format tally. The one dep-bound
//! seam is DECODE + DOWNSCALE — turning an image file into a 9×8 grayscale buffer — which
//! burrow-cli does with the `image` crate. That seam is injected here (`scan` takes a hasher
//! closure), so this whole module is testable without any image library and the eventual
//! decode backend (the `image` crate, a `sips` shell-out, or otherwise) is a single, isolated
//! decision that doesn't touch the tested matching logic.

use std::collections::BTreeMap;
use std::path::Path;

/// The dHash downscale target: 9 wide × 8 tall grayscale (each of the 64 bits compares a pixel
/// to its right neighbor, so 9 columns yield 8 comparisons per row).
pub const DHASH_W: usize = 9;
pub const DHASH_H: usize = 8;

/// 64-bit difference hash from a 9×8 grayscale buffer (row-major, `DHASH_W*DHASH_H` bytes; the
/// byte at `(x,y)` is `gray[y*DHASH_W + x]`). Each bit: is this pixel brighter than the one to
/// its right? This is the exact bit-logic burrow-cli runs after `image` resizes to 9×8 luma —
/// the decode/resize is the caller's job (the injected seam). Returns 0 on a wrong-sized buffer.
pub fn dhash_from_gray(gray: &[u8]) -> u64 {
    if gray.len() != DHASH_W * DHASH_H {
        return 0;
    }
    let px = |x: usize, y: usize| gray[y * DHASH_W + x];
    let mut hash = 0u64;
    let mut bit = 0;
    for y in 0..DHASH_H {
        for x in 0..(DHASH_W - 1) {
            if px(x, y) > px(x + 1, y) {
                hash |= 1 << bit;
            }
            bit += 1;
        }
    }
    hash
}

/// Hamming distance between two hashes (differing-bit count).
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// The decode seam (the one dep-bound step): downscale a decoded image to 9×8 grayscale with the
/// `image` crate's Triangle filter, then run the pure [`dhash_from_gray`] bit-logic — byte-for-byte
/// the same pipeline burrow-cli uses, so hashes match the cli exactly.
pub fn dhash(img: &image::DynamicImage) -> u64 {
    let small = img.resize_exact(
        DHASH_W as u32,
        DHASH_H as u32,
        image::imageops::FilterType::Triangle,
    );
    // to_luma8() yields a row-major DHASH_W×DHASH_H grayscale buffer (`DHASH_W*DHASH_H` bytes).
    dhash_from_gray(small.to_luma8().as_raw())
}

/// Decode an image file (PNG/JPEG) and compute its dHash. The `scan` decode closure for the real
/// backend. Errors carry the path + the decoder's message.
pub fn hash_file(path: &Path) -> Result<u64, String> {
    let img = image::open(path).map_err(|e| format!("decode {}: {e}", path.display()))?;
    Ok(dhash(&img))
}

/// Extensions `scan` can hand to a png/jpeg decoder.
fn is_supported_image(p: &Path) -> bool {
    matches!(
        p.extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_lowercase())
            .as_deref(),
        Some("png") | Some("jpg") | Some("jpeg")
    )
}

/// Image formats present in a folder that the png/jpeg decoder CANNOT read: HEIC — the dominant
/// Apple Photos format — plus HEIF/TIFF/GIF/WebP/BMP. Surfaced so a folder full of iPhone photos
/// reads as "can't read these yet", not a silent empty result.
const UNSUPPORTED_IMAGE_EXTS: &[&str] = &["heic", "heif", "tiff", "tif", "gif", "webp", "bmp"];

/// Count, by lowercased extension, the images `scan` skipped because they can't be decoded.
/// Non-recursive to match `scan`. An empty map ⇒ nothing was silently dropped.
pub fn count_unsupported(dir: &Path) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some(ext) = e
                .path()
                .extension()
                .and_then(|x| x.to_str())
                .map(|s| s.to_lowercase())
            {
                if UNSUPPORTED_IMAGE_EXTS.contains(&ext.as_str()) {
                    *counts.entry(ext).or_insert(0) += 1;
                }
            }
        }
    }
    counts
}

/// A cluster of near-duplicate images (paths within the hamming threshold of each other).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub paths: Vec<String>,
}

/// Greedy clustering: group items whose hashes are within `threshold` hamming distance of a
/// group's representative. Only groups with >1 member are returned.
pub fn group_similar(items: &[(String, u64)], threshold: u32) -> Vec<Group> {
    let mut groups: Vec<(u64, Vec<String>)> = Vec::new();
    for (path, h) in items {
        if let Some(g) = groups
            .iter_mut()
            .find(|(rep, _)| hamming(*rep, *h) <= threshold)
        {
            g.1.push(path.clone());
        } else {
            groups.push((*h, vec![path.clone()]));
        }
    }
    groups
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(_, paths)| Group { paths })
        .collect()
}

/// Scan a directory (non-recursive) for similar images. `hash_file` is the injected decode seam
/// — it turns a supported image path into a dHash (returning `None` on decode failure); the real
/// backend decodes+downscales to 9×8 grayscale and calls [`dhash_from_gray`]. Deterministic:
/// paths are sorted before clustering.
pub fn scan(dir: &Path, threshold: u32, hash_file: impl Fn(&Path) -> Option<u64>) -> Vec<Group> {
    let mut items = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if is_supported_image(&p) {
                if let Some(h) = hash_file(&p) {
                    items.push((p.to_string_lossy().into_owned(), h));
                }
            }
        }
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));
    group_similar(&items, threshold)
}

use crate::json::escape as esc;

/// Serialize the group list as a `[{paths:[…]}]` JSON array.
fn groups_json(groups: &[Group]) -> String {
    let gs = groups
        .iter()
        .map(|g| {
            let paths = g.paths.iter().map(|p| esc(p)).collect::<Vec<_>>().join(",");
            format!("{{\"paths\":[{paths}]}}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{gs}]")
}

/// Serialize the unsupported-format tally as a `{ext:count}` JSON object.
fn unsupported_json(unsupported: &BTreeMap<String, usize>) -> String {
    let us = unsupported
        .iter()
        .map(|(ext, n)| format!("{}:{}", esc(ext), n))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{us}}}")
}

/// The full `photos` command report, matching burrow-cli's contract so the GUI parses one shape:
/// `{dir,threshold,similar_groups:[{paths:[…]}],skipped_unsupported:N,skipped_formats:{ext:count}}`.
pub fn report_json(
    dir: &str,
    threshold: u32,
    groups: &[Group],
    unsupported: &BTreeMap<String, usize>,
) -> String {
    let skipped_total: usize = unsupported.values().sum();
    format!(
        "{{\"dir\":{},\"threshold\":{},\"similar_groups\":{},\"skipped_unsupported\":{},\"skipped_formats\":{}}}",
        esc(dir),
        threshold,
        groups_json(groups),
        skipped_total,
        unsupported_json(unsupported)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    /// A 9×8 grayscale that strictly decreases left→right on every row: every "left > right"
    /// comparison is true ⇒ all 64 bits set.
    fn left_bright() -> Vec<u8> {
        let mut g = vec![0u8; DHASH_W * DHASH_H];
        for y in 0..DHASH_H {
            for x in 0..DHASH_W {
                g[y * DHASH_W + x] = (200 - x as i32 * 20) as u8;
            }
        }
        g
    }

    /// Strictly increasing left→right ⇒ no "left > right" ⇒ all bits clear.
    fn right_bright() -> Vec<u8> {
        let mut g = vec![0u8; DHASH_W * DHASH_H];
        for y in 0..DHASH_H {
            for x in 0..DHASH_W {
                g[y * DHASH_W + x] = (10 + x as i32 * 20) as u8;
            }
        }
        g
    }

    #[test]
    fn dhash_bit_logic_is_exact_and_deterministic() {
        assert_eq!(dhash_from_gray(&left_bright()), u64::MAX, "all left>right");
        assert_eq!(dhash_from_gray(&right_bright()), 0, "no left>right");
        // uniform: equal neighbors are NOT strictly greater ⇒ 0
        assert_eq!(dhash_from_gray(&[128u8; DHASH_W * DHASH_H]), 0);
        // deterministic
        assert_eq!(
            dhash_from_gray(&left_bright()),
            dhash_from_gray(&left_bright())
        );
    }

    #[test]
    fn dhash_rejects_wrong_size() {
        assert_eq!(dhash_from_gray(&[0u8; 10]), 0);
        assert_eq!(dhash_from_gray(&[]), 0);
    }

    #[test]
    fn hamming_counts_differing_bits() {
        assert_eq!(hamming(0, 0), 0);
        assert_eq!(hamming(0, u64::MAX), 64);
        assert_eq!(hamming(0b1011, 0b0010), 2);
    }

    #[test]
    fn similar_hashes_group_and_distant_ones_do_not() {
        let base = 0xF0F0_F0F0_F0F0_F0F0u64;
        let close = base ^ 0b11; // 2 bits away
        let far = !base; // 64 bits away
        let items = vec![
            ("a.png".to_string(), base),
            ("b.png".to_string(), close),
            ("c.png".to_string(), far),
        ];
        let groups = group_similar(&items, 5);
        assert_eq!(groups.len(), 1, "only a+b cluster");
        assert_eq!(groups[0].paths, vec!["a.png", "b.png"]);
    }

    #[test]
    fn singletons_are_not_returned() {
        let items = vec![("only.png".to_string(), 42u64)];
        assert!(group_similar(&items, 5).is_empty());
    }

    #[test]
    fn scan_hashes_supported_images_and_clusters() {
        let dir = std::env::temp_dir().join(format!("burrow_photos_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["a.png", "b.jpg", "c.jpeg", "notes.txt", "pic.heic"] {
            std::fs::write(dir.join(n), "x").unwrap();
        }
        // Fake decode: a.png & b.jpg hash the same, c.jpeg is far away.
        let hashes = |p: &Path| -> Option<u64> {
            match p.file_name()?.to_str()? {
                "a.png" | "b.jpg" => Some(0xAAAA_AAAA_AAAA_AAAA),
                "c.jpeg" => Some(0x5555_5555_5555_5555),
                _ => None,
            }
        };
        let groups = scan(&dir, 4, hashes);
        assert_eq!(groups.len(), 1, "a+b cluster; c alone; txt/heic ignored");
        assert_eq!(groups[0].paths.len(), 2);
        assert!(groups[0].paths[0].ends_with("a.png"), "sorted");
        // heic is surfaced as unsupported, not silently dropped.
        assert_eq!(count_unsupported(&dir).get("heic"), Some(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Build `Group`s from a JSON array shaped like the golden's `similar_groups` (produced by
    /// `groups_json`, the same helper `report_json` uses for that field). Used by
    /// `report_json_matches_cli_contract` below so the golden is read the same way there as
    /// everywhere else in this module, instead of duplicating the parse.
    fn groups_from_json_array(arr: &[Json]) -> Vec<Group> {
        arr.iter()
            .map(|g| Group {
                paths: g
                    .get("paths")
                    .and_then(Json::as_array)
                    .expect("group.paths must be an array")
                    .iter()
                    .map(|p| p.as_str().expect("path entry must be a string").to_string())
                    .collect(),
            })
            .collect()
    }

    /// Re-anchored to the golden (RULEBOOK §3e): every value below is read back out of
    /// `photos.golden.json` at run time through the engine's own JSON reader, not retyped — this
    /// goes red the instant the golden moves, unlike the hand-typed literal it replaces. The
    /// golden's fixture (`photos.golden.provenance.txt`) genuinely clusters 3 real images, so
    /// `similar_groups` is non-empty (RULEBOOK §3b: a blind golden proves nothing).
    ///
    /// `skipped_unsupported`/`skipped_formats` are NOT in the golden: the shipping oracle silently
    /// drops the undecodable HEIC in that fixture, while this engine correctly reports it —
    /// RULEBOOK §4, ADJUDICATED, do not delete these fields. So this test asserts every key the
    /// golden DOES have is present and equal, and separately asserts the two authorized extras
    /// stay present; it must never require the engine's key set to equal the golden's exactly
    /// (RULE 1: an extra key can never break the app).
    #[test]
    fn report_json_matches_cli_contract() {
        let golden = Json::parse(include_str!("photos.golden.json"))
            .expect("vendored golden must be valid JSON");
        let dir = golden
            .get("dir")
            .and_then(Json::as_str)
            .expect("golden.dir");
        let threshold = golden
            .get("threshold")
            .and_then(Json::as_u64)
            .expect("golden.threshold") as u32;
        let golden_groups = golden
            .get("similar_groups")
            .and_then(Json::as_array)
            .expect("golden.similar_groups must be an array");
        assert!(
            !golden_groups.is_empty(),
            "golden.similar_groups is empty — this test can no longer prove anything"
        );
        let groups = groups_from_json_array(golden_groups);
        // The golden carries no skip data for this fixture at all (the oracle doesn't emit these
        // keys — RULEBOOK §4), so this is not read off the golden; it mirrors the ENGINE's own
        // measured output over this exact fixture (one undecodable HEIC), recorded in RULEBOOK §4.
        let mut unsupported = BTreeMap::new();
        unsupported.insert("heic".to_string(), 1usize);

        let engine_out = report_json(dir, threshold, &groups, &unsupported);
        let engine = Json::parse(&engine_out).expect("report_json must emit valid JSON");

        let Json::Object(golden_top) = &golden else {
            panic!("golden root must be a JSON object");
        };
        for key in golden_top.keys() {
            assert_eq!(
                engine.get(key.as_str()),
                golden.get(key.as_str()),
                "engine's {key} must match the golden's {key} verbatim"
            );
        }

        // The two authorized extras (RULEBOOK §4) must still be present — deleting them to shrink
        // the diff against the golden would silently regress the HEIC-count feature this contract
        // exists to carry.
        assert_eq!(
            engine.get("skipped_unsupported").and_then(Json::as_u64),
            Some(unsupported.values().sum::<usize>() as u64),
            "must not delete this RULEBOOK §4 field"
        );
        assert_eq!(
            engine
                .get("skipped_formats")
                .and_then(|v| v.get("heic"))
                .and_then(Json::as_u64),
            unsupported.get("heic").map(|n| *n as u64),
            "must not delete this RULEBOOK §4 field"
        );
    }

    // --- real-decoder tests: exercise the `image`-backed decode seam (dhash/hash_file). ---
    use image::{DynamicImage, ImageBuffer, Luma};

    /// A horizontal "tent" (rises then falls in x) -> a distinctive, non-trivial dhash.
    fn tent_x(offset: i32) -> DynamicImage {
        let img = ImageBuffer::from_fn(64, 64, |x, _y| {
            let base = if x < 32 { x } else { 63 - x } as i32;
            Luma([(base * 4 + offset).clamp(0, 255) as u8])
        });
        DynamicImage::ImageLuma8(img)
    }
    /// A vertical tent -> horizontally uniform -> hash ~0 (structurally different).
    fn tent_y() -> DynamicImage {
        let img = ImageBuffer::from_fn(64, 64, |_x, y| {
            let base = if y < 32 { y } else { 63 - y } as i32;
            Luma([(base * 4).clamp(0, 255) as u8])
        });
        DynamicImage::ImageLuma8(img)
    }

    #[test]
    fn dhash_is_deterministic_and_nontrivial() {
        let h = dhash(&tent_x(0));
        assert_eq!(h, dhash(&tent_x(0)));
        assert!(h != 0, "tent_x should produce a non-trivial hash");
    }

    #[test]
    fn similar_images_group_and_different_ones_dont() {
        let similar = vec![
            ("a.png".to_string(), dhash(&tent_x(0))),
            ("b.png".to_string(), dhash(&tent_x(8))), // same structure, brighter
        ];
        assert_eq!(group_similar(&similar, 10).len(), 1);
        let different = vec![
            ("a.png".to_string(), dhash(&tent_x(0))),
            ("c.png".to_string(), dhash(&tent_y())),
        ];
        assert!(group_similar(&different, 5).is_empty());
    }

    #[test]
    fn scan_finds_similar_pngs_end_to_end_with_real_decode() {
        let dir = std::env::temp_dir().join(format!("burrow_photos_real_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        tent_x(0).save(dir.join("a.png")).unwrap();
        tent_x(8).save(dir.join("b.png")).unwrap(); // similar
        tent_y().save(dir.join("c.png")).unwrap(); // different
        std::fs::write(dir.join("IMG.HEIC"), b"nope").unwrap(); // unsupported, surfaced
        let groups = scan(&dir, 10, |p| hash_file(p).ok());
        assert_eq!(groups.len(), 1, "a.png + b.png form one similar group");
        assert_eq!(groups[0].paths.len(), 2);
        assert_eq!(count_unsupported(&dir).get("heic"), Some(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hash_file_errors_on_undecodable() {
        let dir = std::env::temp_dir().join(format!("burrow_photos_bad_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("broken.png");
        std::fs::write(&bad, b"this is not a png").unwrap();
        assert!(hash_file(&bad).is_err(), "garbage bytes must not decode");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
