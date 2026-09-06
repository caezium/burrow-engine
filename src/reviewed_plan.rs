//! Shared input boundary for exact purge and installer plans. Candidate classification remains
//! in each command; a path list never grants permission to remove an arbitrary filesystem entry.

use std::path::{Component, Path, PathBuf};

pub(crate) fn read_paths(file: &str) -> Result<Vec<String>, String> {
    use std::io::Read;
    const MAX_BYTES: u64 = 8 * 1024 * 1024;
    let unreadable = |error| format!("plan file not found or unreadable: {file} ({error})");
    let before = std::fs::symlink_metadata(file).map_err(unreadable)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err("plan source must be a regular file, not a symbolic link".into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux and BSD/Darwin use different O_NOFOLLOW/O_NONBLOCK values. Nonblocking open
        // closes the lstat-to-open FIFO replacement race; fstat below still requires a file.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let flags = 0x20000 | 0x800;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let flags = 0x100 | 0x4;
        options.custom_flags(flags);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let input = options.open(file).map_err(unreadable)?;
    let metadata = input.metadata().map_err(unreadable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("plan source must be a regular file, not a symbolic link".into());
    }
    if metadata.len() > MAX_BYTES {
        return Err("plan exceeds the 8 MiB byte limit".into());
    }
    let mut text = String::new();
    input
        .take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    if text.len() as u64 > MAX_BYTES {
        return Err("plan exceeds the 8 MiB byte limit".into());
    }
    let mut paths = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let path = Path::new(line);
        if !path.is_absolute()
            || line.chars().any(char::is_control)
            || path.components().any(|c| matches!(c, Component::ParentDir))
        {
            return Err("plan contains an invalid absolute path".into());
        }
        if seen.insert(line) {
            paths.push(line.to_string());
        }
        if paths.len() > 4096 {
            return Err("plan contains more than 4096 paths".into());
        }
    }
    if paths.is_empty() {
        return Err("plan contains no paths".into());
    }
    Ok(paths)
}

/// The scan walks real directory entries below each root and never follows a symlinked child.
/// Repeat that namespace check at apply so a renamed parent cannot redirect a reviewed path.
pub(crate) fn relative_components(path: &Path, root: &Path) -> Option<Vec<PathBuf>> {
    if !path.is_absolute() || !root.is_absolute() {
        return None;
    }
    let relative = path.strip_prefix(root).ok()?;
    let components: Option<Vec<_>> = relative
        .components()
        .map(|part| match part {
            Component::Normal(name) => Some(PathBuf::from(name)),
            _ => None,
        })
        .collect();
    let components = components?;
    if components.is_empty() {
        return None;
    }
    let mut current = root.to_path_buf();
    for part in &components {
        current.push(part);
        if std::fs::symlink_metadata(&current)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return None;
        }
    }
    Some(components)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_source_refuses_oversized_and_nonregular_files() {
        let root = std::env::temp_dir().join(format!("burrow_plan_source_{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("large.plan");
        std::fs::File::create(&file)
            .unwrap()
            .set_len(8 * 1024 * 1024 + 1)
            .unwrap();
        assert!(read_paths(file.to_str().unwrap())
            .unwrap_err()
            .contains("8 MiB"));
        assert!(read_paths(root.to_str().unwrap())
            .unwrap_err()
            .contains("regular file"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let alias = root.join("alias.plan");
            symlink(&file, &alias).unwrap();
            assert!(read_paths(alias.to_str().unwrap())
                .unwrap_err()
                .contains("regular file"));
            let fifo = root.join("pipe.plan");
            let output = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .output()
                .unwrap();
            assert!(output.status.success());
            let start = std::time::Instant::now();
            assert!(read_paths(fifo.to_str().unwrap())
                .unwrap_err()
                .contains("regular file"));
            assert!(start.elapsed() < std::time::Duration::from_secs(1));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn configured_root_alias_is_supported_but_child_alias_is_refused() {
        let root = std::env::temp_dir().join(format!("burrow_plan_roots_{}", std::process::id()));
        let real = root.join("real");
        std::fs::create_dir_all(real.join("project/target")).unwrap();
        let alias = root.join("configured");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert!(relative_components(&alias.join("project/target"), &alias).is_some());
        std::os::unix::fs::symlink(real.join("project"), alias.join("child-alias")).unwrap();
        assert!(relative_components(&alias.join("child-alias/target"), &alias).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_input_preserves_spaces_and_refuses_empty_relative_and_parent_paths() {
        let file =
            std::env::temp_dir().join(format!("burrow_reviewed_plan_{}", std::process::id()));
        let path = std::env::temp_dir()
            .join("reviewed item ")
            .to_string_lossy()
            .into_owned();
        std::fs::write(&file, format!("# plan\n{path}\n{path}\n")).unwrap();
        assert_eq!(read_paths(file.to_str().unwrap()).unwrap(), vec![path]);
        for bad in ["# empty\n", "relative/item\n", "/a/../b\n", "/a\tb\n"] {
            std::fs::write(&file, bad).unwrap();
            assert!(read_paths(file.to_str().unwrap()).is_err(), "{bad:?}");
        }
        std::fs::remove_file(file).unwrap();
    }
}
