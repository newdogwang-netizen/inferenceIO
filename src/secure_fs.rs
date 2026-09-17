use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};

pub fn open_regular_read(path: &Path) -> io::Result<File> {
    open_regular(path, OFlag::O_RDONLY, Mode::empty())
}

pub fn open_regular_read_write(path: &Path) -> io::Result<File> {
    open_regular(path, OFlag::O_RDWR, Mode::empty())
}

pub fn open_regular_append_create(path: &Path) -> io::Result<File> {
    open_regular(
        path,
        OFlag::O_RDWR | OFlag::O_APPEND | OFlag::O_CREAT,
        Mode::from_bits_truncate(0o600),
    )
}

pub fn open_regular_create(path: &Path) -> io::Result<File> {
    open_regular(
        path,
        OFlag::O_RDWR | OFlag::O_CREAT,
        Mode::from_bits_truncate(0o600),
    )
}

pub fn read_regular_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_read(path)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the {limit}-byte limit: {}", path.display()),
        ));
    }
    Ok(bytes)
}

pub fn read_regular_prefix(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_regular_read(path)?;
    let mut bytes = Vec::with_capacity(limit);
    file.take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Atomically publish one temporary child without replacing an existing
/// destination. Both paths must be direct children of the already-openable
/// parent directory.
pub fn commit_path_noreplace(parent: &Path, temporary: &Path, output: &Path) -> io::Result<()> {
    let temporary_name = direct_child_name(parent, temporary, "temporary")?;
    let output_name = direct_child_name(parent, output, "output")?;

    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::{RenameFlags, renameat2};

        let directory = File::open(parent)?;
        renameat2(
            &directory,
            Path::new(temporary_name),
            &directory,
            Path::new(output_name),
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(io::Error::other)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let metadata = std::fs::symlink_metadata(temporary)?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic no-replace directory publication requires Linux renameat2",
            ));
        }
        std::fs::hard_link(temporary, output)?;
        std::fs::remove_file(temporary)
    }
}

fn direct_child_name<'a>(
    parent: &Path,
    path: &'a Path,
    label: &str,
) -> io::Result<&'a std::ffi::OsStr> {
    if path.parent() != Some(parent) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path must be a direct child of the commit directory"),
        ));
    }
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path has no file name"),
        )
    })
}

fn open_regular(path: &Path, access: OFlag, mode: Mode) -> io::Result<File> {
    let descriptor = open(
        path,
        access | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
        mode,
    )
    .map_err(io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path is not a regular file: {}", path.display()),
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use super::*;

    #[test]
    fn commit_publishes_once_without_leaving_a_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let temporary = directory.path().join("temporary");
        let output = directory.path().join("output");
        File::create(&temporary)
            .unwrap()
            .write_all(b"evidence")
            .unwrap();

        commit_path_noreplace(directory.path(), &temporary, &output).unwrap();
        assert!(!temporary.exists());
        assert_eq!(fs::read(&output).unwrap(), b"evidence");

        let second = directory.path().join("second");
        File::create(&second)
            .unwrap()
            .write_all(b"replacement")
            .unwrap();
        assert!(commit_path_noreplace(directory.path(), &second, &output).is_err());
        assert!(second.exists());
        assert_eq!(fs::read(&output).unwrap(), b"evidence");
    }

    #[test]
    fn commit_rejects_paths_outside_the_named_parent() {
        let directory = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let temporary = other.path().join("temporary");
        File::create(&temporary).unwrap();
        let output = directory.path().join("output");
        assert_eq!(
            commit_path_noreplace(directory.path(), &temporary, &output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
