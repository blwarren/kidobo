//! Descriptor-based protection for configuration and remote cache storage.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

pub(crate) fn secure_file(path: &Path) -> io::Result<bool> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config must be a regular file",
        ));
    }
    set_mode(&file, 0o600)
}

pub(crate) fn ensure_private_dir(path: &Path) -> io::Result<bool> {
    #[cfg(unix)]
    {
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory must have a child name",
            )
        })?;
        let parent = open_parent_directory(path)?;
        ensure_private_dir_at(&parent, name)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
        Ok(false)
    }
}

#[cfg(unix)]
pub(crate) fn open_parent_directory(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent)
}

#[cfg(unix)]
pub(crate) fn ensure_private_dir_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let path = std::path::PathBuf::from(format!("/dev/fd/{}", parent.as_raw_fd())).join(name);
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW);
    let directory = options.open(&path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote cache must be a directory",
        ));
    }
    set_mode(&directory, 0o700)
}

fn set_mode(file: &File, mode: u32) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o7777 != mode {
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            return Ok(true);
        }
    }
    Ok(false)
}
