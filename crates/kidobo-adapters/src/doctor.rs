//! Read-only host probes used by the doctor application use case.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use kidobo_app::doctor::{CacheReadiness, DoctorProbe, ProbeFailure};

use crate::command_common::find_executable_in_path;
use crate::command_runner::{CommandExecutor, SudoCommandRunner, SystemCommandExecutor};

#[derive(Debug)]
pub struct SystemDoctorProbe<R = SudoCommandRunner<SystemCommandExecutor>> {
    runner: R,
}

impl<R> SystemDoctorProbe<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for SystemDoctorProbe {
    fn default() -> Self {
        Self::new(SudoCommandRunner::default())
    }
}

impl<E: CommandExecutor> DoctorProbe for SystemDoctorProbe<SudoCommandRunner<E>> {
    fn find_binary(&self, binary: &str) -> Option<PathBuf> {
        find_executable_in_path(binary, env::var_os("PATH"))
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn cache_readiness(&self, path: &Path) -> Result<CacheReadiness, String> {
        ensure_cache_path_ready(path).map_err(|error| error.to_string())
    }

    fn run_sudo_probe(&self, command: &str, args: &[&str]) -> Result<(), ProbeFailure> {
        let result = self
            .runner
            .run(command, args)
            .map_err(|error| ProbeFailure::Execution {
                reason: error.to_string(),
            })?;
        if result.status.success() {
            Ok(())
        } else {
            Err(ProbeFailure::Exit {
                status: format!("{:?}", result.status),
                stderr: result.stderr,
            })
        }
    }
}

fn ensure_cache_path_ready(path: &Path) -> Result<CacheReadiness, CacheWritableError> {
    if path.exists() {
        ensure_directory_is_writable(path)?;
        return Ok(CacheReadiness::ExistingDirectory);
    }
    let parent = path
        .ancestors()
        .skip(1)
        .find(|candidate| candidate.exists())
        .map(Path::to_path_buf)
        .ok_or_else(|| CacheWritableError::MissingParent {
            path: path.to_path_buf(),
        })?;
    ensure_directory_is_writable(&parent)?;
    Ok(CacheReadiness::CreatableFromParent { parent })
}

fn ensure_directory_is_writable(path: &Path) -> Result<(), CacheWritableError> {
    let metadata = fs::metadata(path).map_err(|source| CacheWritableError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(CacheWritableError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    if !directory_has_mutation_permission_bits(&metadata) {
        return Err(CacheWritableError::InsufficientMode {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn directory_has_mutation_permission_bits(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        mode & 0o222 != 0 && mode & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        !metadata.permissions().readonly()
    }
}

#[derive(Debug, thiserror::Error)]
enum CacheWritableError {
    #[error("failed to read metadata for {path}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("path exists but is not a directory: {path}")]
    NotDirectory { path: PathBuf },

    #[error("path lacks write or directory traversal permission bits: {path}")]
    InsufficientMode { path: PathBuf },

    #[error("no existing parent directory found for {path}")]
    MissingParent { path: PathBuf },
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::ensure_cache_path_ready;

    #[test]
    fn cache_readiness_requires_write_and_traversal_bits() {
        for mode in [0o222, 0o555] {
            let temp = TempDir::new().expect("tempdir");
            let cache = temp.path().join("cache");
            fs::create_dir(&cache).expect("mkdir");
            fs::set_permissions(&cache, fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(ensure_cache_path_ready(&cache).is_err(), "mode {mode:o}");
        }
    }

    #[test]
    fn cache_readiness_rejects_existing_file() {
        let temp = TempDir::new().expect("tempdir");
        let cache = temp.path().join("cache");
        fs::write(&cache, "file").expect("write");
        assert!(ensure_cache_path_ready(&cache).is_err());
    }
}
