use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::adapters::command_common::find_executable_in_path;
use crate::adapters::config::load_config_from_file;
use crate::adapters::path::{
    PathResolutionError, PathResolutionInput, ResolvedPaths, resolve_paths,
};
use crate::core::config::Config;

use super::report::{DoctorCheck, fail_check, ok_check, skip_check};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ipv6Mode {
    Enabled,
    Disabled,
    Unknown,
}

pub(super) type BinaryAvailability = BTreeMap<&'static str, bool>;
pub(super) type PathsResult = Result<ResolvedPaths, PathResolutionError>;

const REQUIRED_BINARY_CHECKS: [(&str, &str); 4] = [
    ("binary_sudo", "sudo"),
    ("binary_bgpq4", "bgpq4"),
    ("binary_ipset", "ipset"),
    ("binary_iptables", "iptables"),
];

#[derive(Debug)]
pub(super) struct DoctorBuildContext {
    pub(super) paths_result: PathsResult,
    pub(super) ipv6_mode: Ipv6Mode,
}

pub(super) trait BinaryLocator {
    fn find_in_path(&self, binary: &str) -> Option<PathBuf>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct SystemBinaryLocator;

impl BinaryLocator for SystemBinaryLocator {
    fn find_in_path(&self, binary: &str) -> Option<PathBuf> {
        find_executable_in_path(binary, env::var_os("PATH"))
    }
}

pub(super) fn collect_doctor_context(
    path_input: &PathResolutionInput,
    checks: &mut Vec<DoctorCheck>,
) -> DoctorBuildContext {
    let paths_result = resolve_paths(path_input);

    let ipv6_mode = match &paths_result {
        Ok(paths) => match load_config_from_file(&paths.config_file) {
            Ok(parsed) => {
                checks.push(ok_check(
                    "config_parse",
                    format!("config parsed: {}", paths.config_file.display()),
                ));
                ipv6_mode_from_config(Some(&parsed))
            }
            Err(err) => {
                checks.push(fail_check(
                    "config_parse",
                    format!("failed to parse {}: {err}", paths.config_file.display()),
                ));
                ipv6_mode_from_config(None)
            }
        },
        Err(err) => {
            checks.push(fail_check(
                "config_parse",
                format!("path resolution failed: {err}"),
            ));
            ipv6_mode_from_config(None)
        }
    };

    DoctorBuildContext {
        paths_result,
        ipv6_mode,
    }
}

pub(super) fn collect_binary_checks(
    checks: &mut Vec<DoctorCheck>,
    binary_locator: &dyn BinaryLocator,
    ipv6_mode: Ipv6Mode,
) -> BinaryAvailability {
    let mut binary_available = BTreeMap::new();

    for &(check_name, binary) in &REQUIRED_BINARY_CHECKS {
        let available = push_binary_check(checks, binary_locator, check_name, binary);
        binary_available.insert(binary, available);
    }

    push_ipv6_binary_check(checks, binary_locator, ipv6_mode, &mut binary_available);
    binary_available
}

fn ipv6_mode_from_config(config: Option<&Config>) -> Ipv6Mode {
    match config {
        Some(cfg) if cfg.ipset.enable_ipv6 => Ipv6Mode::Enabled,
        Some(_) => Ipv6Mode::Disabled,
        None => Ipv6Mode::Unknown,
    }
}

fn push_ipv6_binary_check(
    checks: &mut Vec<DoctorCheck>,
    binary_locator: &dyn BinaryLocator,
    ipv6_mode: Ipv6Mode,
    binary_available: &mut BinaryAvailability,
) {
    let available = if let Some(reason) = ipv6_skip_reason(ipv6_mode) {
        checks.push(skip_check("binary_ip6tables", reason));
        false
    } else {
        push_binary_check(checks, binary_locator, "binary_ip6tables", "ip6tables")
    };

    binary_available.insert("ip6tables", available);
}

pub(super) fn push_path_checks(checks: &mut Vec<DoctorCheck>, paths_result: &PathsResult) {
    match paths_result {
        Ok(paths) => {
            checks.push(file_exists_check("file_config", &paths.config_file));
            checks.push(file_exists_check("file_blocklist", &paths.blocklist_file));
            checks.push(cache_writability_check(&paths.remote_cache_dir));
        }
        Err(err) => {
            checks.push(fail_check(
                "file_config",
                format!("path resolution unavailable: {err}"),
            ));
            checks.push(fail_check(
                "file_blocklist",
                format!("path resolution unavailable: {err}"),
            ));
            checks.push(fail_check(
                "cache_writable",
                format!("path resolution unavailable: {err}"),
            ));
        }
    }
}

pub(super) fn ipv6_skip_reason(ipv6_mode: Ipv6Mode) -> Option<&'static str> {
    match ipv6_mode {
        Ipv6Mode::Enabled => None,
        Ipv6Mode::Disabled => Some("ipv6 disabled in config"),
        Ipv6Mode::Unknown => Some("config unavailable; ipv6 state unknown"),
    }
}

fn push_binary_check(
    checks: &mut Vec<DoctorCheck>,
    locator: &dyn BinaryLocator,
    check_name: &'static str,
    binary: &str,
) -> bool {
    match locator.find_in_path(binary) {
        Some(path) => {
            checks.push(ok_check(
                check_name,
                format!("found on PATH: {}", path.display()),
            ));
            true
        }
        None => {
            checks.push(fail_check(
                check_name,
                format!("{binary} not found on PATH"),
            ));
            false
        }
    }
}

fn file_exists_check(check_name: &'static str, path: &Path) -> DoctorCheck {
    if path.exists() {
        ok_check(check_name, format!("exists: {}", path.display()))
    } else {
        fail_check(check_name, format!("missing: {}", path.display()))
    }
}

fn cache_writability_check(remote_cache_dir: &Path) -> DoctorCheck {
    match ensure_cache_path_ready(remote_cache_dir) {
        Ok(CachePathReady::ExistingDirectory) => skip_check(
            "cache_writable",
            format!(
                "remote cache directory has plausible write and traversal bits, but effective access was not mutated to verify it: {}",
                remote_cache_dir.display()
            ),
        ),
        Ok(CachePathReady::CreatableFromParent { parent }) => skip_check(
            "cache_writable",
            format!(
                "remote cache parent has plausible write and traversal bits, but creation was not attempted: {}",
                parent.display()
            ),
        ),
        Err(reason) => fail_check(
            "cache_writable",
            format!(
                "remote cache path is not writable at {}: {reason}",
                remote_cache_dir.display()
            ),
        ),
    }
}

#[derive(Debug, Error)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CachePathReady {
    ExistingDirectory,
    CreatableFromParent { parent: PathBuf },
}

fn ensure_cache_path_ready(remote_cache_dir: &Path) -> Result<CachePathReady, CacheWritableError> {
    if remote_cache_dir.exists() {
        ensure_directory_is_writable(remote_cache_dir)?;
        return Ok(CachePathReady::ExistingDirectory);
    }

    let parent = remote_cache_dir
        .ancestors()
        .skip(1)
        .find(|candidate| candidate.exists())
        .map(Path::to_path_buf)
        .ok_or_else(|| CacheWritableError::MissingParent {
            path: remote_cache_dir.to_path_buf(),
        })?;
    ensure_directory_is_writable(&parent)?;
    Ok(CachePathReady::CreatableFromParent { parent })
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

#[cfg(all(test, unix))]
mod cache_permission_tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::cache_writability_check;
    use crate::cli::doctor::DoctorCheckStatus;

    #[test]
    fn cache_check_fails_without_write_or_traversal_bits() {
        for mode in [0o222, 0o555] {
            let temp = TempDir::new().expect("tempdir");
            let cache = temp.path().join("cache");
            fs::create_dir(&cache).expect("mkdir");
            fs::set_permissions(&cache, fs::Permissions::from_mode(mode)).expect("chmod");

            let check = cache_writability_check(&cache);
            assert_eq!(check.status, DoctorCheckStatus::Fail, "mode {mode:o}");
        }
    }

    #[test]
    fn cache_check_skips_when_mode_is_plausible_but_unproven() {
        let temp = TempDir::new().expect("tempdir");
        let cache = temp.path().join("cache");
        fs::create_dir(&cache).expect("mkdir");
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o777)).expect("chmod");

        let check = cache_writability_check(&cache);
        assert_eq!(check.status, DoctorCheckStatus::Skip);
        assert_eq!(check.name, "cache_writable");
    }

    #[test]
    fn cache_check_fails_for_existing_non_directory() {
        let temp = TempDir::new().expect("tempdir");
        let cache = temp.path().join("cache");
        fs::write(&cache, "not a directory").expect("write file");

        let check = cache_writability_check(&cache);
        assert_eq!(check.status, DoctorCheckStatus::Fail);
    }
}
