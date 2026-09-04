//! Read-only health checks and machine-readable doctor report types.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
use crate::ports::{ConfigRepository, PathResolver};

/// Aggregate doctor result used by human and JSON renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorOverall {
    /// Every required check succeeded or was intentionally skipped.
    #[serde(rename = "OK")]
    Ok,
    /// At least one required check failed.
    #[serde(rename = "FAIL")]
    Fail,
}

/// Stable status of one doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DoctorCheckStatus {
    /// Check succeeded.
    #[serde(rename = "OK")]
    Ok,
    /// Check failed.
    #[serde(rename = "FAIL")]
    Fail,
    /// Check was not applicable or could not safely be attempted.
    #[serde(rename = "SKIP")]
    Skip,
}

/// One named, operator-visible doctor check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    /// Stable machine-readable check name.
    pub name: String,
    /// Check status.
    pub status: DoctorCheckStatus,
    /// Human-readable evidence or failure detail.
    pub detail: String,
}

/// Complete deterministic doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    /// Aggregate status.
    pub overall: DoctorOverall,
    /// Ordered individual checks.
    pub checks: Vec<DoctorCheck>,
}

/// Readiness of the configured cache location without creating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheReadiness {
    /// The cache path is already a directory.
    ExistingDirectory,
    /// The cache path is absent but has an existing writable-parent candidate.
    CreatableFromParent {
        /// Existing ancestor used for the readiness check.
        parent: PathBuf,
    },
}

/// Failure from a bounded, read-only external diagnostic probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeFailure {
    /// The command could not be executed.
    Execution {
        /// Execution diagnostic.
        reason: String,
    },
    /// The command ran but returned an unsuccessful status.
    Exit {
        /// Rendered exit status.
        status: String,
        /// Bounded standard-error diagnostic.
        stderr: String,
    },
}

/// Read-only operating-system probes used by the doctor workflow.
pub trait DoctorProbe {
    /// Finds an executable by name without running it.
    fn find_binary(&self, binary: &str) -> Option<PathBuf>;

    /// Returns whether a path exists without mutating it.
    fn path_exists(&self, path: &Path) -> bool;

    /// Inspects whether a cache directory exists or could plausibly be created.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the relevant filesystem metadata cannot be inspected.
    fn cache_readiness(&self, path: &Path) -> Result<CacheReadiness, String>;

    /// Runs one bounded, read-only privileged probe.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeFailure`] when the command cannot execute or exits unsuccessfully.
    fn run_sudo_probe(&self, command: &str, args: &[&str]) -> Result<(), ProbeFailure>;
}

/// Ports required by the read-only doctor workflow.
pub struct DoctorDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Read-only host probe adapter.
    pub probes: &'a dyn DoctorProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Mode {
    Enabled,
    Disabled,
    Unknown,
}

/// Runs all applicable read-only checks and returns a deterministic report.
///
/// Individual failures are represented in the report rather than returned as workflow errors.
///
/// # Errors
///
/// Returns [`AppError::Interrupted`] when cancellation is observed between checks.
pub fn execute(
    request: &PathResolutionInput,
    dependencies: &DoctorDependencies<'_>,
) -> Result<DoctorReport, AppError> {
    dependencies.cancellation.check()?;
    let mut checks = Vec::new();
    let paths_result = dependencies
        .paths
        .resolve(request, ConfigRequirement::Required);
    let ipv6_mode = match &paths_result {
        Ok(paths) => match dependencies.configs.load(&paths.config_file) {
            Ok(config) => {
                checks.push(ok_check(
                    "config_parse",
                    format!("config parsed: {}", paths.config_file.display()),
                ));
                if config.ipset.enable_ipv6 {
                    Ipv6Mode::Enabled
                } else {
                    Ipv6Mode::Disabled
                }
            }
            Err(error) => {
                checks.push(fail_check(
                    "config_parse",
                    format!("failed to parse {}: {error}", paths.config_file.display()),
                ));
                Ipv6Mode::Unknown
            }
        },
        Err(error) => {
            checks.push(fail_check("config_parse", error.to_string()));
            Ipv6Mode::Unknown
        }
    };

    let mut available = BTreeMap::new();
    for (check_name, binary) in [
        ("binary_sudo", "sudo"),
        ("binary_bgpq4", "bgpq4"),
        ("binary_ipset", "ipset"),
        ("binary_iptables", "iptables"),
    ] {
        dependencies.cancellation.check()?;
        available.insert(
            binary,
            push_binary_check(&mut checks, dependencies.probes, check_name, binary),
        );
    }
    let ip6_available = if let Some(reason) = ipv6_skip_reason(ipv6_mode) {
        checks.push(skip_check("binary_ip6tables", reason));
        false
    } else {
        push_binary_check(
            &mut checks,
            dependencies.probes,
            "binary_ip6tables",
            "ip6tables",
        )
    };
    available.insert("ip6tables", ip6_available);

    push_path_checks(&mut checks, &paths_result, dependencies.probes);
    dependencies.cancellation.check()?;
    push_sudo_checks(
        &mut checks,
        ipv6_mode,
        &available,
        dependencies.probes,
        dependencies.cancellation,
    )?;
    dependencies.cancellation.check()?;
    Ok(DoctorReport::from_checks(checks))
}

impl DoctorReport {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let overall = if checks
            .iter()
            .any(|check| check.status == DoctorCheckStatus::Fail)
        {
            DoctorOverall::Fail
        } else {
            DoctorOverall::Ok
        };
        Self { overall, checks }
    }
}

fn push_binary_check(
    checks: &mut Vec<DoctorCheck>,
    probe: &dyn DoctorProbe,
    check_name: &'static str,
    binary: &str,
) -> bool {
    if let Some(path) = probe.find_binary(binary) {
        checks.push(ok_check(
            check_name,
            format!("found on PATH: {}", path.display()),
        ));
        true
    } else {
        checks.push(fail_check(
            check_name,
            format!("{binary} not found on PATH"),
        ));
        false
    }
}

fn push_path_checks(
    checks: &mut Vec<DoctorCheck>,
    paths: &Result<ResolvedPaths, AppError>,
    probe: &dyn DoctorProbe,
) {
    let Ok(paths) = paths else {
        let reason = match paths {
            Err(AppError::PathResolution { reason }) => reason.clone(),
            Err(error) => error.to_string(),
            Ok(_) => String::new(),
        };
        for name in ["file_config", "file_blocklist", "cache_writable"] {
            checks.push(fail_check(
                name,
                format!("path resolution unavailable: {reason}"),
            ));
        }
        return;
    };
    checks.push(file_check(
        "file_config",
        &paths.config_file,
        probe.path_exists(&paths.config_file),
    ));
    checks.push(file_check(
        "file_blocklist",
        &paths.blocklist_file,
        probe.path_exists(&paths.blocklist_file),
    ));
    checks.push(match probe.cache_readiness(&paths.remote_cache_dir) {
        Ok(CacheReadiness::ExistingDirectory) => skip_check(
            "cache_writable",
            format!(
                "remote cache directory has plausible write and traversal bits, but effective access was not mutated to verify it: {}",
                paths.remote_cache_dir.display()
            ),
        ),
        Ok(CacheReadiness::CreatableFromParent { parent }) => skip_check(
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
                paths.remote_cache_dir.display()
            ),
        ),
    });
}

fn file_check(name: &'static str, path: &Path, exists: bool) -> DoctorCheck {
    if exists {
        ok_check(name, format!("exists: {}", path.display()))
    } else {
        fail_check(name, format!("missing: {}", path.display()))
    }
}

fn push_sudo_checks(
    checks: &mut Vec<DoctorCheck>,
    ipv6_mode: Ipv6Mode,
    available: &BTreeMap<&str, bool>,
    probe: &dyn DoctorProbe,
    cancellation: &dyn crate::ports::Cancellation,
) -> Result<(), AppError> {
    for (name, binary, arguments) in [
        ("sudo_probe_ipset", "ipset", &["list"][..]),
        ("sudo_probe_iptables", "iptables", &["-S"][..]),
    ] {
        cancellation.check()?;
        checks.push(sudo_check(name, binary, arguments, available, probe));
    }
    cancellation.check()?;
    if let Some(reason) = ipv6_skip_reason(ipv6_mode) {
        checks.push(skip_check("sudo_probe_ip6tables", reason));
    } else {
        checks.push(sudo_check(
            "sudo_probe_ip6tables",
            "ip6tables",
            &["-S"],
            available,
            probe,
        ));
    }
    Ok(())
}

fn sudo_check(
    name: &'static str,
    binary: &str,
    arguments: &[&str],
    available: &BTreeMap<&str, bool>,
    probe: &dyn DoctorProbe,
) -> DoctorCheck {
    if !available.get("sudo").copied().unwrap_or(false) {
        return skip_check(name, "sudo binary is unavailable");
    }
    if !available.get(binary).copied().unwrap_or(false) {
        return skip_check(name, format!("{binary} binary is unavailable"));
    }
    let command = format!("{binary} {}", arguments.join(" "));
    match probe.run_sudo_probe(binary, arguments) {
        Ok(()) => ok_check(name, format!("sudo -n {command} succeeded")),
        Err(ProbeFailure::Execution { reason }) => fail_check(
            name,
            format!("sudo -n {command} execution failed: {reason}"),
        ),
        Err(ProbeFailure::Exit { status, stderr }) => fail_check(
            name,
            format!(
                "sudo -n {command} failed with status {}: {}",
                status,
                stderr_detail(&stderr)
            ),
        ),
    }
}

fn ipv6_skip_reason(mode: Ipv6Mode) -> Option<&'static str> {
    match mode {
        Ipv6Mode::Enabled => None,
        Ipv6Mode::Disabled => Some("ipv6 disabled in config"),
        Ipv6Mode::Unknown => Some("config unavailable; ipv6 state unknown"),
    }
}

fn stderr_detail(stderr: &str) -> &str {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "no stderr"
    } else {
        trimmed
    }
}

fn ok_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Ok,
        detail,
    }
}

fn fail_check(name: &'static str, detail: String) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Fail,
        detail,
    }
}

fn skip_check(name: &'static str, detail: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        status: DoctorCheckStatus::Skip,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use kidobo_core::config::Config;

    use super::{
        CacheReadiness, DoctorCheckStatus, DoctorDependencies, DoctorOverall, DoctorProbe,
        ProbeFailure, execute,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, PathResolver};

    struct Paths;
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            _requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            Ok(ResolvedPaths {
                config_dir: PathBuf::from("/root/config"),
                config_file: PathBuf::from("/root/config/config.toml"),
                data_dir: PathBuf::from("/root/data"),
                blocklist_file: PathBuf::from("/root/data/blocklist.txt"),
                cache_dir: PathBuf::from("/root/cache"),
                remote_cache_dir: PathBuf::from("/root/cache/remote"),
                lock_file: PathBuf::from("/root/cache/lock"),
            })
        }
    }

    struct Configs;
    impl ConfigRepository for Configs {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            Config::from_toml_str("[ipset]\nset_name='kidobo'\nenable_ipv6=false\n")
                .map_err(AppError::from)
        }
    }

    #[derive(Default)]
    struct Probes(Mutex<Vec<String>>);
    impl DoctorProbe for Probes {
        fn find_binary(&self, binary: &str) -> Option<PathBuf> {
            Some(PathBuf::from(format!("/usr/bin/{binary}")))
        }

        fn path_exists(&self, _path: &Path) -> bool {
            true
        }

        fn cache_readiness(&self, _path: &Path) -> Result<CacheReadiness, String> {
            Ok(CacheReadiness::ExistingDirectory)
        }

        fn run_sudo_probe(&self, command: &str, _args: &[&str]) -> Result<(), ProbeFailure> {
            self.0.lock().expect("probes").push(command.to_string());
            Ok(())
        }
    }

    fn request() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn disabled_ipv6_skips_binary_and_probe_without_invoking_them() {
        let probes = Probes::default();
        let report = execute(
            &request(),
            &DoctorDependencies {
                cancellation: &crate::ports::NoCancellation,
                paths: &Paths,
                configs: &Configs,
                probes: &probes,
            },
        );

        let report = report.expect("doctor report");
        assert_eq!(report.overall, DoctorOverall::Ok);
        let ip6_checks = report
            .checks
            .iter()
            .filter(|check| check.name.contains("ip6tables"))
            .collect::<Vec<_>>();
        assert_eq!(ip6_checks.len(), 2);
        assert!(
            ip6_checks
                .iter()
                .all(|check| check.status == DoctorCheckStatus::Skip)
        );
        assert!(
            ip6_checks
                .iter()
                .all(|check| check.detail == "ipv6 disabled in config")
        );
        assert_eq!(*probes.0.lock().expect("probes"), ["ipset", "iptables"]);
    }
}
