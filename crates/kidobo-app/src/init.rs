//! Idempotent provisioning workflow and generated systemd unit templates.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::PathResolver;

/// Preferred trusted installed executable path.
pub const DEFAULT_KIDOBO_BINARY_PATH: &str = "/usr/local/bin/kidobo";
/// Secondary trusted installed executable path.
pub const FALLBACK_KIDOBO_BINARY_PATH: &str = "/usr/bin/kidobo";
/// Default systemd unit directory.
pub const DEFAULT_SYSTEMD_DIR: &str = "/etc/systemd/system";
/// Managed one-shot synchronization service filename.
pub const KIDOBO_SYNC_SERVICE_FILE: &str = "kidobo-sync.service";
/// Managed synchronization timer filename.
pub const KIDOBO_SYNC_TIMER_FILE: &str = "kidobo-sync.timer";

/// Default configuration written only when no configuration exists.
pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"[ipset]
set_name = "kidobo"
chain_action = "DROP"

[safe]
ips = []
include_github_meta = true
github_meta_url = "https://api.github.com/meta"
# github_meta_categories = ["api", "git", "hooks", "packages"]

[remote]
timeout_secs = 30
urls = []

[asn]
banned = []
cache_stale_after_secs = 86400
"#;

/// Default local blocklist written only when none exists.
pub const DEFAULT_BLOCKLIST_TEMPLATE: &str =
    "# Add one IP or CIDR entry per line.\n# Example: 203.0.113.7\n";

/// Default persistent hourly systemd timer unit.
pub const DEFAULT_SYSTEMD_TIMER_TEMPLATE: &str = r"[Unit]
Description=Run kidobo sync periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
Unit=kidobo-sync.service

[Install]
WantedBy=timers.target
";

/// Request to provision Kidobo's local files and optional live systemd units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Alternate filesystem root; when present, live systemd enablement is skipped.
    pub root_override: Option<PathBuf>,
    /// Trusted executable paths considered in order.
    pub executable_candidates: Vec<PathBuf>,
}

/// Whether an idempotently provisioned artifact was created or retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionState {
    /// Artifact did not exist and was created.
    Created,
    /// Existing artifact was preserved unchanged.
    Preserved,
}

/// Path and state of one provisioned directory or file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedArtifact {
    /// Provisioned path.
    pub path: PathBuf,
    /// Whether the artifact was created or preserved.
    pub state: ProvisionState,
}

/// Successful initialization result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitOutcome {
    /// Provisioned artifacts in workflow order.
    pub artifacts: Vec<ProvisionedArtifact>,
    /// Whether the live systemd timer was enabled.
    pub systemd_enabled: bool,
}

/// Side-effect boundary for safe, idempotent initialization.
pub trait InitProvisioner {
    /// Selects an installed executable from the trusted candidate paths.
    ///
    /// # Errors
    ///
    /// Returns an error when no candidate resolves to an acceptable executable.
    fn resolve_installed_executable(&self, candidates: &[PathBuf]) -> Result<PathBuf, AppError>;

    /// Creates a directory if it is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be inspected or created safely.
    fn ensure_dir(&self, path: &Path) -> Result<ProvisionState, AppError>;

    /// Creates a file with the supplied contents if it is absent.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be inspected or created safely.
    fn ensure_file(&self, path: &Path, contents: &str) -> Result<ProvisionState, AppError>;

    /// Reloads systemd and enables the managed timer.
    ///
    /// # Errors
    ///
    /// Returns an error when a required systemd command fails.
    fn enable_systemd_timer(&self) -> Result<(), AppError>;
}

/// Ports required by the initialization workflow.
pub struct InitDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Filesystem and systemd provisioner.
    pub provisioner: &'a dyn InitProvisioner,
}

/// Provisions Kidobo directories, configuration, blocklist, lock, and systemd units.
///
/// # Errors
///
/// Returns an error when paths cannot be resolved, the installed executable cannot be trusted, an
/// artifact cannot be provisioned, or live systemd enablement fails.
pub fn execute(
    request: &InitRequest,
    dependencies: &InitDependencies<'_>,
) -> Result<InitOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Optional)?;
    let executable = dependencies
        .provisioner
        .resolve_installed_executable(&request.executable_candidates)?;
    let systemd_dir = request.root_override.as_ref().map_or_else(
        || PathBuf::from(DEFAULT_SYSTEMD_DIR),
        |root| root.join("systemd/system"),
    );
    let service_file = systemd_dir.join(KIDOBO_SYNC_SERVICE_FILE);
    let timer_file = systemd_dir.join(KIDOBO_SYNC_TIMER_FILE);
    let mut outcome = InitOutcome::default();

    for directory in [
        &paths.config_dir,
        &paths.data_dir,
        &paths.remote_cache_dir,
        &systemd_dir,
    ] {
        dependencies.cancellation.check()?;
        let state = dependencies.provisioner.ensure_dir(directory)?;
        outcome.artifacts.push(ProvisionedArtifact {
            path: directory.clone(),
            state,
        });
    }

    let service_template =
        build_systemd_service_template(&executable, request.root_override.as_deref());
    for (file, contents) in [
        (&paths.config_file, DEFAULT_CONFIG_TEMPLATE),
        (&paths.blocklist_file, DEFAULT_BLOCKLIST_TEMPLATE),
        (&paths.lock_file, ""),
        (&service_file, service_template.as_str()),
        (&timer_file, DEFAULT_SYSTEMD_TIMER_TEMPLATE),
    ] {
        dependencies.cancellation.check()?;
        let state = dependencies.provisioner.ensure_file(file, contents)?;
        outcome.artifacts.push(ProvisionedArtifact {
            path: file.clone(),
            state,
        });
    }

    if request.root_override.is_none() {
        dependencies.cancellation.check()?;
        dependencies.provisioner.enable_systemd_timer()?;
        outcome.systemd_enabled = true;
    }
    Ok(outcome)
}

#[must_use]
/// Renders the compatibility-sensitive one-shot systemd service unit.
///
/// A root override is encoded as a native `KIDOBO_ROOT` environment setting for fixture installs.
pub fn build_systemd_service_template(
    executable_path: &Path,
    root_override: Option<&Path>,
) -> String {
    let mut output = String::from(
        "[Unit]\n\
Description=Kidobo firewall blocklist sync\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n",
    );
    let _journal_environment_write =
        writeln!(&mut output, "Environment=\"KIDOBO_LOG_FORMAT=journal\"");
    if let Some(root) = root_override {
        let root = root.to_string_lossy();
        let _root_environment_write = writeln!(
            &mut output,
            "Environment=\"KIDOBO_ROOT={}\"",
            escape_systemd_value(root.as_ref())
        );
    }
    let executable = executable_path.to_string_lossy();
    let _exec_start_write = writeln!(
        &mut output,
        "ExecStart=\"{}\" sync",
        escape_systemd_value(executable.as_ref())
    );
    output
}

fn escape_systemd_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use kidobo_core::config::Config;

    use super::{
        DEFAULT_CONFIG_TEMPLATE, DEFAULT_SYSTEMD_TIMER_TEMPLATE, InitDependencies, InitProvisioner,
        InitRequest, ProvisionState, build_systemd_service_template, execute,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::PathResolver;

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
                lock_file: PathBuf::from("/root/cache/sync.lock"),
            })
        }
    }

    #[derive(Default)]
    struct Provisioner {
        events: Mutex<Vec<String>>,
    }
    impl InitProvisioner for Provisioner {
        fn resolve_installed_executable(
            &self,
            _candidates: &[PathBuf],
        ) -> Result<PathBuf, AppError> {
            Ok(PathBuf::from("/usr/local/bin/kidobo"))
        }

        fn ensure_dir(&self, path: &Path) -> Result<ProvisionState, AppError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("dir:{}", path.display()));
            Ok(ProvisionState::Created)
        }

        fn ensure_file(&self, path: &Path, _contents: &str) -> Result<ProvisionState, AppError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("file:{}", path.display()));
            Ok(ProvisionState::Preserved)
        }

        fn enable_systemd_timer(&self) -> Result<(), AppError> {
            self.events
                .lock()
                .expect("events")
                .push("systemd".to_string());
            Ok(())
        }
    }

    fn request(root_override: Option<PathBuf>) -> InitRequest {
        InitRequest {
            paths: PathResolutionInput {
                explicit_config_path: None,
                temp_dir: PathBuf::from("/tmp"),
                env: std::collections::BTreeMap::new(),
            },
            root_override,
            executable_candidates: vec![PathBuf::from("/usr/local/bin/kidobo")],
        }
    }

    #[test]
    fn provisions_all_artifacts_and_enables_systemd_on_host() {
        let provisioner = Provisioner::default();
        let outcome = execute(
            &request(None),
            &InitDependencies {
                cancellation: &crate::ports::NoCancellation,
                paths: &Paths,
                provisioner: &provisioner,
            },
        )
        .expect("init");
        assert_eq!(outcome.artifacts.len(), 9);
        assert!(outcome.systemd_enabled);
        assert_eq!(
            provisioner.events.lock().expect("events").last(),
            Some(&"systemd".to_string())
        );
    }

    #[test]
    fn root_override_skips_live_systemd_commands() {
        let provisioner = Provisioner::default();
        let outcome = execute(
            &request(Some(PathBuf::from("/sandbox"))),
            &InitDependencies {
                cancellation: &crate::ports::NoCancellation,
                paths: &Paths,
                provisioner: &provisioner,
            },
        )
        .expect("init");
        assert!(!outcome.systemd_enabled);
        assert!(
            !provisioner
                .events
                .lock()
                .expect("events")
                .contains(&"systemd".to_string())
        );
    }

    #[test]
    fn service_template_escapes_root_and_executable() {
        let rendered = build_systemd_service_template(
            Path::new("/path/with\"quote/kidobo"),
            Some(Path::new("/root/with\\slash")),
        );
        assert!(rendered.contains("KIDOBO_ROOT=/root/with\\\\slash"));
        assert!(rendered.contains("ExecStart=\"/path/with\\\"quote/kidobo\" sync"));
    }

    #[test]
    fn service_template_matches_the_complete_default_contract() {
        assert_eq!(
            build_systemd_service_template(Path::new("/usr/local/bin/kidobo"), None),
            "[Unit]\n\
Description=Kidobo firewall blocklist sync\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=oneshot\n\
Environment=\"KIDOBO_LOG_FORMAT=journal\"\n\
ExecStart=\"/usr/local/bin/kidobo\" sync\n"
        );
    }

    #[test]
    fn default_timer_template_matches_the_complete_contract() {
        assert_eq!(
            DEFAULT_SYSTEMD_TIMER_TEMPLATE,
            "[Unit]\n\
Description=Run kidobo sync periodically\n\
\n\
[Timer]\n\
OnBootSec=2min\n\
OnUnitActiveSec=1h\n\
Persistent=true\n\
Unit=kidobo-sync.service\n\
\n\
[Install]\n\
WantedBy=timers.target\n"
        );
    }

    #[test]
    fn default_config_is_accepted_by_the_production_parser() {
        let config = Config::from_toml_str(DEFAULT_CONFIG_TEMPLATE).expect("default config");
        assert_eq!(config.ipset.set_name, "kidobo");
    }
}
