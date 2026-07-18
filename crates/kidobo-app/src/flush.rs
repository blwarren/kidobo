use std::path::Path;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushRequest {
    pub paths: PathResolutionInput,
    pub cache_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFailure {
    pub operation: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlushOutcome {
    pub completed: Vec<String>,
    pub failed: Vec<CleanupFailure>,
}

impl FlushOutcome {
    #[must_use]
    pub fn failure_details(&self) -> String {
        self.failed
            .iter()
            .map(|failure| failure.reason.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub trait FlushBackend {
    fn cleanup_firewall(&self, family: FirewallFamily) -> Result<(), String>;

    fn destroy_ipset(&self, set_name: &str) -> Result<(), String>;

    fn clear_remote_cache(&self, path: &Path) -> Result<(), String>;
}

pub struct FlushDependencies<'a> {
    pub paths: &'a dyn PathResolver,
    pub configs: &'a dyn ConfigRepository,
    pub locks: &'a dyn LockManager,
    pub backend: &'a dyn FlushBackend,
}

pub fn execute(
    request: &FlushRequest,
    dependencies: &FlushDependencies<'_>,
) -> Result<FlushOutcome, AppError> {
    let requirement = if request.cache_only {
        ConfigRequirement::Optional
    } else {
        ConfigRequirement::Required
    };
    let paths = dependencies.paths.resolve(&request.paths, requirement)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;

    if request.cache_only {
        dependencies
            .backend
            .clear_remote_cache(&paths.remote_cache_dir)
            .map_err(|reason| AppError::FlushCacheIo {
                path: paths.remote_cache_dir,
                reason,
            })?;
        return Ok(FlushOutcome {
            completed: vec!["remote cache".to_string()],
            failed: Vec::new(),
        });
    }

    let config = dependencies.configs.load(&paths.config_file)?;
    let mut outcome = FlushOutcome::default();
    attempt(
        &mut outcome,
        "IPv4 firewall",
        dependencies.backend.cleanup_firewall(FirewallFamily::Ipv4),
    );
    attempt(
        &mut outcome,
        "IPv6 firewall",
        dependencies.backend.cleanup_firewall(FirewallFamily::Ipv6),
    );
    attempt(
        &mut outcome,
        format!("ipset `{}`", config.ipset.set_name),
        dependencies.backend.destroy_ipset(&config.ipset.set_name),
    );
    if config.ipset.set_name_v6 != config.ipset.set_name {
        attempt(
            &mut outcome,
            format!("ipset `{}`", config.ipset.set_name_v6),
            dependencies
                .backend
                .destroy_ipset(&config.ipset.set_name_v6),
        );
    }
    attempt(
        &mut outcome,
        "remote cache",
        dependencies
            .backend
            .clear_remote_cache(&paths.remote_cache_dir)
            .map_err(|reason| {
                format!(
                    "failed to clear remote cache at {}: {reason}",
                    paths.remote_cache_dir.display()
                )
            }),
    );
    Ok(outcome)
}

fn attempt(outcome: &mut FlushOutcome, operation: impl Into<String>, result: Result<(), String>) {
    let operation = operation.into();
    match result {
        Ok(()) => outcome.completed.push(operation),
        Err(reason) => outcome.failed.push(CleanupFailure { operation, reason }),
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use kidobo_core::config::Config;

    use super::{FirewallFamily, FlushBackend, FlushDependencies, FlushRequest, execute};
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, LockGuard, LockManager, PathResolver};

    fn config() -> Config {
        Config::from_toml_str("[ipset]\nset_name='kidobo'\nset_name_v6='kidobo-v6'\n")
            .expect("config")
    }

    fn paths() -> ResolvedPaths {
        ResolvedPaths {
            config_dir: PathBuf::from("/root/config"),
            config_file: PathBuf::from("/root/config/config.toml"),
            data_dir: PathBuf::from("/root/data"),
            blocklist_file: PathBuf::from("/root/data/blocklist.txt"),
            cache_dir: PathBuf::from("/root/cache"),
            remote_cache_dir: PathBuf::from("/root/cache/remote"),
            lock_file: PathBuf::from("/root/cache/sync.lock"),
        }
    }

    struct Paths;
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            _requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            Ok(paths())
        }
    }

    struct Configs;
    impl ConfigRepository for Configs {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            Ok(config())
        }
    }

    struct Guard;
    impl LockGuard for Guard {}

    struct Locks;
    impl LockManager for Locks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            Ok(Box::new(Guard))
        }
    }

    struct Backend {
        events: Mutex<Vec<String>>,
        fail: bool,
    }

    impl FlushBackend for Backend {
        fn cleanup_firewall(&self, family: FirewallFamily) -> Result<(), String> {
            let event = format!("firewall:{family:?}");
            self.run(&event)
        }

        fn destroy_ipset(&self, set_name: &str) -> Result<(), String> {
            self.run(&format!("ipset:{set_name}"))
        }

        fn clear_remote_cache(&self, _path: &Path) -> Result<(), String> {
            self.run("cache")
        }
    }

    impl Backend {
        fn run(&self, event: &str) -> Result<(), String> {
            self.events.lock().expect("events").push(event.to_string());
            if self.fail {
                Err(format!("{event} failed"))
            } else {
                Ok(())
            }
        }
    }

    fn request(cache_only: bool) -> FlushRequest {
        FlushRequest {
            paths: PathResolutionInput {
                explicit_config_path: None,
                temp_dir: PathBuf::from("/tmp"),
                env: std::collections::BTreeMap::new(),
            },
            cache_only,
        }
    }

    #[test]
    fn full_flush_attempts_every_cleanup_in_order() {
        let backend = Backend {
            events: Mutex::new(Vec::new()),
            fail: false,
        };
        let outcome = execute(
            &request(false),
            &FlushDependencies {
                paths: &Paths,
                configs: &Configs,
                locks: &Locks,
                backend: &backend,
            },
        )
        .expect("flush");

        assert!(outcome.failed.is_empty());
        assert_eq!(
            *backend.events.lock().expect("events"),
            [
                "firewall:Ipv4",
                "firewall:Ipv6",
                "ipset:kidobo",
                "ipset:kidobo-v6",
                "cache",
            ]
        );
    }

    #[test]
    fn full_flush_records_every_failure_without_stopping() {
        let backend = Backend {
            events: Mutex::new(Vec::new()),
            fail: true,
        };
        let outcome = execute(
            &request(false),
            &FlushDependencies {
                paths: &Paths,
                configs: &Configs,
                locks: &Locks,
                backend: &backend,
            },
        )
        .expect("typed outcome");

        assert_eq!(outcome.failed.len(), 5);
        assert_eq!(backend.events.lock().expect("events").len(), 5);
    }

    #[test]
    fn cache_only_flush_does_not_run_firewall_or_load_config() {
        let backend = Backend {
            events: Mutex::new(Vec::new()),
            fail: false,
        };
        execute(
            &request(true),
            &FlushDependencies {
                paths: &Paths,
                configs: &Configs,
                locks: &Locks,
                backend: &backend,
            },
        )
        .expect("cache flush");
        assert_eq!(*backend.events.lock().expect("events"), ["cache"]);
    }
}
