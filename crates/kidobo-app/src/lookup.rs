//! Deterministic offline lookup with borrowed match batches and a compact summary.

pub use kidobo_core::lookup::LookupSourceEntry;
use kidobo_core::lookup::try_run_lookup_by_target;
use std::path::PathBuf;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, PathResolver, TargetFileReader};
use crate::source::{Notice, OfflineLookupContext, OfflineLookupRegistry};
use crate::temporary_bans::{Clock, TemporaryBanRepository};

/// One lookup target supplied directly or through a bounded file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupInput {
    /// One operator-supplied IP address or CIDR.
    Single(String),
    /// File containing line-oriented targets.
    File(PathBuf),
}

/// Request to search local and cached source data without network access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Direct or file-based targets.
    pub input: LookupInput,
}

/// Counts and diagnostics after every valid target has been emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSummary {
    /// Number of unique valid target strings.
    pub total_count: usize,
    /// Number of valid targets with at least one match.
    pub matched_count: usize,
    /// Sorted, unique invalid target strings.
    pub invalid_targets: Vec<String>,
    /// Whether targets came from a file rather than one direct argument.
    pub file_mode: bool,
    /// Soft configuration or source-availability notices.
    pub notices: Vec<Notice>,
}

/// Ports and registry required by offline lookup.
pub struct LookupDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Optional validated configuration source.
    pub configs: &'a dyn ConfigRepository,
    /// Bounded target-file reader.
    pub target_files: &'a dyn TargetFileReader,
    /// Ordered offline source registry.
    pub sources: &'a OfflineLookupRegistry,
    /// Time source for one consistent expiry decision per lookup.
    pub clock: &'a dyn Clock,
    /// Read-only access to persistent temporary bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
}

/// Performs deterministic offline lookup against local and cached source registries.
///
/// # Errors
///
/// Returns an error when paths cannot be resolved, a target file cannot be read, or a required
/// offline source cannot be loaded, cancellation is requested, or the callback fails.
/// Callback errors retain their type. Configuration-loading failures remain soft notices.
pub fn execute<E: From<AppError>>(
    request: &LookupRequest,
    dependencies: &LookupDependencies<'_>,
    mut emit: impl FnMut(&str, &[&LookupSourceEntry]) -> Result<(), E>,
) -> Result<LookupSummary, E> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Optional)?;
    let (config, notices) = match dependencies.configs.load(&paths.config_file) {
        Ok(config) => (Some(config), Vec::new()),
        Err(error) => (
            None,
            vec![Notice::warning(format!(
                "lookup config-backed sources unavailable; checking local, temporary, and cached remote sources: {error}"
            ))],
        ),
    };

    let (targets, file_mode) = match &request.input {
        LookupInput::Single(target) => (vec![target.clone()], false),
        LookupInput::File(path) => (dependencies.target_files.read_lines(path)?, true),
    };

    let cutoff = dependencies.clock.now_unix_secs()?;
    let temporary_bans = dependencies
        .temporary_bans
        .load(&paths.temporary_bans_file())?;
    let context = OfflineLookupContext {
        cancellation: dependencies.cancellation,
        paths: &paths,
        config: config.as_ref(),
        temporary_bans: &temporary_bans,
        cutoff,
    };
    let source_entries = dependencies.sources.load(&context)?;
    dependencies.cancellation.check()?;

    let mut total_count = 0;
    let mut matched_count = 0;
    let invalid_targets =
        try_run_lookup_by_target(&targets, &source_entries, |target, matches| {
            dependencies.cancellation.check()?;
            emit(target, matches)?;
            total_count += 1;
            matched_count += usize::from(!matches.is_empty());
            dependencies.cancellation.check()?;
            Ok::<(), E>(())
        })?;

    Ok(LookupSummary {
        total_count,
        matched_count,
        invalid_targets,
        file_mode,
        notices,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use kidobo_core::config::Config;
    use kidobo_core::lookup::LookupSourceEntry;
    use kidobo_core::network::parse_ip_cidr_token;
    use kidobo_core::temporary_bans::TemporaryBans;

    use super::{LookupDependencies, LookupInput, LookupRequest, execute};
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, PathResolver, TargetFileReader};
    use crate::source::{OfflineLookupContext, OfflineLookupProvider, OfflineLookupRegistry};
    use crate::temporary_bans::{Clock, TemporaryBanRepository};

    struct TemporaryState;

    impl Clock for TemporaryState {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            Ok(100)
        }
    }

    impl TemporaryBanRepository for TemporaryState {
        fn load(&self, path: &Path) -> Result<TemporaryBans, AppError> {
            assert_eq!(path, Path::new("/root/data/temporary-bans.toml"));
            Ok(TemporaryBans::default())
        }

        fn save(&self, _: &Path, _: &TemporaryBans) -> Result<(), AppError> {
            panic!("offline lookup must not write temporary state")
        }
    }

    struct Paths;
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Optional);
            Ok(ResolvedPaths {
                root_override: Some(PathBuf::from("/root")),
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

    struct MissingConfig;
    impl ConfigRepository for MissingConfig {
        fn load(&self, path: &Path) -> Result<Config, AppError> {
            Err(AppError::MissingConfigFile {
                path: path.to_path_buf(),
            })
        }
    }

    struct Targets;
    impl TargetFileReader for Targets {
        fn read_lines(&self, _path: &Path) -> Result<Vec<String>, AppError> {
            Ok(vec![
                "198.51.100.8".to_string(),
                "invalid".to_string(),
                "203.0.113.8".to_string(),
            ])
        }
    }

    struct CachedSource;
    impl OfflineLookupProvider for CachedSource {
        fn id(&self) -> &'static str {
            "cached"
        }

        fn append_offline(
            &self,
            _context: &OfflineLookupContext<'_>,
            entries: &mut Vec<LookupSourceEntry>,
        ) -> Result<(), AppError> {
            entries.push(LookupSourceEntry {
                source_label: Arc::from("cache:test"),
                source_line: "198.51.100.0/24".to_string(),
                cidr: parse_ip_cidr_token("198.51.100.0/24").expect("cidr"),
            });
            Ok(())
        }
    }

    fn path_input() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn lookup_stops_on_a_typed_callback_error_or_cancellation_between_batches() {
        #[derive(Debug)]
        enum SinkError {
            Application(AppError),
            Output(std::io::Error),
        }
        impl From<AppError> for SinkError {
            fn from(error: AppError) -> Self {
                Self::Application(error)
            }
        }
        for cancel in [false, true] {
            let cancellation = std::sync::atomic::AtomicBool::new(false);
            let mut sources = OfflineLookupRegistry::new();
            sources.register(CachedSource).expect("register");
            let mut emitted = Vec::new();
            let result = execute(
                &LookupRequest {
                    paths: path_input(),
                    input: LookupInput::File(PathBuf::from("targets")),
                },
                &LookupDependencies {
                    cancellation: &cancellation,
                    paths: &Paths,
                    configs: &MissingConfig,
                    target_files: &Targets,
                    sources: &sources,
                    clock: &TemporaryState,
                    temporary_bans: &TemporaryState,
                },
                |target, _| {
                    emitted.push(target.to_string());
                    if cancel {
                        cancellation.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    } else {
                        Err(SinkError::Output(std::io::Error::from(
                            std::io::ErrorKind::BrokenPipe,
                        )))
                    }
                },
            );
            assert_eq!(emitted, ["198.51.100.8"]);
            match result.expect_err("must stop after first batch") {
                SinkError::Application(AppError::Interrupted) => assert!(cancel),
                SinkError::Output(error) => {
                    assert!(!cancel);
                    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                }
                other @ SinkError::Application(_) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn lookup_captures_one_clock_and_state_snapshot_without_writes_or_valid_config() {
        #[derive(Default)]
        struct Snapshot {
            clock_calls: std::cell::Cell<usize>,
            load_calls: std::cell::Cell<usize>,
        }
        impl Clock for Snapshot {
            fn now_unix_secs(&self) -> Result<u64, AppError> {
                self.clock_calls.set(self.clock_calls.get() + 1);
                Ok(100)
            }
        }
        impl TemporaryBanRepository for Snapshot {
            fn load(&self, _: &Path) -> Result<TemporaryBans, AppError> {
                self.load_calls.set(self.load_calls.get() + 1);
                Ok(TemporaryBans {
                    ips: [(parse_ip_cidr_token("198.51.100.0/24").expect("cidr"), 101)].into(),
                    asns: [(64512, 101)].into(),
                })
            }
            fn save(&self, _: &Path, _: &TemporaryBans) -> Result<(), AppError> {
                panic!("lookup must not mutate records")
            }
        }
        struct SnapshotProvider;
        impl OfflineLookupProvider for SnapshotProvider {
            fn id(&self) -> &'static str {
                "temporary"
            }
            fn append_offline(
                &self,
                context: &OfflineLookupContext<'_>,
                entries: &mut Vec<LookupSourceEntry>,
            ) -> Result<(), AppError> {
                assert!(context.config.is_none());
                assert_eq!(context.cutoff, 100);
                assert_eq!(context.temporary_bans.active_asns(context.cutoff), [64512]);
                entries.extend(
                    context
                        .temporary_bans
                        .active_ips(context.cutoff)
                        .into_iter()
                        .map(|cidr| LookupSourceEntry {
                            source_label: Arc::from("temporary:blocklist"),
                            source_line: cidr.to_string(),
                            cidr,
                        }),
                );
                Ok(())
            }
        }
        let snapshot = Snapshot::default();
        let mut sources = OfflineLookupRegistry::new();
        sources
            .register(SnapshotProvider)
            .expect("temporary source");
        let mut batches = Vec::new();
        let outcome = execute(
            &LookupRequest {
                paths: path_input(),
                input: LookupInput::File(PathBuf::from("targets")),
            },
            &LookupDependencies {
                cancellation: &crate::ports::NoCancellation,
                paths: &Paths,
                configs: &MissingConfig,
                target_files: &Targets,
                sources: &sources,
                clock: &snapshot,
                temporary_bans: &snapshot,
            },
            |target, matches| {
                batches.push((
                    target.to_string(),
                    matches
                        .iter()
                        .map(|entry| (*entry).clone())
                        .collect::<Vec<_>>(),
                ));
                Ok::<(), AppError>(())
            },
        )
        .expect("lookup");
        assert_eq!(outcome.total_count, 2);
        assert_eq!(outcome.matched_count, 1);
        assert_eq!(snapshot.clock_calls.get(), 1);
        assert_eq!(snapshot.load_calls.get(), 1);
        assert_eq!(batches[0].1[0].source_label.as_ref(), "temporary:blocklist");
        assert_eq!(batches[0].1[0].source_line, "198.51.100.0/24");
        assert_eq!(batches[1].1.len(), 0);
    }

    #[test]
    fn lookup_returns_typed_matches_invalid_targets_and_config_notice() {
        let mut sources = OfflineLookupRegistry::new();
        sources.register(CachedSource).expect("register");
        let mut batches = Vec::new();
        let outcome = execute(
            &LookupRequest {
                paths: path_input(),
                input: LookupInput::File(PathBuf::from("targets.txt")),
            },
            &LookupDependencies {
                cancellation: &crate::ports::NoCancellation,
                paths: &Paths,
                configs: &MissingConfig,
                target_files: &Targets,
                sources: &sources,
                clock: &TemporaryState,
                temporary_bans: &TemporaryState,
            },
            |target, matches| {
                batches.push((
                    target.to_string(),
                    matches
                        .iter()
                        .map(|entry| (*entry).clone())
                        .collect::<Vec<_>>(),
                ));
                Ok::<(), AppError>(())
            },
        )
        .expect("lookup");

        assert!(outcome.file_mode);
        assert_eq!(outcome.total_count, 2);
        assert_eq!(batches[0].0, "198.51.100.8");
        assert_eq!(batches[0].1.len(), 1);
        assert_eq!(batches[0].1[0].source_label.as_ref(), "cache:test");
        assert_eq!(batches[1].0, "203.0.113.8");
        assert_eq!(batches[1].1.len(), 0);
        assert_eq!(outcome.invalid_targets, ["invalid"]);
        assert_eq!(outcome.notices.len(), 1);
        assert!(
            outcome.notices[0]
                .message
                .contains("config-backed sources unavailable")
        );
    }
}
