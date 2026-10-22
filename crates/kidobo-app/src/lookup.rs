//! Deterministic offline lookup workflow and presentation-oriented outcomes.

use std::path::PathBuf;
use std::sync::Arc;

use kidobo_core::lookup::run_lookup_by_target;
use kidobo_core::network::CanonicalCidr;

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

/// One source entry overlapping a valid lookup target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupSourceMatch {
    /// Stable operator-visible source label.
    pub source_label: Arc<str>,
    /// Original matched source line.
    pub matched_source_entry: String,
    /// Canonical CIDR used for overlap matching.
    pub matched_cidr: CanonicalCidr,
}

/// A valid lookup target and its deterministic matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupTargetOutcome {
    /// Original target text.
    pub target: String,
    /// Source matches sorted by source identity and entry.
    pub matches: Vec<LookupSourceMatch>,
}

/// Complete offline lookup result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOutcome {
    /// Valid targets and their matches in deterministic target order.
    pub targets: Vec<LookupTargetOutcome>,
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
/// offline source cannot be loaded. Configuration-loading failures remain soft notices.
pub fn execute(
    request: &LookupRequest,
    dependencies: &LookupDependencies<'_>,
) -> Result<LookupOutcome, AppError> {
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

    let mut target_outcomes = Vec::with_capacity(targets.len());
    let invalid_targets = run_lookup_by_target(&targets, &source_entries, |target, matches| {
        target_outcomes.push(LookupTargetOutcome {
            target: target.to_string(),
            matches: matches
                .iter()
                .map(|source| LookupSourceMatch {
                    source_label: Arc::clone(&source.source_label),
                    matched_source_entry: source.source_line.clone(),
                    matched_cidr: source.cidr,
                })
                .collect(),
        });
    });

    Ok(LookupOutcome {
        targets: target_outcomes,
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
        )
        .expect("lookup");
        assert_eq!(snapshot.clock_calls.get(), 1);
        assert_eq!(snapshot.load_calls.get(), 1);
        assert_eq!(
            outcome.targets[0].matches[0].source_label.as_ref(),
            "temporary:blocklist"
        );
        assert_eq!(
            outcome.targets[0].matches[0].matched_source_entry,
            "198.51.100.0/24"
        );
        assert_eq!(outcome.targets[1].matches.len(), 0);
    }

    #[test]
    fn lookup_returns_typed_matches_invalid_targets_and_config_notice() {
        let mut sources = OfflineLookupRegistry::new();
        sources.register(CachedSource).expect("register");
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
        )
        .expect("lookup");

        assert!(outcome.file_mode);
        assert_eq!(outcome.targets.len(), 2);
        assert_eq!(outcome.targets[0].target, "198.51.100.8");
        assert_eq!(outcome.targets[0].matches.len(), 1);
        assert_eq!(
            outcome.targets[0].matches[0].source_label.as_ref(),
            "cache:test"
        );
        assert_eq!(outcome.targets[1].target, "203.0.113.8");
        assert_eq!(outcome.targets[1].matches.len(), 0);
        assert_eq!(outcome.invalid_targets, ["invalid"]);
        assert_eq!(outcome.notices.len(), 1);
        assert!(
            outcome.notices[0]
                .message
                .contains("config-backed sources unavailable")
        );
    }
}
