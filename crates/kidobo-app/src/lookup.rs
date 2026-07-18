use std::collections::BTreeSet;
use std::path::PathBuf;

use kidobo_core::lookup::{LookupMatch, parse_target_strict, run_lookup};

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, PathResolver, TargetFileReader};
use crate::source::{Notice, OfflineLookupContext, OfflineLookupRegistry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupInput {
    Single(String),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupRequest {
    pub paths: PathResolutionInput,
    pub input: LookupInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOutcome {
    pub targets: Vec<String>,
    pub valid_targets: BTreeSet<String>,
    pub matches: Vec<LookupMatch>,
    pub invalid_targets: Vec<String>,
    pub file_mode: bool,
    pub notices: Vec<Notice>,
}

pub struct LookupDependencies<'a> {
    pub paths: &'a dyn PathResolver,
    pub configs: &'a dyn ConfigRepository,
    pub target_files: &'a dyn TargetFileReader,
    pub sources: &'a OfflineLookupRegistry,
}

pub fn execute(
    request: &LookupRequest,
    dependencies: &LookupDependencies<'_>,
) -> Result<LookupOutcome, AppError> {
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Optional)?;
    let (config, notices) = match dependencies.configs.load(&paths.config_file) {
        Ok(config) => (Some(config), Vec::new()),
        Err(error) => (
            None,
            vec![Notice::warning(format!(
                "lookup config-backed sources unavailable; checking only local and cached remote sources: {error}"
            ))],
        ),
    };

    let (targets, file_mode) = match &request.input {
        LookupInput::Single(target) => (vec![target.clone()], false),
        LookupInput::File(path) => (dependencies.target_files.read_lines(path)?, true),
    };

    let context = OfflineLookupContext {
        paths: &paths,
        config: config.as_ref(),
    };
    let source_entries = dependencies.sources.load(&context)?;

    let report = run_lookup(&targets, &source_entries);
    let valid_targets = targets
        .iter()
        .filter_map(|target| parse_target_strict(target).ok().map(|_| target.clone()))
        .collect::<BTreeSet<_>>();

    Ok(LookupOutcome {
        targets,
        valid_targets,
        matches: report.matches,
        invalid_targets: report.invalid_targets,
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

    use super::{LookupDependencies, LookupInput, LookupRequest, execute};
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, PathResolver, TargetFileReader};
    use crate::source::{OfflineLookupContext, OfflineLookupProvider, OfflineLookupRegistry};

    struct Paths;
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Optional);
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

        fn load_offline(
            &self,
            _context: &OfflineLookupContext<'_>,
        ) -> Result<Vec<LookupSourceEntry>, AppError> {
            Ok(vec![LookupSourceEntry {
                source_label: Arc::from("cache:test"),
                source_line: "198.51.100.0/24".to_string(),
                cidr: parse_ip_cidr_token("198.51.100.0/24").expect("cidr"),
            }])
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
    fn lookup_returns_typed_matches_invalid_targets_and_config_notice() {
        let mut sources = OfflineLookupRegistry::new();
        sources.register(CachedSource).expect("register");
        let outcome = execute(
            &LookupRequest {
                paths: path_input(),
                input: LookupInput::File(PathBuf::from("targets.txt")),
            },
            &LookupDependencies {
                paths: &Paths,
                configs: &MissingConfig,
                target_files: &Targets,
                sources: &sources,
            },
        )
        .expect("lookup");

        assert!(outcome.file_mode);
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].target, "198.51.100.8");
        assert_eq!(outcome.invalid_targets, ["invalid"]);
        assert_eq!(outcome.valid_targets.len(), 2);
        assert_eq!(outcome.notices.len(), 1);
        assert!(
            outcome.notices[0]
                .message
                .contains("config-backed sources unavailable")
        );
    }
}
