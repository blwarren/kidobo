//! Shared blocklist ports and facade for IP and ASN mutation workflows.

mod asn;
mod ban;
mod unban;

pub use asn::{
    AsnBanDependencies, AsnBanOutcome, AsnBanRequest, AsnCacheRemover, AsnConfigEditor,
    AsnConfigUpdate, AsnPrefixBatch, AsnPrefixLoader, AsnUnbanDependencies, AsnUnbanOutcome,
    AsnUnbanRequest, execute_ban_asn, execute_unban_asn,
};
pub use ban::{BanDependencies, BanOutcome, BanRequest, execute_ban};
pub use unban::{
    UnbanApplyDependencies, UnbanDecision, UnbanOutcome, UnbanPreparation,
    UnbanPreparationDependencies, UnbanPreview, UnbanRequest, apply_unban, prepare_unban,
};

#[cfg(test)]
#[path = "blocklist/temporary_tests.rs"]
mod temporary_tests;

use crate::AppError;
use crate::temporary_bans::Clock;
use kidobo_core::blocklist::{BlocklistDocument, parse_blocklist_target};
use kidobo_core::network::CanonicalCidr;
pub use kidobo_core::temporary_bans::BanDuration;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// One target supplied directly or through a bounded line-oriented file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocklistInput {
    /// One operator-supplied IP address or CIDR.
    Single(String),
    /// File containing one target per non-comment line.
    File(PathBuf),
}

/// Per-target result from a successful ban workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanChange {
    /// Canonical target appended to the blocklist.
    Added(String),
    /// Canonical target already present, including an earlier target in the same request.
    AlreadyPresent(String),
    /// An existing permanent entry prevents a temporary downgrade.
    AlreadyPermanent(String),
    /// A new temporary entry was recorded.
    TemporaryAdded {
        /// Canonical target identity.
        target: String,
        /// Absolute expiry in Unix seconds.
        expires_at: u64,
    },
    /// An existing temporary entry received a replacement deadline.
    TemporaryRescheduled {
        /// Canonical target identity.
        target: String,
        /// Replacement expiry in Unix seconds.
        expires_at: u64,
    },
}

/// Persistence boundary for the operator-managed local blocklist.
pub trait BlocklistRepository {
    /// Loads and parses the blocklist at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or contains an invalid entry.
    fn load(&self, path: &Path) -> Result<BlocklistDocument, AppError>;

    /// Appends canonical entries while preserving the document's newline structure.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocklist cannot be updated atomically.
    fn append_entries(
        &self,
        path: &Path,
        entries: &[String],
        has_content: bool,
        trailing_newline: bool,
    ) -> Result<(), AppError>;

    /// Replaces the blocklist with the supplied lines.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocklist cannot be written atomically.
    fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError>;

    /// Reads operator-supplied blocklist targets from a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the target file cannot be read within its configured bound.
    fn read_target_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}

struct TemporaryBanContext<'a> {
    cancellation: &'a dyn crate::ports::Cancellation,
    clock: &'a dyn Clock,
}

fn record_temporary_bans<T: Copy + Eq + std::hash::Hash + Ord>(
    entries: &mut BTreeMap<T, u64>,
    targets: &[T],
    permanent: &HashSet<T>,
    duration: BanDuration,
    path: &Path,
    dependencies: &TemporaryBanContext<'_>,
    render: impl Fn(&T) -> String,
) -> Result<(Vec<BanChange>, bool), AppError> {
    dependencies.cancellation.check()?;
    let has_updates = targets.iter().any(|target| !permanent.contains(target));
    let expires_at = if has_updates {
        duration
            .expires_at(dependencies.clock.now_unix_secs()?)
            .map_err(|error| AppError::TemporaryBans {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?
    } else {
        0
    };
    let mut seen = HashSet::new();
    let changes = targets
        .iter()
        .map(|target| {
            let rendered = render(target);
            if permanent.contains(target) {
                BanChange::AlreadyPermanent(rendered)
            } else if !seen.insert(*target) {
                BanChange::AlreadyPresent(rendered)
            } else if entries.insert(*target, expires_at).is_some() {
                BanChange::TemporaryRescheduled {
                    target: rendered,
                    expires_at,
                }
            } else {
                BanChange::TemporaryAdded {
                    target: rendered,
                    expires_at,
                }
            }
        })
        .collect();
    Ok((changes, has_updates))
}

enum ParsedBlocklistInput {
    Ready(Vec<CanonicalCidr>),
    InvalidTargets(Vec<String>),
    EmptyFile,
}

fn parse_input(
    input: &BlocklistInput,
    repository: &dyn BlocklistRepository,
) -> Result<ParsedBlocklistInput, AppError> {
    let raw = match input {
        BlocklistInput::Single(value) => {
            return parse_blocklist_target(value)
                .map(|target| ParsedBlocklistInput::Ready(vec![target]))
                .map_err(|_| AppError::BlocklistTargetParse {
                    input: value.clone(),
                });
        }
        BlocklistInput::File(path) => repository.read_target_lines(path)?,
    };
    if raw.is_empty() {
        return Ok(ParsedBlocklistInput::EmptyFile);
    }
    let mut targets = Vec::with_capacity(raw.len());
    let mut invalid = Vec::new();
    for value in raw {
        match parse_blocklist_target(&value) {
            Ok(target) => targets.push(target),
            Err(_) => invalid.push(value),
        }
    }
    Ok(if invalid.is_empty() {
        ParsedBlocklistInput::Ready(targets)
    } else {
        ParsedBlocklistInput::InvalidTargets(invalid)
    })
}

fn partial_update_error(
    source: AppError,
    completed: bool,
    temporary_path: &Path,
    permanent_path: &Path,
) -> AppError {
    if completed {
        AppError::PartialBanUpdate {
            completed: temporary_path.to_path_buf(),
            pending: permanent_path.to_path_buf(),
            source: Box::new(source),
        }
    } else {
        source
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use kidobo_core::blocklist::BlocklistDocument;
    use kidobo_core::config::Config;

    use super::{
        AsnCacheRemover, AsnConfigEditor, AsnConfigUpdate, AsnUnbanDependencies, AsnUnbanRequest,
        BanChange, BanDependencies, BanRequest, BlocklistInput, BlocklistRepository, UnbanDecision,
        UnbanRequest, apply_unban, execute_ban, execute_unban_asn, prepare_unban,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, LockGuard, LockManager, PathResolver};

    struct Paths;

    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            _requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
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

    struct Configs;

    struct EmptyTemporary;

    impl crate::temporary_bans::TemporaryBanRepository for EmptyTemporary {
        fn load(&self, _: &Path) -> Result<kidobo_core::temporary_bans::TemporaryBans, AppError> {
            Ok(kidobo_core::temporary_bans::TemporaryBans::default())
        }

        fn save(
            &self,
            _: &Path,
            _: &kidobo_core::temporary_bans::TemporaryBans,
        ) -> Result<(), AppError> {
            panic!("permanent-only test must not save temporary bans");
        }
    }

    struct FixedClock(u64);

    impl crate::temporary_bans::Clock for FixedClock {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            Ok(self.0)
        }
    }

    impl ConfigRepository for Configs {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n").map_err(AppError::from)
        }
    }

    struct Guard;
    impl LockGuard for Guard {}

    #[derive(Default)]
    struct Locks(Mutex<usize>);

    impl LockManager for Locks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            *self.0.lock().expect("locks") += 1;
            Ok(Box::new(Guard))
        }
    }

    struct Repository {
        contents: Mutex<String>,
        target_lines: Mutex<Vec<String>>,
        fail_write: std::sync::atomic::AtomicBool,
    }

    impl Repository {
        fn new(contents: &str) -> Self {
            Self {
                contents: Mutex::new(contents.to_string()),
                target_lines: Mutex::new(Vec::new()),
                fail_write: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl BlocklistRepository for Repository {
        fn load(&self, _path: &Path) -> Result<BlocklistDocument, AppError> {
            BlocklistDocument::parse(&self.contents.lock().expect("contents")).map_err(|error| {
                AppError::BlocklistParseLine {
                    path: PathBuf::from("/root/data/blocklist.txt"),
                    line: error.line_number,
                    content: error.content,
                }
            })
        }

        fn append_entries(
            &self,
            _path: &Path,
            entries: &[String],
            has_content: bool,
            trailing_newline: bool,
        ) -> Result<(), AppError> {
            let mut contents = self.contents.lock().expect("contents");
            if has_content && !trailing_newline {
                contents.push('\n');
            }
            for entry in entries {
                contents.push_str(entry);
                contents.push('\n');
            }
            Ok(())
        }

        fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError> {
            if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AppError::BlocklistWrite {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("injected write failure"),
                });
            }
            let mut rendered = lines.join("\n");
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            *self.contents.lock().expect("contents") = rendered;
            Ok(())
        }

        fn read_target_lines(&self, _path: &Path) -> Result<Vec<String>, AppError> {
            Ok(self.target_lines.lock().expect("targets").clone())
        }
    }

    fn request_input() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    fn dependencies<'a>(repository: &'a Repository, locks: &'a Locks) -> BanDependencies<'a> {
        BanDependencies {
            cancellation: &crate::ports::NoCancellation,
            paths: &Paths,
            configs: &Configs,
            locks,
            repository,
            temporary_bans: &EmptyTemporary,
            clock: &FixedClock(1000),
        }
    }

    fn preparation_dependencies<'a>(
        deps: &BanDependencies<'a>,
    ) -> super::UnbanPreparationDependencies<'a> {
        super::UnbanPreparationDependencies {
            cancellation: deps.cancellation,
            paths: deps.paths,
            configs: deps.configs,
            repository: deps.repository,
            temporary_bans: deps.temporary_bans,
        }
    }

    fn apply_dependencies<'a>(deps: &BanDependencies<'a>) -> super::UnbanApplyDependencies<'a> {
        super::UnbanApplyDependencies {
            cancellation: deps.cancellation,
            paths: deps.paths,
            configs: deps.configs,
            locks: deps.locks,
            repository: deps.repository,
            temporary_bans: deps.temporary_bans,
        }
    }

    #[derive(Default)]
    struct TemporaryRepository {
        state: Mutex<kidobo_core::temporary_bans::TemporaryBans>,
        fail_save: std::sync::atomic::AtomicBool,
    }

    impl crate::temporary_bans::TemporaryBanRepository for TemporaryRepository {
        fn load(&self, _: &Path) -> Result<kidobo_core::temporary_bans::TemporaryBans, AppError> {
            Ok(self.state.lock().expect("state").clone())
        }

        fn save(
            &self,
            path: &Path,
            state: &kidobo_core::temporary_bans::TemporaryBans,
        ) -> Result<(), AppError> {
            if self.fail_save.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AppError::TemporaryBans {
                    path: path.to_path_buf(),
                    reason: "injected failure".into(),
                });
            }
            *self.state.lock().expect("state") = state.clone();
            Ok(())
        }
    }

    fn cidr(text: &str) -> kidobo_core::network::CanonicalCidr {
        kidobo_core::network::parse_ip_cidr_strict(text).expect("CIDR")
    }

    #[test]
    fn temporary_file_ban_shares_deadline_replaces_it_and_preserves_permanent_entries() {
        let repository = Repository::new("203.0.113.7\n");
        *repository.target_lines.lock().expect("targets") = vec![
            "203.0.113.7".into(),
            "198.51.100.9".into(),
            "2001:db8::/48".into(),
        ];
        let temporary = TemporaryRepository::default();
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let mut request = BanRequest {
            paths: request_input(),
            input: BlocklistInput::File("targets.txt".into()),
            duration: Some("3d".parse().expect("duration")),
        };
        let result = execute_ban(&request, &dependencies).expect("temporary file ban");
        let super::BanOutcome::TemporaryApplied { changes, .. } = result else {
            panic!("temporary result")
        };
        assert_eq!(
            changes,
            vec![
                BanChange::AlreadyPermanent("203.0.113.7/32".into()),
                BanChange::TemporaryAdded {
                    target: "198.51.100.9/32".into(),
                    expires_at: 260_200
                },
                BanChange::TemporaryAdded {
                    target: "2001:db8::/48".into(),
                    expires_at: 260_200
                },
            ]
        );
        request.duration = Some("1h".parse().expect("duration"));
        let result = execute_ban(&request, &dependencies).expect("shorten");
        let super::BanOutcome::TemporaryApplied { changes, .. } = result else {
            panic!("temporary result")
        };
        assert_eq!(
            changes[1],
            BanChange::TemporaryRescheduled {
                target: "198.51.100.9/32".into(),
                expires_at: 4600
            }
        );
        assert_eq!(
            temporary.state.lock().expect("state").ips,
            [(cidr("198.51.100.9"), 4600), (cidr("2001:db8::/48"), 4600)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        request.duration = None;
        execute_ban(&request, &dependencies).expect("make permanent");
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n198.51.100.9/32\n2001:db8::/48\n"
        );
        assert_eq!(temporary.state.lock().expect("state").ips.len(), 2);
    }

    #[test]
    fn unban_revalidates_temporary_deadlines_and_handles_both_store_failures() {
        use std::sync::atomic::Ordering;
        let repository = Repository::new("203.0.113.7\n");
        let temporary = TemporaryRepository::default();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.7"), 4600);
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".into()),
        };
        let decision = UnbanDecision {
            remove_partial: false,
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("preview")
        };
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.7"), 5600);
        assert!(matches!(
            apply_unban(
                &request,
                &preview,
                &decision,
                &apply_dependencies(&dependencies)
            ),
            Err(AppError::BlocklistChanged)
        ));
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("preview")
        };
        temporary.fail_save.store(true, Ordering::SeqCst);
        assert!(matches!(
            apply_unban(
                &request,
                &preview,
                &decision,
                &apply_dependencies(&dependencies)
            ),
            Err(AppError::TemporaryBans { .. })
        ));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        assert_eq!(
            temporary.state.lock().expect("state").ips[&cidr("203.0.113.7")],
            5600
        );
        temporary.fail_save.store(false, Ordering::SeqCst);
        repository.fail_write.store(true, Ordering::SeqCst);
        let error = apply_unban(
            &request,
            &preview,
            &decision,
            &apply_dependencies(&dependencies),
        )
        .expect_err("second store failure");
        assert!(matches!(error, AppError::PartialBanUpdate { .. }));
        assert!(error.to_string().contains("rerun"));
        assert!(temporary.state.lock().expect("state").ips.is_empty());
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        repository.fail_write.store(false, Ordering::SeqCst);
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies))
                .expect("retry preview")
        else {
            panic!("preview")
        };
        assert_eq!(
            apply_unban(
                &request,
                &preview,
                &decision,
                &apply_dependencies(&dependencies)
            )
            .expect("retry")
            .removed_exact,
            1
        );
        assert!(repository.contents.lock().expect("contents").is_empty());
    }

    #[test]
    fn temporary_partial_unban_respects_confirmation_and_leaves_asns() {
        let repository = Repository::new("");
        let temporary = TemporaryRepository::default();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.0/24"), 4600);
        temporary
            .state
            .lock()
            .expect("state")
            .asns
            .insert(64496, 4600);
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".into()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("preview")
        };
        assert_eq!(
            preview.partial_entries,
            ["203.0.113.0/24 (temporary, expires at Unix 4600)"]
        );
        assert_eq!(
            apply_unban(
                &request,
                &preview,
                &UnbanDecision {
                    remove_partial: false
                },
                &apply_dependencies(&dependencies)
            )
            .expect("decline")
            .total_removed(),
            0
        );
        assert_eq!(temporary.state.lock().expect("state").ips.len(), 1);
        assert_eq!(
            apply_unban(
                &request,
                &preview,
                &UnbanDecision {
                    remove_partial: true
                },
                &apply_dependencies(&dependencies)
            )
            .expect("approve")
            .removed_partial,
            1
        );
        assert!(temporary.state.lock().expect("state").ips.is_empty());
        assert_eq!(
            temporary.state.lock().expect("state").asns,
            [(64496, 4600)].into_iter().collect()
        );
    }

    #[test]
    fn cancellation_after_configuration_or_preview_preserves_blocklist() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancellingConfigs<'a>(&'a AtomicBool);
        impl ConfigRepository for CancellingConfigs<'_> {
            fn load(&self, path: &Path) -> Result<Config, AppError> {
                self.0.store(true, Ordering::SeqCst);
                Configs.load(path)
            }
        }
        let repository = Repository::new("203.0.113.0/24\n");
        let locks = Locks::default();
        let cancelled = AtomicBool::new(false);
        let configs = CancellingConfigs(&cancelled);
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.cancellation = &cancelled;
        dependencies.configs = &configs;
        let result = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::Single("198.51.100.1".to_string()),
            },
            &dependencies,
        );
        assert!(matches!(result, Err(AppError::Interrupted)));
        cancelled.store(false, Ordering::SeqCst);
        dependencies.configs = &Configs;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("expected preview");
        };
        cancelled.store(true, Ordering::SeqCst);
        let result = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: true,
            },
            &apply_dependencies(&dependencies),
        );
        assert!(matches!(result, Err(AppError::Interrupted)));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.0/24\n"
        );
    }

    #[test]
    fn ban_classifies_existing_and_appends_only_new_entries() {
        let repository = Repository::new("# header\n192.0.2.0/24");
        let locks = Locks::default();
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &{
                *repository.target_lines.lock().expect("targets") = vec![
                    "192.0.2.0/24".to_string(),
                    "2001:db8::/64".to_string(),
                    "2001:db8::/64".to_string(),
                ];
                dependencies(&repository, &locks)
            },
        )
        .expect("ban");

        assert_eq!(
            outcome,
            super::BanOutcome::Applied(vec![
                BanChange::AlreadyPresent("192.0.2.0/24".to_string()),
                BanChange::Added("2001:db8::/64".to_string()),
                BanChange::AlreadyPresent("2001:db8::/64".to_string()),
            ])
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "# header\n192.0.2.0/24\n2001:db8::/64\n"
        );
        assert_eq!(*locks.0.lock().expect("locks"), 1);
    }

    #[test]
    fn file_ban_reports_all_invalid_targets_without_mutating() {
        let repository = Repository::new("192.0.2.0/24\n");
        *repository.target_lines.lock().expect("targets") = vec![
            "bad-one".to_string(),
            "198.51.100.7".to_string(),
            "bad-two".to_string(),
        ];
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &dependencies(&repository, &Locks::default()),
        )
        .expect("typed invalid outcome");

        assert_eq!(
            outcome,
            super::BanOutcome::InvalidTargets(vec!["bad-one".into(), "bad-two".into()])
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "192.0.2.0/24\n"
        );
    }

    #[test]
    fn empty_file_and_invalid_single_bans_leave_blocklist_unchanged() {
        let repository = Repository::new("192.0.2.0/24\n");
        let locks = Locks::default();
        let dependencies = dependencies(&repository, &locks);
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &dependencies,
        )
        .expect("empty file outcome");
        assert_eq!(outcome, super::BanOutcome::EmptyFile);
        let error = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::Single("bad-target".into()),
            },
            &dependencies,
        )
        .expect_err("invalid single target");
        assert!(matches!(error, AppError::BlocklistTargetParse { input } if input == "bad-target"));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "192.0.2.0/24\n"
        );
    }

    #[test]
    fn unban_applies_exact_and_user_approved_partial_matches() {
        let repository = Repository::new(
            "# header\n10.0.0.0/24\n\n10.0.0.1/32\n  192.0.2.0/24  \n# retained comment\n",
        );
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("10.0.0.1".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) = prepare_unban(
            &request,
            &preparation_dependencies(&dependencies(&repository, &locks)),
        )
        .expect("preview") else {
            panic!("expected preview");
        };
        assert_eq!(preview.exact_entries, ["10.0.0.1/32"]);
        assert_eq!(preview.partial_entries, ["10.0.0.0/24"]);

        let outcome = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: true,
            },
            &apply_dependencies(&dependencies(&repository, &locks)),
        )
        .expect("apply");

        assert_eq!(outcome.removed_exact, 1);
        assert_eq!(outcome.removed_partial, 1);
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "# header\n\n  192.0.2.0/24  \n# retained comment\n"
        );
    }

    #[test]
    fn unban_reloads_after_lock_and_rejects_changed_preview() {
        let repository = Repository::new("10.0.0.0/24\n");
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("10.0.0.1".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) = prepare_unban(
            &request,
            &preparation_dependencies(&dependencies(&repository, &locks)),
        )
        .expect("prepare") else {
            panic!("expected preview")
        };
        *repository.contents.lock().expect("contents") = "10.0.0.0/16\n".to_string();

        let error = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: false,
            },
            &apply_dependencies(&dependencies(&repository, &locks)),
        )
        .expect_err("race must fail");

        assert!(matches!(error, AppError::BlocklistChanged));
        assert_eq!(*locks.0.lock().expect("locks"), 1);
    }

    #[test]
    fn file_unban_distinguishes_empty_invalid_and_ready_without_mutating() {
        let repository = Repository::new("203.0.113.0/24\n");
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::File(PathBuf::from("targets.txt")),
        };
        let dependencies = dependencies(&repository, &locks);
        assert_eq!(
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("empty file"),
            super::UnbanPreparation::EmptyFile
        );

        *repository.target_lines.lock().expect("targets") =
            vec!["bad-one".into(), "203.0.113.7".into(), "bad-two".into()];
        assert_eq!(
            prepare_unban(&request, &preparation_dependencies(&dependencies))
                .expect("invalid file"),
            super::UnbanPreparation::InvalidTargets(vec!["bad-one".into(), "bad-two".into()])
        );

        *repository.target_lines.lock().expect("targets") = vec!["198.51.100.7".into()];
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("valid file")
        else {
            panic!("valid unmatched targets still need a preview");
        };
        assert_eq!(preview.requested_target_count, 1);
        assert_eq!(preview.exact_entries, Vec::<String>::new());
        assert_eq!(preview.partial_entries, Vec::<String>::new());
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.0/24\n"
        );
        assert_eq!(*locks.0.lock().expect("locks"), 0);
    }

    #[test]
    fn file_unban_deduplicates_canonical_targets_before_preview_and_removal() {
        let repository = Repository::new("203.0.113.0/24\n198.51.100.0/24\n");
        *repository.target_lines.lock().expect("targets") = vec![
            "203.0.113.7/24".into(),
            "203.0.113.0/24".into(),
            "198.51.100.7".into(),
            "198.51.100.7/32".into(),
        ];
        let locks = Locks::default();
        let dependencies = dependencies(&repository, &locks);
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::File(PathBuf::from("targets.txt")),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("valid targets");
        };
        assert_eq!(preview.requested_target_count, 2);
        assert_eq!(preview.target_label, "2 file target(s)");
        assert_eq!(preview.exact_entries, ["203.0.113.0/24"]);
        assert_eq!(preview.partial_entries, ["198.51.100.0/24"]);

        let outcome = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: false,
            },
            &apply_dependencies(&dependencies),
        )
        .expect("remove exact matches");
        assert_eq!(outcome.requested_target_count, 2);
        assert_eq!(outcome.removed_exact, 1);
        assert_eq!(outcome.removed_partial, 0);
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "198.51.100.0/24\n"
        );
    }

    #[test]
    fn unban_uses_fresh_indexes_after_unrelated_source_positions_change() {
        let repository = Repository::new("203.0.113.7\n198.51.100.0/24\n");
        let temporary = TemporaryRepository::default();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .extend([(cidr("203.0.113.7"), 4600), (cidr("2001:db8::1"), 5000)]);
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".into()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &preparation_dependencies(&dependencies)).expect("preview")
        else {
            panic!("valid target");
        };
        *repository.contents.lock().expect("contents") =
            "# new comment\n198.51.100.0/24\n203.0.113.7\n".into();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("192.0.2.1"), 6000);

        let outcome = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: false,
            },
            &apply_dependencies(&dependencies),
        )
        .expect("only unmatched state changed");
        assert_eq!(outcome.removed_exact, 2);
        assert_eq!(outcome.removed_partial, 0);
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "# new comment\n198.51.100.0/24\n"
        );
        assert_eq!(
            temporary.state.lock().expect("state").ips,
            [(cidr("192.0.2.1"), 6000), (cidr("2001:db8::1"), 5000),]
                .into_iter()
                .collect()
        );
    }

    // Drop records lock release, making the ledger sensitive to deletion occurring one statement
    // too late even though both operations would otherwise succeed in a sequential unit test.
    struct EventGuard(Arc<Mutex<Vec<&'static str>>>);

    impl LockGuard for EventGuard {}

    impl Drop for EventGuard {
        fn drop(&mut self) {
            self.0.lock().expect("events").push("unlock");
        }
    }

    struct EventLocks(Arc<Mutex<Vec<&'static str>>>);

    impl LockManager for EventLocks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            self.0.lock().expect("events").push("lock");
            Ok(Box::new(EventGuard(Arc::clone(&self.0))))
        }
    }

    struct EventAsn(Arc<Mutex<Vec<&'static str>>>);

    impl AsnConfigEditor for EventAsn {
        fn update_config(
            &self,
            _config_path: &Path,
            _add: &[u32],
            _remove: &[u32],
        ) -> Result<AsnConfigUpdate, AppError> {
            self.0.lock().expect("events").push("update");
            Ok(AsnConfigUpdate {
                added: Vec::new(),
                removed: vec![64512],
            })
        }
    }

    impl AsnCacheRemover for EventAsn {
        fn delete_cache(&self, _asn: u32, _cache_dir: &Path) -> Result<bool, AppError> {
            self.0.lock().expect("events").push("delete");
            Ok(true)
        }
    }

    #[test]
    fn asn_unban_holds_the_process_lock_through_cache_deletion() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let locks = EventLocks(Arc::clone(&events));
        let asn = EventAsn(Arc::clone(&events));
        let dependencies = AsnUnbanDependencies {
            cancellation: &crate::ports::NoCancellation,
            paths: &Paths,
            configs: &Configs,
            locks: &locks,
            config_editor: &asn,
            cache_remover: &asn,
            temporary_bans: &EmptyTemporary,
        };

        let outcome = execute_unban_asn(
            &AsnUnbanRequest {
                paths: request_input(),
                tokens: vec!["As64512".to_string()],
            },
            &dependencies,
        )
        .expect("unban ASN");

        assert_eq!(outcome.removed, [64512]);
        assert_eq!(outcome.deleted_cache_files, 1);
        assert_eq!(
            *events.lock().expect("events"),
            ["lock", "update", "delete", "unlock"]
        );
    }
}
