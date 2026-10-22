//! ASN workflow regressions using in-memory sources and a controlled clock.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use kidobo_core::blocklist::BlocklistDocument;
use kidobo_core::config::Config;
use kidobo_core::network::parse_ip_cidr_strict;
use kidobo_core::temporary_bans::TemporaryBans;

use crate::AppError;
use crate::blocklist::{
    AsnBanDependencies, AsnBanRequest, AsnCacheRemover, AsnConfigEditor, AsnConfigUpdate,
    AsnPrefixBatch, AsnPrefixLoader, AsnUnbanDependencies, AsnUnbanRequest, BanChange,
    BlocklistRepository, execute_ban_asn, execute_unban_asn,
};
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
use crate::ports::{ConfigRepository, LockGuard, LockManager, NoCancellation, PathResolver};
use crate::temporary_bans::{Clock, TemporaryBanRepository};

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Lock,
    Unlock,
    Resolve(u32),
    Clock,
    TemporarySave,
    ConfigWrite,
    CacheDelete(u32),
    BlocklistRead,
    BlocklistWrite,
}

#[derive(Default)]
struct Harness {
    events: Rc<RefCell<Vec<Event>>>,
    locked: Rc<Cell<bool>>,
    state: RefCell<TemporaryBans>,
    permanent_asns: RefCell<BTreeSet<u32>>,
    blocklist: RefCell<String>,
    now: Cell<u64>,
    fail_resolve: Cell<Option<u32>>,
    fail_temporary_save: Cell<bool>,
    fail_config_write: Cell<bool>,
    caches: RefCell<BTreeSet<u32>>,
}

impl Harness {
    fn new() -> Self {
        Self {
            now: Cell::new(1000),
            blocklist: RefCell::new("203.0.113.0/24\n".to_owned()),
            ..Self::default()
        }
    }

    fn ban_dependencies(&self) -> AsnBanDependencies<'_> {
        AsnBanDependencies {
            cancellation: &NoCancellation,
            paths: self,
            configs: self,
            locks: self,
            repository: self,
            prefix_loader: self,
            config_editor: self,
            temporary_bans: self,
            clock: self,
        }
    }

    fn unban_dependencies(&self) -> AsnUnbanDependencies<'_> {
        AsnUnbanDependencies {
            cancellation: &NoCancellation,
            paths: self,
            configs: self,
            locks: self,
            temporary_bans: self,
            config_editor: self,
            cache_remover: self,
        }
    }

    fn record(&self, event: Event) {
        assert!(
            self.locked.get(),
            "operation outside process lock: {event:?}"
        );
        self.events.borrow_mut().push(event);
    }
}

impl PathResolver for Harness {
    fn resolve(
        &self,
        _: &PathResolutionInput,
        _: ConfigRequirement,
    ) -> Result<ResolvedPaths, AppError> {
        Ok(ResolvedPaths {
            root_override: Some(PathBuf::from("/fixture")),
            config_dir: PathBuf::from("/fixture/config"),
            config_file: PathBuf::from("/fixture/config/config.toml"),
            data_dir: PathBuf::from("/fixture/data"),
            blocklist_file: PathBuf::from("/fixture/data/blocklist.txt"),
            cache_dir: PathBuf::from("/fixture/cache"),
            remote_cache_dir: PathBuf::from("/fixture/cache/remote"),
            lock_file: PathBuf::from("/fixture/cache/lock"),
        })
    }
}

impl ConfigRepository for Harness {
    fn load(&self, _: &Path) -> Result<Config, AppError> {
        let mut config = Config::from_toml_str("[ipset]\nset_name='kidobo'\n")?;
        config.asn.banned = self.permanent_asns.borrow().iter().copied().collect();
        Ok(config)
    }
}

struct Guard {
    events: Rc<RefCell<Vec<Event>>>,
    locked: Rc<Cell<bool>>,
}

impl LockGuard for Guard {}

impl Drop for Guard {
    fn drop(&mut self) {
        assert!(self.locked.replace(false));
        self.events.borrow_mut().push(Event::Unlock);
    }
}

impl LockManager for Harness {
    fn acquire(&self, _: &Path) -> Result<Box<dyn LockGuard>, AppError> {
        assert!(!self.locked.replace(true));
        self.record(Event::Lock);
        Ok(Box::new(Guard {
            events: Rc::clone(&self.events),
            locked: Rc::clone(&self.locked),
        }))
    }
}

impl Clock for Harness {
    fn now_unix_secs(&self) -> Result<u64, AppError> {
        self.record(Event::Clock);
        Ok(self.now.get())
    }
}

impl TemporaryBanRepository for Harness {
    fn load(&self, _: &Path) -> Result<TemporaryBans, AppError> {
        assert!(self.locked.get());
        Ok(self.state.borrow().clone())
    }

    fn save(&self, path: &Path, state: &TemporaryBans) -> Result<(), AppError> {
        self.record(Event::TemporarySave);
        if self.fail_temporary_save.get() {
            return Err(AppError::TemporaryBans {
                path: path.to_path_buf(),
                reason: "injected temporary save failure".to_owned(),
            });
        }
        *self.state.borrow_mut() = state.clone();
        Ok(())
    }
}

impl AsnPrefixLoader for Harness {
    fn load_prefixes(&self, asn: u32, _: &Path, _: Duration) -> Result<AsnPrefixBatch, AppError> {
        self.record(Event::Resolve(asn));
        self.now.set(self.now.get() + 60);
        if self.fail_resolve.get() == Some(asn) {
            return Err(AppError::Asn {
                source: Box::new(std::io::Error::other("injected prefix failure")),
            });
        }
        self.caches.borrow_mut().insert(asn);
        Ok(AsnPrefixBatch {
            prefixes: vec![parse_ip_cidr_strict("203.0.113.0/24").expect("prefix")],
            stale: false,
        })
    }
}

impl AsnConfigEditor for Harness {
    fn update_config(
        &self,
        path: &Path,
        add: &[u32],
        remove: &[u32],
    ) -> Result<AsnConfigUpdate, AppError> {
        self.record(Event::ConfigWrite);
        if self.fail_config_write.get() {
            return Err(AppError::ConfigWrite {
                path: path.to_path_buf(),
                source: std::io::Error::other("injected config write failure"),
            });
        }
        let mut permanent = self.permanent_asns.borrow_mut();
        Ok(AsnConfigUpdate {
            added: add
                .iter()
                .copied()
                .filter(|asn| permanent.insert(*asn))
                .collect(),
            removed: remove
                .iter()
                .copied()
                .filter(|asn| permanent.remove(asn))
                .collect(),
        })
    }
}

impl AsnCacheRemover for Harness {
    fn delete_cache(&self, asn: u32, _: &Path) -> Result<bool, AppError> {
        self.record(Event::CacheDelete(asn));
        Ok(self.caches.borrow_mut().remove(&asn))
    }
}

impl BlocklistRepository for Harness {
    fn load(&self, _: &Path) -> Result<BlocklistDocument, AppError> {
        self.record(Event::BlocklistRead);
        Ok(BlocklistDocument::parse(&self.blocklist.borrow()).expect("fixture blocklist"))
    }

    fn append_entries(&self, _: &Path, _: &[String], _: bool, _: bool) -> Result<(), AppError> {
        panic!("ASN operations must not append local IP entries");
    }

    fn write_lines(&self, _: &Path, lines: &[String]) -> Result<(), AppError> {
        self.record(Event::BlocklistWrite);
        *self.blocklist.borrow_mut() = lines.join("\n");
        Ok(())
    }

    fn read_target_lines(&self, _: &Path) -> Result<Vec<String>, AppError> {
        panic!("ASN operations must not read target files");
    }
}

fn request(tokens: &[&str], duration: Option<&str>) -> AsnBanRequest {
    AsnBanRequest {
        paths: PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/fixture/tmp"),
            env: BTreeMap::new(),
        },
        tokens: tokens.iter().map(|token| (*token).to_owned()).collect(),
        duration: duration.map(|value| value.parse().expect("duration")),
    }
}

fn unban_request(tokens: &[&str]) -> AsnUnbanRequest {
    let ban = request(tokens, None);
    AsnUnbanRequest {
        paths: ban.paths,
        tokens: ban.tokens,
    }
}

#[test]
fn second_asn_resolution_failure_does_not_save_any_ban() {
    let fixture = Harness::new();
    fixture.fail_resolve.set(Some(64497));
    fixture.state.borrow_mut().asns.insert(64498, 5000);
    let original = fixture.state.borrow().clone();
    let result = execute_ban_asn(
        &request(&["AS64496", "64497"], Some("3h")),
        &fixture.ban_dependencies(),
    );
    assert!(matches!(result, Err(AppError::Asn { .. })));
    assert_eq!(*fixture.state.borrow(), original);
    assert!(fixture.permanent_asns.borrow().is_empty());
    assert_eq!(
        *fixture.events.borrow(),
        [
            Event::Lock,
            Event::Resolve(64496),
            Event::Resolve(64497),
            Event::Unlock
        ]
    );
    assert_eq!(*fixture.caches.borrow(), BTreeSet::from([64496]));
}

#[test]
fn invalid_asn_tokens_fail_before_lock_or_any_side_effects() {
    let fixture = Harness::new();
    let request = request(&["AS64496", "AS0"], None);
    for result in [
        execute_ban_asn(&request, &fixture.ban_dependencies()).map(|_| ()),
        execute_unban_asn(
            &unban_request(&["AS64496", "AS0"]),
            &fixture.unban_dependencies(),
        )
        .map(|_| ()),
    ] {
        let error = result.expect_err("invalid ASN");
        assert_eq!(
            error.to_string(),
            "ASN operation failed: invalid ASN token `AS0`"
        );
        assert!(matches!(error, AppError::Asn { .. }));
    }
    assert!(fixture.events.borrow().is_empty());
    assert!(fixture.state.borrow().asns.is_empty());
    assert!(fixture.permanent_asns.borrow().is_empty());
    assert!(fixture.caches.borrow().is_empty());
}

#[test]
fn temporary_asn_batch_samples_one_deadline_after_validation_and_preserves_ip_bans() {
    let fixture = Harness::new();
    fixture
        .state
        .borrow_mut()
        .ips
        .insert(parse_ip_cidr_strict("2001:db8::/48").expect("prefix"), 9999);
    let original_ips = fixture.state.borrow().ips.clone();
    let outcome = execute_ban_asn(
        &request(&["aS64497", "AS64496", "As64496", "64497"], Some("1h")),
        &fixture.ban_dependencies(),
    )
    .expect("temporary ban");
    assert_eq!(
        fixture.state.borrow().asns,
        BTreeMap::from([(64496, 4720), (64497, 4720)])
    );
    assert_eq!(fixture.state.borrow().ips, original_ips);
    assert_eq!(
        outcome.temporary_changes,
        [
            BanChange::TemporaryAdded {
                target: "AS64496".to_owned(),
                expires_at: 4720
            },
            BanChange::TemporaryAdded {
                target: "AS64497".to_owned(),
                expires_at: 4720
            },
        ]
    );
    assert_eq!(*fixture.blocklist.borrow(), "203.0.113.0/24\n");
    assert!(fixture.permanent_asns.borrow().is_empty());
    assert_eq!(outcome.removed_duplicate_entries, 0);
    assert_eq!(
        *fixture.events.borrow(),
        [
            Event::Lock,
            Event::Resolve(64496),
            Event::Resolve(64497),
            Event::Clock,
            Event::TemporarySave,
            Event::Unlock
        ]
    );
}

#[test]
fn already_permanent_asn_cannot_be_downgraded_and_does_not_save_temporary_state() {
    let fixture = Harness::new();
    fixture.permanent_asns.borrow_mut().extend([64496, 64498]);
    let outcome = execute_ban_asn(
        &request(&["AS64496"], Some("1h")),
        &fixture.ban_dependencies(),
    )
    .expect("permanent ban retained");
    assert_eq!(
        outcome.temporary_changes,
        [BanChange::AlreadyPermanent("AS64496".to_owned())]
    );
    assert_eq!(*fixture.state.borrow(), TemporaryBans::default());
    assert_eq!(
        *fixture.permanent_asns.borrow(),
        BTreeSet::from([64496, 64498])
    );
    assert_eq!(
        *fixture.events.borrow(),
        [Event::Lock, Event::Resolve(64496), Event::Unlock]
    );
}

#[test]
fn repeating_temporary_asn_ban_replaces_deadline_with_a_shorter_one() {
    let fixture = Harness::new();
    execute_ban_asn(
        &request(&["AS64496"], Some("2d")),
        &fixture.ban_dependencies(),
    )
    .expect("first ban");
    let first_deadline = fixture.state.borrow().asns[&64496];
    let outcome = execute_ban_asn(
        &request(&["AS64496"], Some("1h")),
        &fixture.ban_dependencies(),
    )
    .expect("reschedule");
    assert_eq!(fixture.state.borrow().asns[&64496], 4720);
    assert!(first_deadline > fixture.state.borrow().asns[&64496]);
    assert_eq!(
        outcome.temporary_changes,
        [BanChange::TemporaryRescheduled {
            target: "AS64496".to_owned(),
            expires_at: 4720
        }]
    );
}

#[test]
fn partial_asn_unban_keeps_shared_cache_until_retry_completes_both_stores() {
    let fixture = Harness::new();
    fixture.permanent_asns.borrow_mut().extend([64496, 64497]);
    fixture
        .state
        .borrow_mut()
        .asns
        .extend([(64496, 5000), (64497, 6000)]);
    fixture.caches.borrow_mut().extend([64496, 64497]);
    fixture.fail_config_write.set(true);
    let unban = unban_request(&["AS64496", "64497"]);
    let error =
        execute_unban_asn(&unban, &fixture.unban_dependencies()).expect_err("partial failure");
    let AppError::PartialBanUpdate {
        completed, pending, ..
    } = error
    else {
        panic!("missing partial-update diagnostic: {error}");
    };
    assert_eq!(
        completed,
        PathBuf::from("/fixture/data/temporary-bans.toml")
    );
    assert_eq!(pending, PathBuf::from("/fixture/config/config.toml"));
    assert!(fixture.state.borrow().asns.is_empty());
    assert_eq!(
        *fixture.permanent_asns.borrow(),
        BTreeSet::from([64496, 64497])
    );
    assert_eq!(*fixture.caches.borrow(), BTreeSet::from([64496, 64497]));
    assert_eq!(
        *fixture.events.borrow(),
        [
            Event::Lock,
            Event::TemporarySave,
            Event::ConfigWrite,
            Event::Unlock
        ]
    );

    fixture.events.borrow_mut().clear();
    fixture.fail_config_write.set(false);
    let outcome = execute_unban_asn(&unban, &fixture.unban_dependencies()).expect("retry");
    assert_eq!(outcome.removed, [64496, 64497]);
    assert_eq!(outcome.deleted_cache_files, 2);
    assert!(fixture.state.borrow().asns.is_empty());
    assert!(fixture.permanent_asns.borrow().is_empty());
    assert!(fixture.caches.borrow().is_empty());
    assert_eq!(
        *fixture.events.borrow(),
        [
            Event::Lock,
            Event::ConfigWrite,
            Event::CacheDelete(64496),
            Event::CacheDelete(64497),
            Event::Unlock
        ]
    );
}

#[test]
fn temporary_save_failure_prevents_asn_config_and_cache_changes() {
    let fixture = Harness::new();
    fixture.permanent_asns.borrow_mut().insert(64496);
    fixture.state.borrow_mut().asns.insert(64496, 5000);
    fixture.caches.borrow_mut().insert(64496);
    fixture.fail_temporary_save.set(true);
    let original = fixture.state.borrow().clone();
    let result = execute_unban_asn(&unban_request(&["AS64496"]), &fixture.unban_dependencies());
    assert!(matches!(result, Err(AppError::TemporaryBans { .. })));
    assert_eq!(*fixture.state.borrow(), original);
    assert_eq!(*fixture.permanent_asns.borrow(), BTreeSet::from([64496]));
    assert_eq!(*fixture.caches.borrow(), BTreeSet::from([64496]));
    assert_eq!(
        *fixture.events.borrow(),
        [Event::Lock, Event::TemporarySave, Event::Unlock]
    );
}

#[test]
fn temporary_only_asn_unban_succeeds_without_rewriting_permanent_config() {
    let fixture = Harness::new();
    fixture.state.borrow_mut().asns.insert(64496, 5000);
    fixture.caches.borrow_mut().insert(64496);
    fixture.fail_config_write.set(true);
    let outcome = execute_unban_asn(&unban_request(&["AS64496"]), &fixture.unban_dependencies())
        .expect("temporary-only unban");
    assert_eq!(outcome.removed, [64496]);
    assert_eq!(outcome.deleted_cache_files, 1);
    assert!(fixture.state.borrow().asns.is_empty());
    assert!(fixture.caches.borrow().is_empty());
    assert_eq!(
        *fixture.events.borrow(),
        [
            Event::Lock,
            Event::TemporarySave,
            Event::CacheDelete(64496),
            Event::Unlock
        ]
    );
}
