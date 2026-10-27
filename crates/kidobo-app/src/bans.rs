//! Read-only inventory of permanent and temporary operator-managed bans.

use kidobo_core::network::CanonicalCidr;
use kidobo_core::temporary_bans::TemporaryBans;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
use crate::ports::{Cancellation, ConfigRepository, PathResolver};
use crate::temporary_bans::Clock;

/// Default maximum number of saved records shown by the CLI.
pub const DEFAULT_BAN_LIST_LIMIT: usize = 50;

/// Which saved lifetimes are included in an inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanLifetimeFilter {
    /// Include permanent records and every saved temporary record.
    All,
    /// Include active and expired temporary records only.
    Temporary,
    /// Include permanent local and configured ASN records only.
    Permanent,
}

/// Identity class of an operator-managed saved ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanKind {
    /// One canonical IPv4 or IPv6 network, including individual addresses.
    Ip,
    /// One autonomous system number.
    Asn,
}

/// One saved source record; it does not establish live firewall enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedBan {
    /// Canonical CIDR or AS-prefixed ASN identity.
    pub target: String,
    /// Whether the identity is an IP/CIDR or ASN.
    pub kind: BanKind,
    /// Absolute Unix expiry, or `None` for a permanent record.
    pub expires_at: Option<u64>,
    /// Whether the saved source is eligible at the inventory cutoff, independent of live state.
    pub active: bool,
}

/// Boundedly parsed operator-managed IP and temporary source state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SavedBanSources {
    /// Permanent local identities; duplicate canonical entries are permitted on input.
    pub local: Vec<CanonicalCidr>,
    /// All saved temporary records, including expired identities awaiting pruning.
    pub temporary: TemporaryBans,
}

/// Read-only capability that cannot fetch feeds, resolve ASNs, or write source state.
pub trait SavedBanReader {
    /// Reads the local blocklist and temporary state using their existing validation rules.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable, oversized, or invalid saved source state. Missing source
    /// files represent empty state and are not created.
    fn read(&self, paths: &ResolvedPaths) -> Result<SavedBanSources, AppError>;
}

/// Selection and output bound for a saved-ban inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanListRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Whether permanent, temporary, or both lifetimes are selected.
    pub lifetime: BanLifetimeFilter,
    /// Restricts the result to configured and temporary ASN identities.
    pub asn_only: bool,
    /// Maximum displayed records; `None` requests all records within storage limits.
    pub limit: Option<usize>,
}

/// Deterministic source inventory with one consistent expiry cutoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanListOutcome {
    /// Selected records in kind, lifetime, and canonical identity order.
    pub records: Vec<SavedBan>,
    /// Unix timestamp used for every active/expired decision.
    pub cutoff: u64,
    /// Total selected records before applying the display limit.
    pub total: usize,
    /// Selected records excluded by the display limit.
    pub omitted: usize,
}

/// Read-only capabilities needed by the saved-ban inventory.
pub struct BanListDependencies<'a> {
    /// Cooperative cancellation checked between bounded reads and record groups.
    pub cancellation: &'a dyn Cancellation,
    /// Resolves runtime paths without creating files.
    pub paths: &'a dyn PathResolver,
    /// Loads validated configuration, including permanent ASN identities.
    pub configs: &'a dyn ConfigRepository,
    /// Supplies a single inventory-wide expiry cutoff.
    pub clock: &'a dyn Clock,
    /// Reads only local permanent and temporary source state.
    pub reader: &'a dyn SavedBanReader,
}

/// Lists only operator-managed saved bans without consulting imported feeds or live enforcement.
///
/// Exact duplicates within a lifetime are removed. A target saved both permanently and temporarily
/// remains two records because the underlying sources and expiry consequences are distinct.
///
/// # Errors
///
/// Returns an error when required configuration, saved source state, or time is unavailable or
/// invalid, or when cancellation is requested.
pub fn execute(
    request: &BanListRequest,
    dependencies: &BanListDependencies<'_>,
) -> Result<BanListOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    dependencies.cancellation.check()?;
    let mut config = dependencies.configs.load(&paths.config_file)?;
    dependencies.cancellation.check()?;
    let cutoff = dependencies.clock.now_unix_secs()?;
    let mut sources = dependencies.reader.read(&paths)?;
    dependencies.cancellation.check()?;
    let mut records = Vec::new();

    if !request.asn_only {
        if request.lifetime != BanLifetimeFilter::Temporary {
            sources.local.sort_unstable();
            sources.local.dedup();
            for target in sources.local {
                records.push(record(target.to_string(), BanKind::Ip, None, cutoff));
            }
        }
        if request.lifetime != BanLifetimeFilter::Permanent {
            for (target, expiry) in &sources.temporary.ips {
                records.push(record(
                    target.to_string(),
                    BanKind::Ip,
                    Some(*expiry),
                    cutoff,
                ));
            }
        }
    }
    dependencies.cancellation.check()?;
    if request.lifetime != BanLifetimeFilter::Temporary {
        config.asn.banned.sort_unstable();
        config.asn.banned.dedup();
        for asn in config.asn.banned {
            records.push(record(format!("AS{asn}"), BanKind::Asn, None, cutoff));
        }
    }
    if request.lifetime != BanLifetimeFilter::Permanent {
        for (asn, expiry) in sources.temporary.asns {
            records.push(record(
                format!("AS{asn}"),
                BanKind::Asn,
                Some(expiry),
                cutoff,
            ));
        }
    }
    dependencies.cancellation.check()?;
    let total = records.len();
    if let Some(limit) = request.limit {
        records.truncate(limit);
    }
    Ok(BanListOutcome {
        omitted: total - records.len(),
        records,
        cutoff,
        total,
    })
}

fn record(target: String, kind: BanKind, expires_at: Option<u64>, cutoff: u64) -> SavedBan {
    SavedBan {
        target,
        kind,
        active: expires_at.is_none_or(|expiry| expiry > cutoff),
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;

    use kidobo_core::config::Config;
    use kidobo_core::network::parse_ip_cidr_strict;

    use super::*;
    use crate::ports::NoCancellation;

    struct Paths;

    impl PathResolver for Paths {
        fn resolve(
            &self,
            _: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Required);
            Ok(ResolvedPaths {
                root_override: Some(PathBuf::from("/fixture")),
                config_dir: PathBuf::from("/fixture/config"),
                config_file: PathBuf::from("/fixture/config/config.toml"),
                data_dir: PathBuf::from("/fixture/data"),
                blocklist_file: PathBuf::from("/fixture/data/blocklist.txt"),
                cache_dir: PathBuf::from("/fixture/cache"),
                remote_cache_dir: PathBuf::from("/fixture/cache/remote"),
                lock_file: PathBuf::from("/fixture/cache/sync.lock"),
            })
        }
    }

    struct Configs(&'static str);

    impl ConfigRepository for Configs {
        fn load(&self, path: &Path) -> Result<Config, AppError> {
            assert_eq!(path, Path::new("/fixture/config/config.toml"));
            Config::from_toml_str(self.0).map_err(AppError::from)
        }
    }

    struct FixedClock(Cell<usize>);

    impl Clock for FixedClock {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            self.0.set(self.0.get() + 1);
            Ok(100)
        }
    }

    struct Reader;

    impl SavedBanReader for Reader {
        fn read(&self, paths: &ResolvedPaths) -> Result<SavedBanSources, AppError> {
            assert_eq!(
                paths.blocklist_file,
                Path::new("/fixture/data/blocklist.txt")
            );
            let ip = |text| parse_ip_cidr_strict(text).expect("fixture network");
            Ok(SavedBanSources {
                local: vec![ip("203.0.113.7"), ip("203.0.113.7/32"), ip("2001:db8::1")],
                temporary: TemporaryBans {
                    ips: [(ip("198.51.100.9"), 101), (ip("203.0.113.7"), 100)].into(),
                    asns: [(64496, 99), (64497, 200)].into(),
                },
            })
        }
    }

    struct UnreachableReader;

    impl SavedBanReader for UnreachableReader {
        fn read(&self, _: &ResolvedPaths) -> Result<SavedBanSources, AppError> {
            panic!("source reader must not be reached");
        }
    }

    const CONFIG: &str = "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64498,64496,64496]\n";

    fn request() -> BanListRequest {
        BanListRequest {
            paths: PathResolutionInput {
                explicit_config_path: None,
                temp_dir: PathBuf::from("/tmp"),
                env: BTreeMap::new(),
            },
            lifetime: BanLifetimeFilter::All,
            asn_only: false,
            limit: None,
        }
    }

    fn run(request: &BanListRequest, clock: &FixedClock) -> BanListOutcome {
        execute(
            request,
            &BanListDependencies {
                cancellation: &NoCancellation,
                paths: &Paths,
                configs: &Configs(CONFIG),
                clock,
                reader: &Reader,
            },
        )
        .expect("saved inventory")
    }

    #[test]
    fn inventory_deduplicates_saved_identities_and_retains_expired_and_dual_lifetimes() {
        let clock = FixedClock(Cell::new(0));
        let outcome = run(&request(), &clock);
        assert_eq!(outcome.cutoff, 100);
        assert_eq!(clock.0.get(), 1);
        assert_eq!(outcome.total, 8);
        assert_eq!(outcome.omitted, 0);
        assert_eq!(
            outcome.records,
            vec![
                record("203.0.113.7/32".to_string(), BanKind::Ip, None, 100),
                record("2001:db8::1/128".to_string(), BanKind::Ip, None, 100),
                record("198.51.100.9/32".to_string(), BanKind::Ip, Some(101), 100),
                record("203.0.113.7/32".to_string(), BanKind::Ip, Some(100), 100),
                record("AS64496".to_string(), BanKind::Asn, None, 100),
                record("AS64498".to_string(), BanKind::Asn, None, 100),
                record("AS64496".to_string(), BanKind::Asn, Some(99), 100),
                record("AS64497".to_string(), BanKind::Asn, Some(200), 100),
            ]
        );
        let expired = outcome
            .records
            .iter()
            .filter(|ban| !ban.active)
            .collect::<Vec<_>>();
        assert_eq!(
            expired
                .iter()
                .map(|ban| ban.target.as_str())
                .collect::<Vec<_>>(),
            vec!["203.0.113.7/32", "AS64496"]
        );
    }

    #[test]
    fn lifetime_and_asn_filters_compose_without_importing_feed_entries() {
        for (lifetime, asn_only, expected) in [
            (BanLifetimeFilter::All, false, 8),
            (BanLifetimeFilter::Permanent, false, 4),
            (BanLifetimeFilter::Temporary, false, 4),
            (BanLifetimeFilter::All, true, 4),
            (BanLifetimeFilter::Permanent, true, 2),
            (BanLifetimeFilter::Temporary, true, 2),
        ] {
            let mut request = request();
            request.lifetime = lifetime;
            request.asn_only = asn_only;
            let outcome = run(&request, &FixedClock(Cell::new(0)));
            assert_eq!(outcome.total, expected, "{lifetime:?}, ASN only={asn_only}");
            if asn_only {
                assert!(outcome.records.iter().all(|ban| ban.kind == BanKind::Asn));
            }
            if lifetime == BanLifetimeFilter::Permanent {
                assert!(outcome.records.iter().all(|ban| ban.expires_at.is_none()));
            } else if lifetime == BanLifetimeFilter::Temporary {
                assert!(outcome.records.iter().all(|ban| ban.expires_at.is_some()));
            }
        }
    }

    #[test]
    fn display_limit_reports_total_and_omitted_after_filtering() {
        let mut request = request();
        request.limit = Some(3);
        let limited = run(&request, &FixedClock(Cell::new(0)));
        assert_eq!(limited.records.len(), 3);
        assert_eq!(limited.total, 8);
        assert_eq!(limited.omitted, 5);
        request.asn_only = true;
        request.lifetime = BanLifetimeFilter::Temporary;
        request.limit = Some(1);
        let filtered = run(&request, &FixedClock(Cell::new(0)));
        assert_eq!(filtered.total, 2);
        assert_eq!(filtered.omitted, 1);
        assert_eq!(filtered.records[0].target, "AS64496");
        assert!(!filtered.records[0].active);
    }

    #[test]
    fn invalid_configuration_and_cancellation_stop_before_source_reads() {
        let clock = FixedClock(Cell::new(0));
        let cancelled = AtomicBool::new(true);
        let config = Configs("not TOML");
        let mut dependencies = BanListDependencies {
            cancellation: &cancelled,
            paths: &Paths,
            configs: &config,
            clock: &clock,
            reader: &UnreachableReader,
        };
        assert!(matches!(
            execute(&request(), &dependencies),
            Err(AppError::Interrupted)
        ));
        assert_eq!(clock.0.get(), 0);
        dependencies.cancellation = &NoCancellation;
        assert!(matches!(
            execute(&request(), &dependencies),
            Err(AppError::ConfigParse { .. })
        ));
        assert_eq!(clock.0.get(), 0);
    }
}
