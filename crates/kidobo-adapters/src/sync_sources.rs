//! Built-in online source providers used by the sync application use case.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::source::{
    FailurePolicy, Notice, PendingCachePromotion, SourceRole, SyncSourceBatch, SyncSourceContext,
    SyncSourceDescriptor, SyncSourceLoad, SyncSourceProvider, SyncSourceRegistry,
};

use crate::asn::{AsnPrefixResolver, Bgpq4AsnPrefixResolver, load_asn_prefixes_with_cache};
use crate::blocklist_file::{
    BlocklistNormalizeResult, load_blocklist_document, normalize_local_blocklist_with_fast_state,
};
use crate::cache_generation::StagedGeneration;
use crate::github_meta::prepare_github_meta_safelist;
use crate::http_cache::prepare_iplist_with_cache;
use crate::http_client::{HttpClient, ReqwestHttpClient};

struct CancellableHttpClient<'a, C: ?Sized> {
    inner: &'a C,
    cancellation: &'a dyn kidobo_app::ports::Cancellation,
}

impl<C: HttpClient + ?Sized> HttpClient for CancellableHttpClient<'_, C> {
    fn fetch(
        &self,
        request: crate::http_client::HttpRequest,
    ) -> Result<crate::http_client::HttpResponse, crate::http_client::HttpClientError> {
        self.cancellation.check().map_err(|error| {
            crate::http_client::HttpClientError::Request {
                reason: error.to_string(),
            }
        })?;
        self.inner.fetch(request)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{url}: {source}")]
struct RemoteFeedError {
    url: String,
    #[source]
    source: crate::http_cache::HttpCacheError,
}

/// Maximum number of concurrent remote-feed workers.
pub const MAX_REMOTE_FETCH_WORKERS: usize = 5;
const BLOCKLIST_FAST_STATE_FILE: &str = "blocklist-normalize.fast-state";

struct StagedCachePromotion(StagedGeneration);

impl PendingCachePromotion for StagedCachePromotion {
    fn promote(self: Box<Self>) -> std::io::Result<()> {
        let Self(generation) = *self;
        generation.promote().map(|_| ())
    }
}

/// Required synchronization provider for the normalized local blocklist.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalBlocklistSyncProvider;

impl SyncSourceProvider for LocalBlocklistSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "local-blocklist",
            role: SourceRole::Candidate,
            failure_policy: FailurePolicy::Required,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        context.cancellation.check()?;
        let fast_state_path = context.paths.cache_dir.join(BLOCKLIST_FAST_STATE_FILE);
        let normalization = normalize_local_blocklist_with_fast_state(
            &context.paths.blocklist_file,
            &fast_state_path,
        )?;
        let notices = (normalization == BlocklistNormalizeResult::SkippedUnchanged)
            .then(|| {
                Notice::info(format!(
                    "sync blocklist normalization skipped: unchanged path={}",
                    context.paths.blocklist_file.display()
                ))
            })
            .into_iter()
            .collect();
        let document = load_blocklist_document(&context.paths.blocklist_file)?;
        let networks = document
            .lines
            .iter()
            .filter_map(|line| line.canonical)
            .collect();
        Ok(SyncSourceLoad::ready(SyncSourceBatch { networks, notices }))
    }
}

/// Required synchronization provider for active operator-managed temporary IP bans.
#[derive(Debug, Default, Clone, Copy)]
pub struct TemporaryBlocklistSyncProvider;

impl SyncSourceProvider for TemporaryBlocklistSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "temporary-blocklist",
            role: SourceRole::Candidate,
            failure_policy: FailurePolicy::Required,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        Ok(SyncSourceLoad::ready(SyncSourceBatch {
            networks: context.temporary_bans.active_ips(context.cutoff),
            notices: Vec::new(),
        }))
    }
}

/// Best-effort synchronization provider for configured remote feeds.
#[derive(Debug, Clone)]
pub struct RemoteFeedsSyncProvider {
    user_agent: String,
}

impl RemoteFeedsSyncProvider {
    #[must_use]
    /// Creates a remote provider with the supplied HTTP user agent.
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
        }
    }
}

impl SyncSourceProvider for RemoteFeedsSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "remote-feeds",
            role: SourceRole::Candidate,
            failure_policy: FailurePolicy::BestEffort,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        let timeout = Duration::from_secs(u64::from(context.config.remote.timeout_secs.get()));
        let client = ReqwestHttpClient::with_user_agent_and_timeout(&self.user_agent, timeout);
        prepare_remote_networks_in_chunks(
            &context.config.remote.urls,
            &client,
            &context.paths.remote_cache_dir,
            context.env,
            context.config.ipset.maxelem.get(),
            context.cancellation,
        )
    }
}

/// Required synchronization provider for explicit configuration safelist entries.
#[derive(Debug, Default, Clone, Copy)]
pub struct ConfigSafelistSyncProvider;

impl SyncSourceProvider for ConfigSafelistSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "config-safelist",
            role: SourceRole::Safelist,
            failure_policy: FailurePolicy::Required,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        Ok(SyncSourceLoad::ready(SyncSourceBatch {
            networks: context.config.safe.ips.clone(),
            notices: Vec::new(),
        }))
    }
}

/// Best-effort synchronization provider for GitHub metadata safelist networks.
#[derive(Debug, Clone)]
pub struct GithubMetadataSyncProvider {
    user_agent: String,
}

impl GithubMetadataSyncProvider {
    #[must_use]
    /// Creates a GitHub metadata provider with the supplied HTTP user agent.
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
        }
    }
}

impl SyncSourceProvider for GithubMetadataSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "github-metadata",
            role: SourceRole::ExternalSafelist,
            failure_policy: FailurePolicy::BestEffort,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        if !context.config.safe.include_github_meta {
            return Ok(SyncSourceLoad::default());
        }
        let timeout = Duration::from_secs(u64::from(context.config.remote.timeout_secs.get()));
        let client = ReqwestHttpClient::with_user_agent_and_timeout(&self.user_agent, timeout);
        let loaded = prepare_github_meta_safelist(
            &CancellableHttpClient {
                inner: &client,
                cancellation: context.cancellation,
            },
            &context.paths.remote_cache_dir,
            &context.config.safe.github_meta_url,
            &context.config.safe.github_meta_category_mode(),
            context.env,
        )
        .map_err(|error| AppError::CacheStaging {
            provider: "github-metadata",
            source: Box::new(error),
        })?;
        let fallback = loaded.fallback.map(|fallback| SyncSourceBatch {
            networks: fallback.networks,
            notices: Vec::new(),
        });
        let pending_promotions = loaded
            .pending_promotion
            .map(|promotion| -> Box<dyn PendingCachePromotion> {
                Box::new(StagedCachePromotion(promotion))
            })
            .into_iter()
            .collect();
        Ok(SyncSourceLoad {
            fallback_failure: loaded.staging_failure.map(|error| AppError::CacheStaging {
                provider: "github-metadata",
                source: Box::new(error),
            }),
            primary: SyncSourceBatch {
                networks: loaded.primary.networks,
                notices: Vec::new(),
            },
            fallback,
            pending_promotions,
        })
    }
}

/// Required synchronization provider for configured ASN prefix caches and refreshes.
#[derive(Debug, Default, Clone, Copy)]
pub struct AsnBansSyncProvider;

impl SyncSourceProvider for AsnBansSyncProvider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        SyncSourceDescriptor {
            id: "asn-bans",
            role: SourceRole::Candidate,
            failure_policy: FailurePolicy::Required,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
        let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();
        load_asn_bans(context, &resolver)
    }
}

fn load_asn_bans(
    context: &SyncSourceContext<'_>,
    resolver: &dyn AsnPrefixResolver,
) -> Result<SyncSourceLoad, AppError> {
    let stale_after =
        Duration::from_secs(u64::from(context.config.asn.cache_stale_after_secs.get()));
    let cache_dir = context.paths.cache_dir.join("asn");
    let asns = context
        .config
        .asn
        .banned
        .iter()
        .copied()
        .chain(context.temporary_bans.active_asns(context.cutoff))
        .collect::<BTreeSet<_>>();
    let mut networks = Vec::new();
    let mut notices = Vec::new();
    for asn in asns {
        context.cancellation.check()?;
        let loaded = load_asn_prefixes_with_cache(asn, &cache_dir, stale_after, resolver).map_err(
            |error| AppError::Asn {
                source: Box::new(error),
            },
        )?;
        if loaded.stale {
            notices.push(Notice::warning(format!(
                "ASN cache refresh failed; using stale prefixes for AS{asn}"
            )));
        }
        networks.extend(loaded.prefixes);
    }
    networks.sort_unstable();
    networks.dedup();
    Ok(SyncSourceLoad::ready(SyncSourceBatch { networks, notices }))
}

/// Builds the complete registry of synchronization source providers.
///
/// # Errors
///
/// Returns [`AppError::DuplicateSourceProvider`] if the built-in provider IDs are not unique.
pub fn build_sync_source_registry(product_version: &str) -> Result<SyncSourceRegistry, AppError> {
    let user_agent = format!("kidobo/{product_version}");
    let mut registry = SyncSourceRegistry::new();
    registry.register(LocalBlocklistSyncProvider)?;
    registry.register(TemporaryBlocklistSyncProvider)?;
    registry.register(RemoteFeedsSyncProvider::new(&user_agent))?;
    registry.register(ConfigSafelistSyncProvider)?;
    registry.register(GithubMetadataSyncProvider::new(user_agent))?;
    registry.register(AsnBansSyncProvider)?;
    Ok(registry)
}

fn prepare_remote_networks_in_chunks<S, C>(
    urls: &[S],
    http_client: &C,
    cache_dir: &Path,
    env: &std::collections::BTreeMap<OsString, OsString>,
    maxelem: u32,
    cancellation: &dyn kidobo_app::ports::Cancellation,
) -> Result<SyncSourceLoad, AppError>
where
    S: AsRef<str> + Sync,
    C: HttpClient + Sync,
{
    let http_client = CancellableHttpClient {
        inner: http_client,
        cancellation,
    };
    let aggregate_limit = remote_aggregate_limit(maxelem);
    let mut seen_urls = BTreeSet::new();
    let unique_urls = urls
        .iter()
        .map(AsRef::as_ref)
        .filter(|url| seen_urls.insert(*url))
        .collect::<Vec<_>>();
    let mut aggregate = BTreeSet::new();
    let mut notices = Vec::new();
    let mut pending_promotions: Vec<Box<dyn PendingCachePromotion>> = Vec::new();

    for chunk in unique_urls.chunks(MAX_REMOTE_FETCH_WORKERS) {
        cancellation.check()?;
        let worker_count = remote_fetch_worker_count(chunk.len());
        let next_idx = AtomicUsize::new(0);
        let results = Mutex::new(Vec::with_capacity(chunk.len()));
        thread::scope(|scope| {
            for _ in 0..worker_count {
                scope.spawn(|| {
                    loop {
                        if cancellation.is_cancelled() {
                            break;
                        }
                        let index = next_idx.fetch_add(1, Ordering::Relaxed);
                        let Some(url) = chunk.get(index) else {
                            break;
                        };
                        let url = *url;
                        let result =
                            prepare_iplist_with_cache(&http_client, url, cache_dir, env, maxelem)
                                .map_err(|error| match error {
                                    error @ crate::http_cache::HttpCacheError::ReadIplist {
                                        ..
                                    } => AppError::Source {
                                        provider: "remote-feeds",
                                        source: Box::new(RemoteFeedError {
                                            url: url.to_string(),
                                            source: error,
                                        }),
                                    },
                                    error => AppError::CacheStaging {
                                        provider: "remote-feeds",
                                        source: Box::new(RemoteFeedError {
                                            url: url.to_string(),
                                            source: error,
                                        }),
                                    },
                                });
                        results
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((index, result));
                    }
                });
            }
        });

        cancellation.check()?;

        let mut chunk_results = results
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        chunk_results.sort_unstable_by_key(|(index, _)| *index);
        for (_, result) in chunk_results {
            let prepared = match result {
                Ok(prepared) => prepared,
                Err(error @ AppError::Source { .. }) => {
                    notices.push(Notice::warning(format!(
                        "remote source fetch failed softly: {error}"
                    )));
                    continue;
                }
                Err(error) => return Err(error),
            };
            for network in prepared.loaded.networks {
                aggregate.insert(network);
                if aggregate.len() > aggregate_limit {
                    return Err(AppError::SourceAggregateBudgetExceeded {
                        entries: aggregate.len(),
                        limit: aggregate_limit,
                    });
                }
            }
            if let Some(promotion) = prepared.pending_promotion {
                pending_promotions.push(Box::new(StagedCachePromotion(promotion)));
            }
        }
    }

    Ok(SyncSourceLoad {
        primary: SyncSourceBatch {
            networks: aggregate.into_iter().collect(),
            notices,
        },
        fallback: None,
        pending_promotions,
        fallback_failure: None,
    })
}

fn remote_aggregate_limit(maxelem: u32) -> usize {
    let maxelem = usize::try_from(maxelem).unwrap_or(usize::MAX);
    8_192.max(maxelem.saturating_mul(4).min(2_000_000))
}

fn remote_fetch_worker_count(url_count: usize) -> usize {
    let cpu_parallelism =
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    remote_fetch_worker_count_for(url_count, cpu_parallelism)
}

#[must_use]
fn remote_fetch_worker_count_for(url_count: usize, cpu_parallelism: usize) -> usize {
    let cpu_budget = cpu_parallelism.max(1);
    let max_workers = MAX_REMOTE_FETCH_WORKERS.min(cpu_budget);
    url_count.min(max_workers.max(1))
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use kidobo_app::source::{FailurePolicy, SourceRole};
    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        MAX_REMOTE_FETCH_WORKERS, build_sync_source_registry, prepare_remote_networks_in_chunks,
        remote_fetch_worker_count_for,
    };
    use crate::http_client::{HttpClient, HttpClientError, HttpRequest, HttpResponse};

    struct DelayedClient {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        calls: AtomicUsize,
        workers: usize,
        first_wave: std::sync::Barrier,
    }

    struct AggregateBudgetClient;

    struct DuplicateUrlClient {
        calls: AtomicUsize,
    }

    struct FailingClient;

    impl HttpClient for AggregateBudgetClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            let feed = request.url.rsplit('/').next().unwrap_or_default();
            let body = match feed {
                "0" | "1" => {
                    let first = if feed == "0" { 10 } else { 11 };
                    let mut body = String::new();
                    for index in 0..4_096 {
                        writeln!(body, "{first}.0.{}.{}", index / 256, index % 256)
                            .expect("write aggregate fixture");
                    }
                    body.into_bytes()
                }
                _ => b"12.0.0.1\n".to_vec(),
            };
            Ok(HttpResponse {
                status: StatusCode::OK,
                body,
                etag: None,
                last_modified: None,
            })
        }
    }

    impl HttpClient for DelayedClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(current, Ordering::SeqCst);
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.workers {
                self.first_wave.wait();
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            let final_octet = request.url.rsplit('/').next().unwrap_or("1");
            Ok(HttpResponse {
                status: StatusCode::OK,
                body: format!("198.51.100.{final_octet}\n").into_bytes(),
                etag: None,
                last_modified: None,
            })
        }
    }

    impl HttpClient for DuplicateUrlClient {
        fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let body = if call == 0 {
                b"192.0.2.1\n".to_vec()
            } else {
                b"198.51.100.1\n".to_vec()
            };
            Ok(HttpResponse {
                status: StatusCode::OK,
                body,
                etag: None,
                last_modified: None,
            })
        }
    }

    impl HttpClient for FailingClient {
        fn fetch(&self, _request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            Err(HttpClientError::Request {
                reason: "offline".to_owned(),
            })
        }
    }

    fn source_paths(root: &std::path::Path) -> kidobo_app::paths::ResolvedPaths {
        kidobo_app::paths::ResolvedPaths {
            root_override: Some(root.to_path_buf()),
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/lock"),
        }
    }

    #[derive(Default)]
    struct RecordingAsnResolver {
        calls: std::sync::Mutex<Vec<u32>>,
        fail: bool,
    }

    impl crate::asn::AsnPrefixResolver for RecordingAsnResolver {
        fn resolve_prefixes(
            &self,
            asn: u32,
        ) -> Result<Vec<kidobo_core::network::CanonicalCidr>, crate::asn::AsnError> {
            self.calls.lock().expect("calls").push(asn);
            if self.fail {
                return Err(crate::asn::AsnError::ResolveFailed {
                    asn,
                    reason: "injected unavailable resolver".into(),
                });
            }
            Ok(vec![
                kidobo_core::network::parse_ip_cidr_token(&format!(
                    "198.51.100.{}/32",
                    asn - 64511
                ))
                .expect("cidr"),
            ])
        }
    }

    #[test]
    fn temporary_ip_provider_uses_shared_cutoff_and_keeps_active_families_separate() {
        use kidobo_app::source::{SyncSourceContext, SyncSourceProvider};
        use kidobo_core::network::parse_ip_cidr_token;
        let temp = TempDir::new().expect("temporary root");
        let paths = source_paths(temp.path());
        let config = kidobo_core::config::Config::from_toml_str("[ipset]\nset_name = 'kidobo'\n")
            .expect("config");
        let v4 = parse_ip_cidr_token("198.51.100.0/24").expect("v4");
        let v6 = parse_ip_cidr_token("2001:db8::/64").expect("v6");
        let temporary = kidobo_core::temporary_bans::TemporaryBans {
            ips: [(v4, 100), (v6, 101)].into(),
            asns: std::collections::BTreeMap::default(),
        };
        for (cutoff, expected) in [(99, vec![v4, v6]), (100, vec![v6]), (101, Vec::new())] {
            let loaded = super::TemporaryBlocklistSyncProvider
                .load(&SyncSourceContext {
                    cancellation: &kidobo_app::ports::NoCancellation,
                    paths: &paths,
                    config: &config,
                    env: &std::collections::BTreeMap::default(),
                    temporary_bans: &temporary,
                    cutoff,
                })
                .expect("temporary source");
            assert_eq!(loaded.primary.networks, expected);
        }
        assert_eq!(temporary.ips[&v4], 100);
        assert_eq!(temporary.ips[&v6], 101);
    }

    #[test]
    fn asn_source_resolves_union_once_and_ignores_expired_temporary_asns() {
        let temp = TempDir::new().expect("temporary root");
        let paths = source_paths(temp.path());
        let config = kidobo_core::config::Config::from_toml_str(
            "[ipset]\nset_name = 'kidobo'\n[asn]\nbanned = [64512, 64513]\n",
        )
        .expect("config");
        let temporary = kidobo_core::temporary_bans::TemporaryBans {
            ips: std::collections::BTreeMap::default(),
            asns: [(64512, 101), (64513, 100), (64514, 101), (64515, 100)].into(),
        };
        let resolver = RecordingAsnResolver::default();
        let loaded = super::load_asn_bans(
            &kidobo_app::source::SyncSourceContext {
                cancellation: &kidobo_app::ports::NoCancellation,
                paths: &paths,
                config: &config,
                env: &std::collections::BTreeMap::default(),
                temporary_bans: &temporary,
                cutoff: 100,
            },
            &resolver,
        )
        .expect("ASN source");
        assert_eq!(
            *resolver.calls.lock().expect("calls"),
            [64512, 64513, 64514]
        );
        assert_eq!(
            loaded
                .primary
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32"]
        );
        assert!(!paths.cache_dir.join("asn/as64515.iplist").exists());
    }

    #[test]
    fn temporary_asn_requires_prefixes_and_uses_existing_stale_fallback() {
        let temp = TempDir::new().expect("temporary root");
        let paths = source_paths(temp.path());
        let config = kidobo_core::config::Config::from_toml_str(
            "[ipset]\nset_name = 'kidobo'\n[asn]\ncache_stale_after_secs = 1\n",
        )
        .expect("config");
        let temporary = kidobo_core::temporary_bans::TemporaryBans {
            ips: std::collections::BTreeMap::default(),
            asns: [(64512, 101)].into(),
        };
        let context = kidobo_app::source::SyncSourceContext {
            cancellation: &kidobo_app::ports::NoCancellation,
            paths: &paths,
            config: &config,
            env: &std::collections::BTreeMap::default(),
            temporary_bans: &temporary,
            cutoff: 100,
        };
        let resolver = RecordingAsnResolver {
            fail: true,
            ..RecordingAsnResolver::default()
        };
        assert!(matches!(
            super::load_asn_bans(&context, &resolver),
            Err(kidobo_app::AppError::Asn { .. })
        ));
        std::fs::create_dir_all(paths.cache_dir.join("asn")).expect("cache dir");
        let cache_path = paths.cache_dir.join("asn/as64512.iplist");
        std::fs::write(&cache_path, "192.0.2.0/24\n2001:db8::/64\n").expect("stale cache");
        std::fs::File::options()
            .write(true)
            .open(&cache_path)
            .expect("cache file")
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .expect("old timestamp");
        let loaded = super::load_asn_bans(&context, &resolver).expect("stale fallback");
        assert_eq!(
            loaded
                .primary
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/24", "2001:db8::/64"]
        );
        assert_eq!(
            loaded.primary.notices,
            [kidobo_app::source::Notice::warning(
                "ASN cache refresh failed; using stale prefixes for AS64512"
            )]
        );
        assert_eq!(*resolver.calls.lock().expect("calls"), [64512, 64512]);
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&cache_path, 1024)
                .expect("preserved cache"),
            "192.0.2.0/24\n2001:db8::/64\n"
        );

        let mut config_with_overlap = config.clone();
        config_with_overlap.asn.banned = vec![64512];
        let overlap = kidobo_app::source::SyncSourceContext {
            config: &config_with_overlap,
            ..context
        };
        super::load_asn_bans(&overlap, &resolver).expect("overlapping stale fallback");
        assert_eq!(
            *resolver.calls.lock().expect("calls"),
            [64512, 64512, 64512]
        );
    }

    #[test]
    fn built_in_registry_has_stable_order_roles_and_policies() {
        let descriptors = build_sync_source_registry("1.2.3")
            .expect("registry")
            .descriptors();
        assert_eq!(
            descriptors
                .iter()
                .map(|descriptor| (descriptor.id, descriptor.role, descriptor.failure_policy))
                .collect::<Vec<_>>(),
            [
                (
                    "local-blocklist",
                    SourceRole::Candidate,
                    FailurePolicy::Required
                ),
                (
                    "temporary-blocklist",
                    SourceRole::Candidate,
                    FailurePolicy::Required
                ),
                (
                    "remote-feeds",
                    SourceRole::Candidate,
                    FailurePolicy::BestEffort
                ),
                (
                    "config-safelist",
                    SourceRole::Safelist,
                    FailurePolicy::Required
                ),
                (
                    "github-metadata",
                    SourceRole::ExternalSafelist,
                    FailurePolicy::BestEffort
                ),
                ("asn-bans", SourceRole::Candidate, FailurePolicy::Required),
            ]
        );
    }

    #[test]
    fn remote_worker_count_is_bounded_by_urls_cpus_and_cap() {
        assert_eq!(remote_fetch_worker_count_for(0, 8), 0);
        assert_eq!(remote_fetch_worker_count_for(2, 8), 2);
        assert_eq!(remote_fetch_worker_count_for(20, 2), 2);
        assert_eq!(
            remote_fetch_worker_count_for(20, 64),
            MAX_REMOTE_FETCH_WORKERS
        );
        assert_eq!(remote_fetch_worker_count_for(2, 0), 1);
    }

    #[test]
    fn remote_loading_is_bounded_concurrent_and_deterministic() {
        let temp = TempDir::new().expect("tempdir");
        let urls = (1..=8)
            .map(|index| format!("https://example.test/{index}"))
            .collect::<Vec<_>>();
        let workers = super::remote_fetch_worker_count(MAX_REMOTE_FETCH_WORKERS);
        let client = DelayedClient {
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            workers,
            first_wave: std::sync::Barrier::new(workers),
        };

        let loaded = prepare_remote_networks_in_chunks(
            &urls,
            &client,
            temp.path(),
            &std::collections::BTreeMap::new(),
            65_536,
            &kidobo_app::ports::NoCancellation,
        )
        .expect("production preparation");

        assert_eq!(
            loaded
                .primary
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            (1..=8)
                .map(|index| format!("198.51.100.{index}/32"))
                .collect::<Vec<_>>()
        );
        assert_eq!(loaded.primary.notices.len(), 0);
        assert_eq!(loaded.pending_promotions.len(), 8);
        assert_eq!(client.max_in_flight.load(Ordering::SeqCst), workers);
    }

    #[test]
    fn aggregate_budget_rejection_drops_every_staged_generation() {
        let temp = TempDir::new().expect("tempdir");
        let urls = [
            "https://example.test/0",
            "https://example.test/1",
            "https://example.test/2",
        ];

        let Err(error) = prepare_remote_networks_in_chunks(
            &urls,
            &AggregateBudgetClient,
            temp.path(),
            &std::collections::BTreeMap::new(),
            1,
            &kidobo_app::ports::NoCancellation,
        ) else {
            panic!("8,193 distinct entries must exceed the aggregate floor");
        };

        assert!(matches!(
            error,
            kidobo_app::AppError::SourceAggregateBudgetExceeded {
                entries: 8_193,
                limit: 8_192
            }
        ));
        for url in urls {
            assert!(
                !crate::http_cache::remote_generation_store(temp.path(), url)
                    .join("current.json")
                    .exists()
            );
        }
    }

    #[test]
    fn cancellation_joins_active_fetches_and_never_starts_another_wave() {
        struct CancellingClient {
            cancellation: std::sync::atomic::AtomicBool,
            entered: std::sync::Barrier,
            calls: AtomicUsize,
            finished: AtomicUsize,
        }
        impl HttpClient for CancellingClient {
            fn fetch(&self, _: HttpRequest) -> Result<HttpResponse, HttpClientError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.wait();
                self.cancellation.store(true, Ordering::SeqCst);
                self.finished.fetch_add(1, Ordering::SeqCst);
                Ok(HttpResponse {
                    status: StatusCode::OK,
                    body: b"203.0.113.0/24".to_vec(),
                    etag: None,
                    last_modified: None,
                })
            }
        }
        let temp = TempDir::new().expect("tempdir");
        let workers = super::remote_fetch_worker_count(MAX_REMOTE_FETCH_WORKERS);
        let client = CancellingClient {
            cancellation: std::sync::atomic::AtomicBool::new(false),
            entered: std::sync::Barrier::new(workers),
            calls: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
        };
        let urls = (0..12)
            .map(|index| format!("https://example.test/{index}"))
            .collect::<Vec<_>>();
        let result = prepare_remote_networks_in_chunks(
            &urls,
            &client,
            temp.path(),
            &std::collections::BTreeMap::new(),
            100,
            &client.cancellation,
        );
        assert!(matches!(result, Err(kidobo_app::AppError::Interrupted)));
        assert_eq!(client.calls.load(Ordering::SeqCst), workers);
        assert_eq!(client.finished.load(Ordering::SeqCst), workers);
        for url in urls {
            let store = temp
                .path()
                .join("v2/remote")
                .join(crate::http_cache::url_hash_prefix(&url));
            assert!(!store.join("current.json").exists());
            if store.join("generations").exists() {
                assert_eq!(
                    std::fs::read_dir(store.join("generations"))
                        .expect("generations")
                        .count(),
                    0
                );
            }
        }
    }

    #[test]
    fn remote_staging_failure_without_cache_propagates_as_hard_error() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::write(temp.path().join("v2"), b"block staging").expect("block");
        let result = prepare_remote_networks_in_chunks(
            &["https://example.test/feed"],
            &DuplicateUrlClient {
                calls: AtomicUsize::new(0),
            },
            temp.path(),
            &std::collections::BTreeMap::new(),
            100,
            &kidobo_app::ports::NoCancellation,
        );
        let error = result.err().expect("staging failure must abort");
        assert!(matches!(
            &error,
            kidobo_app::AppError::CacheStaging {
                provider: "remote-feeds",
                ..
            }
        ));
        let mut cause: &(dyn std::error::Error + 'static) = &error;
        let source = loop {
            if let Some(source) = cause.downcast_ref::<std::io::Error>() {
                break source;
            }
            cause = cause
                .source()
                .expect("cache staging must retain its I/O cause");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::NotADirectory);
        assert!(source.raw_os_error().is_some());
        assert!(error.to_string().contains("https://example.test/feed:"));
    }

    #[test]
    fn duplicate_urls_share_one_staged_generation_and_leave_a_usable_cache() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.test/duplicate";
        let client = DuplicateUrlClient {
            calls: AtomicUsize::new(0),
        };

        let loaded = prepare_remote_networks_in_chunks(
            &[url, url],
            &client,
            temp.path(),
            &std::collections::BTreeMap::new(),
            65_536,
            &kidobo_app::ports::NoCancellation,
        )
        .expect("duplicate URLs should load once");

        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        assert_eq!(loaded.pending_promotions.len(), 1);
        for promotion in loaded.pending_promotions {
            promotion.promote().expect("promote staged cache");
        }

        let cached = prepare_remote_networks_in_chunks(
            &[url],
            &FailingClient,
            temp.path(),
            &std::collections::BTreeMap::new(),
            65_536,
            &kidobo_app::ports::NoCancellation,
        )
        .expect("cached production load");
        assert_eq!(cached.primary.networks, loaded.primary.networks);
        assert_eq!(cached.primary.notices.len(), 0);
    }
}
