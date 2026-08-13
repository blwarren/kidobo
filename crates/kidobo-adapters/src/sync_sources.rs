//! Built-in online source providers used by the sync application use case.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::source::{
    FailurePolicy, Notice, SourceRole, SyncSourceBatch, SyncSourceContext, SyncSourceDescriptor,
    SyncSourceProvider, SyncSourceRegistry,
};
use kidobo_core::network::CanonicalCidr;

use crate::asn::{Bgpq4AsnPrefixResolver, load_asn_prefixes_with_cache};
use crate::blocklist_file::{
    BlocklistDocument, BlocklistNormalizeResult, normalize_local_blocklist_with_fast_state,
};
use crate::github_meta::load_github_meta_safelist;
use crate::http_cache::{HttpClient, ReqwestHttpClient, fetch_iplist_with_cache};

pub const MAX_REMOTE_FETCH_WORKERS: usize = 5;
const BLOCKLIST_FAST_STATE_FILE: &str = "blocklist-normalize.fast-state";

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

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
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
        let document = BlocklistDocument::load(&context.paths.blocklist_file)?;
        let networks = document
            .lines
            .iter()
            .filter_map(|line| line.canonical)
            .collect();
        Ok(SyncSourceBatch { networks, notices })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteFeedsSyncProvider {
    user_agent: String,
}

impl RemoteFeedsSyncProvider {
    #[must_use]
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

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
        let timeout = Duration::from_secs(u64::from(context.config.remote.timeout_secs.get()));
        let client = ReqwestHttpClient::with_user_agent_and_timeout(&self.user_agent, timeout);
        let (networks, notices) = fetch_remote_networks_concurrently(
            &context.config.remote.urls,
            &client,
            &context.paths.remote_cache_dir,
            context.env,
        );
        Ok(SyncSourceBatch { networks, notices })
    }
}

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

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
        Ok(SyncSourceBatch {
            networks: context.config.safe.ips.clone(),
            notices: Vec::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GithubMetadataSyncProvider {
    user_agent: String,
}

impl GithubMetadataSyncProvider {
    #[must_use]
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
            role: SourceRole::Safelist,
            failure_policy: FailurePolicy::BestEffort,
        }
    }

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
        if !context.config.safe.include_github_meta {
            return Ok(SyncSourceBatch::default());
        }
        let timeout = Duration::from_secs(u64::from(context.config.remote.timeout_secs.get()));
        let client = ReqwestHttpClient::with_user_agent_and_timeout(&self.user_agent, timeout);
        let loaded = load_github_meta_safelist(
            &client,
            &context.paths.remote_cache_dir,
            &context.config.safe.github_meta_url,
            &context.config.safe.github_meta_category_mode(),
            context.env,
        )
        .map_err(|error| AppError::Source {
            provider: "github-metadata",
            reason: error.to_string(),
        })?;
        Ok(SyncSourceBatch {
            networks: loaded.networks,
            notices: Vec::new(),
        })
    }
}

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

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
        let stale_after =
            Duration::from_secs(u64::from(context.config.asn.cache_stale_after_secs.get()));
        let cache_dir = context.paths.cache_dir.join("asn");
        let resolver = Bgpq4AsnPrefixResolver::with_default_timeout();
        let mut networks = Vec::new();
        let mut notices = Vec::new();
        for asn in &context.config.asn.banned {
            let loaded = load_asn_prefixes_with_cache(*asn, &cache_dir, stale_after, &resolver)
                .map_err(|error| AppError::Asn {
                    reason: error.to_string(),
                })?;
            if loaded.stale {
                notices.push(Notice::warning(format!(
                    "ASN cache refresh failed; using stale prefixes for AS{asn}"
                )));
            }
            networks.extend(loaded.prefixes);
        }
        networks.sort_unstable();
        networks.dedup();
        Ok(SyncSourceBatch { networks, notices })
    }
}

pub fn build_sync_source_registry(product_version: &str) -> Result<SyncSourceRegistry, AppError> {
    let user_agent = format!("kidobo/{product_version}");
    let mut registry = SyncSourceRegistry::new();
    registry.register(LocalBlocklistSyncProvider)?;
    registry.register(RemoteFeedsSyncProvider::new(&user_agent))?;
    registry.register(ConfigSafelistSyncProvider)?;
    registry.register(GithubMetadataSyncProvider::new(user_agent))?;
    registry.register(AsnBansSyncProvider)?;
    Ok(registry)
}

pub fn fetch_remote_networks_concurrently<S, C>(
    urls: &[S],
    http_client: &C,
    cache_dir: &Path,
    env: &std::collections::BTreeMap<String, String>,
) -> (Vec<CanonicalCidr>, Vec<Notice>)
where
    S: AsRef<str> + Sync,
    C: HttpClient + Sync,
{
    if urls.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let worker_count = remote_fetch_worker_count(urls.len());
    let next_idx = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(urls.len()));

    thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| {
                loop {
                    let index = next_idx.fetch_add(1, Ordering::Relaxed);
                    let Some(url) = urls.get(index) else {
                        break;
                    };
                    let url = url.as_ref();
                    let result = fetch_iplist_with_cache(http_client, url, cache_dir, env)
                        .map(|cached| cached.networks)
                        .map_err(|error| {
                            Notice::warning(format!(
                                "remote source fetch failed softly for {url}: {error}"
                            ))
                        });
                    results
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((index, result));
                }
            });
        }
    });

    let mut results = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    results.sort_unstable_by_key(|(index, _)| *index);
    let mut networks = Vec::new();
    let mut notices = Vec::new();
    for (_, result) in results {
        match result {
            Ok(loaded) => networks.extend(loaded),
            Err(notice) => notices.push(notice),
        }
    }
    networks.sort_unstable();
    networks.dedup();
    (networks, notices)
}

fn remote_fetch_worker_count(url_count: usize) -> usize {
    let cpu_parallelism =
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    remote_fetch_worker_count_for(url_count, cpu_parallelism)
}

#[must_use]
pub fn remote_fetch_worker_count_for(url_count: usize, cpu_parallelism: usize) -> usize {
    let cpu_budget = cpu_parallelism.max(1);
    let max_workers = MAX_REMOTE_FETCH_WORKERS.min(cpu_budget);
    url_count.min(max_workers.max(1))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use kidobo_app::source::{FailurePolicy, SourceRole};
    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        MAX_REMOTE_FETCH_WORKERS, RemoteFeedsSyncProvider, build_sync_source_registry,
        fetch_remote_networks_concurrently, remote_fetch_worker_count_for,
    };
    use crate::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};

    struct DelayedClient {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl HttpClient for DelayedClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(current, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
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

    #[test]
    fn production_provider_uses_root_product_identity() {
        let provider = RemoteFeedsSyncProvider::new("kidobo/1.2.3");
        assert_eq!(provider.user_agent, "kidobo/1.2.3");
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
                    SourceRole::Safelist,
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
        let client = DelayedClient {
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        };

        let (networks, notices) = fetch_remote_networks_concurrently(
            &urls,
            &client,
            temp.path(),
            &std::collections::BTreeMap::new(),
        );

        assert_eq!(networks.len(), 8);
        assert!(notices.is_empty());
        assert!(client.max_in_flight.load(Ordering::SeqCst) <= MAX_REMOTE_FETCH_WORKERS);
    }
}
