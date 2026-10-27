//! Read-only counterparts of built-in sync sources, returning data without cache work handles.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use kidobo_app::AppError;
use kidobo_app::preview::{
    PreviewSourceContext, PreviewSourceLoad, PreviewSourceProvider, PreviewSourceRegistry,
};
use kidobo_app::source::{
    FailurePolicy, Notice, SourceObservation, SourceProvenance, SourceRole, SyncSourceBatch,
    SyncSourceDescriptor,
};
use kidobo_core::blocklist::BlocklistDocument;

use crate::asn::{AsnPrefixResolver, Bgpq4AsnPrefixResolver, read_asn_for_preview};
use crate::blocklist_file::{BLOCKLIST_READ_LIMIT, load_blocklist_document};
use crate::github_meta::read_github_meta_for_preview;
use crate::http_cache::{ReadOnlyIplist, ReadOnlyIplistError, read_iplist_for_preview};
use crate::http_client::{
    HttpClient, HttpClientError, HttpRequest, HttpResponse, ReqwestHttpClient,
};
use crate::sync_sources::{MAX_REMOTE_FETCH_WORKERS, remote_aggregate_limit};

#[derive(Clone, Copy)]
enum Kind {
    Local,
    Temporary,
    Remote,
    Safelist,
    Github,
    Asn,
}

struct Provider {
    kind: Kind,
    user_agent: String,
}

impl PreviewSourceProvider for Provider {
    fn descriptor(&self) -> SyncSourceDescriptor {
        let (id, role, failure_policy) = match self.kind {
            Kind::Local => (
                "local-blocklist",
                SourceRole::Candidate,
                FailurePolicy::Required,
            ),
            Kind::Temporary => (
                "temporary-blocklist",
                SourceRole::Candidate,
                FailurePolicy::Required,
            ),
            Kind::Remote => (
                "remote-feeds",
                SourceRole::Candidate,
                FailurePolicy::BestEffort,
            ),
            Kind::Safelist => (
                "config-safelist",
                SourceRole::Safelist,
                FailurePolicy::Required,
            ),
            Kind::Github => (
                "github-metadata",
                SourceRole::ExternalSafelist,
                FailurePolicy::BestEffort,
            ),
            Kind::Asn => ("asn-bans", SourceRole::Candidate, FailurePolicy::Required),
        };
        SyncSourceDescriptor {
            id,
            role,
            failure_policy,
        }
    }

    fn load(&self, context: &PreviewSourceContext<'_>) -> Result<PreviewSourceLoad, AppError> {
        context.sync.cancellation.check()?;
        match self.kind {
            Kind::Local => local(context),
            Kind::Temporary => Ok(PreviewSourceLoad::ready(SyncSourceBatch {
                networks: context.sync.temporary_bans.active_ips(context.sync.cutoff),
                notices: Vec::new(),
            })),
            Kind::Safelist => Ok(PreviewSourceLoad::ready(SyncSourceBatch {
                networks: context.sync.config.safe.ips.clone(),
                notices: Vec::new(),
            })),
            Kind::Remote => remote(context, &self.user_agent),
            Kind::Github => github(context, &self.user_agent),
            Kind::Asn => asns(context),
        }
    }
}

/// Builds the same ordered provider identities and roles as normal sync, using data-only readers.
///
/// # Errors
///
/// Returns an error if a built-in provider identity is duplicated.
pub fn build_preview_source_registry(
    product_version: &str,
) -> Result<PreviewSourceRegistry, AppError> {
    let mut registry = PreviewSourceRegistry::new();
    for kind in [
        Kind::Local,
        Kind::Temporary,
        Kind::Remote,
        Kind::Safelist,
        Kind::Github,
        Kind::Asn,
    ] {
        registry.register(Provider {
            kind,
            user_agent: format!("kidobo/{product_version}"),
        })?;
    }
    Ok(registry)
}

fn disabled(id: &str) -> PreviewSourceLoad {
    PreviewSourceLoad {
        observations: vec![SourceObservation {
            label: id.to_string(),
            provenance: SourceProvenance::Disabled,
        }],
        ..PreviewSourceLoad::default()
    }
}

fn local(context: &PreviewSourceContext<'_>) -> Result<PreviewSourceLoad, AppError> {
    let path = &context.sync.paths.blocklist_file;
    let document = load_blocklist_document(path)?;
    let normalized = document.canonicalized_contents();
    if normalized.len() > BLOCKLIST_READ_LIMIT {
        return Err(AppError::PreviewSourceBudget {
            provider: "local-blocklist",
            reason: "normalized local blocklist exceeds the existing 16 MiB source bound"
                .to_string(),
        });
    }
    let document =
        BlocklistDocument::parse(&normalized).map_err(|source| AppError::BlocklistParseLine {
            path: path.clone(),
            line: source.line_number,
            content: source.content,
        })?;
    Ok(PreviewSourceLoad::ready(SyncSourceBatch {
        networks: document
            .lines
            .into_iter()
            .filter_map(|line| line.canonical)
            .collect(),
        notices: Vec::new(),
    }))
}

struct CancellableClient<'a> {
    inner: &'a ReqwestHttpClient,
    cancellation: &'a dyn kidobo_app::ports::Cancellation,
}

impl HttpClient for CancellableClient<'_> {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
        self.cancellation
            .check()
            .map_err(|error| HttpClientError::Request {
                reason: error.to_string(),
            })?;
        self.inner.fetch(request)
    }
}

fn client(context: &PreviewSourceContext<'_>, user_agent: &str) -> Option<ReqwestHttpClient> {
    context.allow_network.then(|| {
        ReqwestHttpClient::with_user_agent_and_timeout(
            user_agent,
            Duration::from_secs(u64::from(context.sync.config.remote.timeout_secs.get())),
        )
    })
}

fn remote(
    context: &PreviewSourceContext<'_>,
    user_agent: &str,
) -> Result<PreviewSourceLoad, AppError> {
    let mut urls = context
        .sync
        .config
        .remote
        .urls
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    urls.sort_unstable();
    urls.dedup();
    if urls.is_empty() {
        return Ok(disabled("remote-feeds"));
    }
    let client = client(context, user_agent);
    let limit = remote_aggregate_limit(context.sync.config.ipset.maxelem.get());
    let mut aggregate = BTreeSet::new();
    let mut observations = Vec::new();
    let mut notices = Vec::new();
    for chunk in urls.chunks(MAX_REMOTE_FETCH_WORKERS) {
        context.sync.cancellation.check()?;
        let results = read_chunk(context, chunk, client.as_ref());
        context.sync.cancellation.check()?;
        for RemoteRead { url, result, .. } in results {
            let loaded = match result {
                Ok(loaded) => loaded,
                Err(ReadOnlyIplistError::CacheRead(source)) => {
                    observations.push(SourceObservation {
                        label: url.to_string(),
                        provenance: SourceProvenance::Unavailable,
                    });
                    notices.push(Notice::warning(format!(
                        "Preview remote cache unavailable for {url}: {source}"
                    )));
                    continue;
                }
                Err(ReadOnlyIplistError::NormalizedLimit { bytes, limit }) => {
                    return Err(AppError::PreviewSourceBudget {
                        provider: "remote-feeds",
                        reason: format!("normalized source {url} has {bytes} bytes; limit={limit}"),
                    });
                }
            };
            observations.push(SourceObservation {
                label: url.to_string(),
                provenance: loaded.provenance,
            });
            notices.extend(loaded.notices);
            for network in loaded.networks {
                aggregate.insert(network);
                if aggregate.len() > limit {
                    return Err(AppError::SourceAggregateBudgetExceeded {
                        entries: aggregate.len(),
                        limit,
                    });
                }
            }
        }
    }
    Ok(PreviewSourceLoad {
        primary: SyncSourceBatch {
            networks: aggregate.into_iter().collect(),
            notices,
        },
        fallback: None,
        observations,
    })
}

struct RemoteRead<'a> {
    index: usize,
    url: &'a str,
    result: Result<ReadOnlyIplist, ReadOnlyIplistError>,
}

fn read_chunk<'a>(
    context: &PreviewSourceContext<'_>,
    urls: &[&'a str],
    client: Option<&ReqwestHttpClient>,
) -> Vec<RemoteRead<'a>> {
    read_chunk_with(context.sync.cancellation, urls, |url| {
        let client = client.map(|inner| CancellableClient {
            inner,
            cancellation: context.sync.cancellation,
        });
        let client = client.as_ref().map(|client| -> &dyn HttpClient { client });
        read_iplist_for_preview(
            client,
            url,
            &context.sync.paths.remote_cache_dir,
            context.sync.env,
            context.sync.config.ipset.maxelem.get(),
        )
    })
}

fn read_chunk_with<'a, F>(
    cancellation: &dyn kidobo_app::ports::Cancellation,
    urls: &[&'a str],
    read: F,
) -> Vec<RemoteRead<'a>>
where
    F: Fn(&'a str) -> Result<ReadOnlyIplist, ReadOnlyIplistError> + Sync,
{
    let results = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for (index, url) in urls.iter().copied().enumerate() {
            if cancellation.is_cancelled() {
                break;
            }
            let results = &results;
            let read = &read;
            scope.spawn(move || {
                if cancellation.is_cancelled() {
                    return;
                }
                let result = read(url);
                results
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(RemoteRead { index, url, result });
            });
        }
    });
    let mut results = results
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    results.sort_unstable_by_key(|read| read.index);
    results
}

fn github(
    context: &PreviewSourceContext<'_>,
    user_agent: &str,
) -> Result<PreviewSourceLoad, AppError> {
    if !context.sync.config.safe.include_github_meta {
        return Ok(disabled("github-metadata"));
    }
    let client = client(context, user_agent);
    let cancellable = client.as_ref().map(|inner| CancellableClient {
        inner,
        cancellation: context.sync.cancellation,
    });
    let loaded = read_github_meta_for_preview(
        cancellable
            .as_ref()
            .map(|client| -> &dyn HttpClient { client }),
        &context.sync.paths.remote_cache_dir,
        &context.sync.config.safe.github_meta_url,
        &context.sync.config.safe.github_meta_category_mode(),
        context.sync.env,
    );
    context.sync.cancellation.check()?;
    Ok(PreviewSourceLoad {
        primary: SyncSourceBatch {
            networks: loaded.primary.networks,
            notices: loaded.notices,
        },
        fallback: loaded.fallback.map(|networks| SyncSourceBatch {
            networks,
            notices: Vec::new(),
        }),
        observations: vec![SourceObservation {
            label: "github-metadata".to_string(),
            provenance: loaded.primary.provenance,
        }],
    })
}

fn asns(context: &PreviewSourceContext<'_>) -> Result<PreviewSourceLoad, AppError> {
    let config = context.sync.config;
    let mut asns = config.asn.banned.clone();
    asns.extend(context.sync.temporary_bans.active_asns(context.sync.cutoff));
    asns.sort_unstable();
    asns.dedup();
    if asns.is_empty() {
        return Ok(disabled("asn-bans"));
    }
    let resolver = context
        .allow_network
        .then(Bgpq4AsnPrefixResolver::with_default_timeout);
    let resolver = resolver
        .as_ref()
        .map(|resolver| -> &dyn AsnPrefixResolver { resolver });
    let mut networks = BTreeSet::new();
    let mut observations = Vec::new();
    let mut notices = Vec::new();
    for asn in asns {
        context.sync.cancellation.check()?;
        let loaded = read_asn_for_preview(
            asn,
            &context.sync.paths.cache_dir.join("asn"),
            Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get())),
            resolver,
        )
        .map_err(|source| AppError::Source {
            provider: "asn-bans",
            source: Box::new(source),
        })?;
        observations.push(SourceObservation {
            label: format!("AS{asn}"),
            provenance: loaded.source,
        });
        if loaded.stale {
            notices.push(Notice::warning(format!("Preview uses stale cached ASN prefixes for AS{asn}; this does not establish current ASN announcements")));
        }
        networks.extend(loaded.prefixes);
    }
    context.sync.cancellation.check()?;
    Ok(PreviewSourceLoad {
        primary: SyncSourceBatch {
            networks: networks.into_iter().collect(),
            notices,
        },
        fallback: None,
        observations,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fmt::Write as _;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::path::Path;

    use super::*;
    use kidobo_app::paths::ResolvedPaths;
    use kidobo_app::source::SyncSourceContext;
    use kidobo_core::config::Config;
    use kidobo_core::temporary_bans::TemporaryBans;

    fn paths(root: &Path) -> ResolvedPaths {
        ResolvedPaths {
            root_override: Some(root.to_path_buf()),
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    fn context<'a>(
        paths: &'a ResolvedPaths,
        config: &'a Config,
        temporary: &'a TemporaryBans,
        env: &'a BTreeMap<OsString, OsString>,
    ) -> PreviewSourceContext<'a> {
        PreviewSourceContext {
            sync: SyncSourceContext {
                cancellation: &kidobo_app::ports::NoCancellation,
                paths,
                config,
                temporary_bans: temporary,
                cutoff: 100,
                env,
            },
            allow_network: false,
        }
    }

    struct FixtureHttp(Vec<u8>);
    impl HttpClient for FixtureHttp {
        fn fetch(&self, _: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            Ok(HttpResponse {
                status: reqwest::StatusCode::OK,
                body: self.0.clone(),
                etag: None,
                last_modified: None,
            })
        }
    }

    fn cached(paths: &ResolvedPaths, url: &str, body: &str) {
        crate::http_cache::fetch_iplist_with_cache(
            &FixtureHttp(body.as_bytes().to_vec()),
            url,
            &paths.remote_cache_dir,
            &BTreeMap::new(),
        )
        .expect("seed validated cache fixture");
    }

    #[test]
    fn preview_and_normal_sync_register_identical_roles_order_and_failure_policy() {
        assert_eq!(
            build_preview_source_registry("test")
                .expect("preview registry")
                .descriptors(),
            crate::sync_sources::build_sync_source_registry("test")
                .expect("sync registry")
                .descriptors()
        );
    }

    #[test]
    fn pre_cancelled_chunk_starts_no_workers_or_cache_reads() {
        struct Cancelled(std::sync::atomic::AtomicUsize);
        impl kidobo_app::ports::Cancellation for Cancelled {
            fn is_cancelled(&self) -> bool {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            }
        }
        let cancelled = Cancelled(std::sync::atomic::AtomicUsize::new(0));
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let results = read_chunk_with(
            &cancelled,
            &["https://a.test", "https://b.test", "https://c.test"],
            |_| {
                reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(ReadOnlyIplist {
                    networks: Vec::new(),
                    provenance: SourceProvenance::Unavailable,
                    notices: Vec::new(),
                })
            },
        );
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(cancelled.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn cancellation_after_spawn_is_checked_again_before_cache_io() {
        struct CancelAfterSpawn(std::sync::atomic::AtomicUsize);
        impl kidobo_app::ports::Cancellation for CancelAfterSpawn {
            fn is_cancelled(&self) -> bool {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
            }
        }
        let cancelled = CancelAfterSpawn(std::sync::atomic::AtomicUsize::new(0));
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let results = read_chunk_with(&cancelled, &["https://a.test"], |_| {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(ReadOnlyIplist {
                networks: Vec::new(),
                provenance: SourceProvenance::Unavailable,
                notices: Vec::new(),
            })
        });
        assert_eq!(reads.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(cancelled.0.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn local_preview_collapses_in_memory_without_normalization_sidecars_or_rewrites() {
        let root = tempfile::tempdir().expect("root");
        let paths = paths(root.path());
        fs::create_dir_all(&paths.data_dir).expect("data");
        let original = "# preserve\r\n192.0.2.128/25\r\n192.0.2.0/25\r\n192.0.2.1\n";
        fs::write(&paths.blocklist_file, original).expect("source");
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\n").expect("config");
        let load = local(&context(
            &paths,
            &config,
            &TemporaryBans::default(),
            &BTreeMap::new(),
        ))
        .expect("read-only local plan");
        assert_eq!(
            load.primary
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/24"]
        );
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(
                &paths.blocklist_file,
                BLOCKLIST_READ_LIMIT
            )
            .expect("preserved source"),
            original
        );
        assert!(!paths.cache_dir.exists());
    }

    #[test]
    fn offline_remote_observations_are_unique_ordered_and_aggregate_cidrs_are_deduplicated() {
        let root = tempfile::tempdir().expect("root");
        let paths = paths(root.path());
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\n[remote]\nurls=['https://z.test/feed','https://a.test/feed','https://a.test/feed']\n").expect("config");
        for url in &config.remote.urls {
            cached(&paths, url, "203.0.113.0/24\n");
        }
        let load = remote(
            &context(&paths, &config, &TemporaryBans::default(), &BTreeMap::new()),
            "test",
        )
        .expect("offline remote data");
        assert_eq!(load.primary.networks.len(), 1);
        assert_eq!(
            load.observations
                .iter()
                .map(|source| source.label.as_str())
                .collect::<Vec<_>>(),
            ["https://a.test/feed", "https://z.test/feed"]
        );
        assert!(
            load.observations
                .iter()
                .all(|source| source.provenance == SourceProvenance::Cache)
        );
    }

    #[test]
    fn preview_remote_aggregate_rejects_many_individually_acceptable_feeds() {
        let root = tempfile::tempdir().expect("root");
        let paths = paths(root.path());
        let config = Config::from_toml_str("[ipset]\nset_name='kidobo'\nmaxelem=1\n[remote]\nurls=['https://a.test/feed','https://b.test/feed','https://c.test/feed']\n").expect("config");
        for (group, url) in (0..3_u32).zip(&config.remote.urls) {
            let body = (0..3000_u32).fold(String::new(), |mut body, entry| {
                writeln!(
                    body,
                    "{}/32",
                    Ipv4Addr::from((10_u32 << 24) + (group << 16) + entry)
                )
                .expect("fixture body");
                body
            });
            cached(&paths, url, &body);
        }
        match remote(
            &context(&paths, &config, &TemporaryBans::default(), &BTreeMap::new()),
            "test",
        )
        .expect_err("aggregate admission enforced")
        {
            AppError::SourceAggregateBudgetExceeded { entries, limit } => {
                assert_eq!(entries, 8193);
                assert_eq!(limit, 8192);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
