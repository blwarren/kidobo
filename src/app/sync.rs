use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use log::{error, info, warn};

use crate::adapters::asn::{Bgpq4AsnPrefixResolver, load_asn_prefixes_with_cache};
use crate::adapters::blocklist_file::{
    BlocklistNormalizeResult, normalize_local_blocklist_with_fast_state,
};
use crate::adapters::github_meta::load_github_meta_safelist;
use crate::adapters::http_cache::{HttpClient, fetch_iplist_with_cache};
use crate::adapters::ipset::{
    IpsetCommandRunner, IpsetFamily, IpsetSetSpec, atomic_replace_ipset_values, ensure_ipset_exists,
};
use crate::adapters::iptables::{
    ChainAction, FirewallCommandRunner, FirewallFamily, cleanup_firewall_wiring,
    ensure_firewall_artifacts_for_families, ensure_firewall_wiring_for_families,
};
use crate::adapters::path::ResolvedPaths;
use crate::core::config::{Config, FirewallAction};
use crate::core::network::CanonicalCidr;
use crate::core::sync::{EffectiveBlocklists, compute_effective_blocklists};
use crate::error::KidoboError;

pub(crate) const MAX_REMOTE_FETCH_WORKERS: usize = 5;
const BLOCKLIST_FAST_STATE_FILE: &str = "blocklist-normalize.fast-state";
#[cfg(test)]
pub(crate) const RESTORE_SCRIPT_READ_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SyncSummary {
    pub ipv4_entries: usize,
    pub ipv6_entries: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct SyncStageTimer {
    enabled: bool,
    overall_start: Instant,
    stage_start: Instant,
}

impl SyncStageTimer {
    pub(crate) fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            overall_start: now,
            stage_start: now,
        }
    }

    pub(crate) fn mark(&mut self, stage: &str) {
        if !self.enabled {
            return;
        }

        let now = Instant::now();
        let stage_ms = now.duration_since(self.stage_start).as_millis();
        let total_ms = now.duration_since(self.overall_start).as_millis();
        info!("sync timer: stage={stage} stage_ms={stage_ms} total_ms={total_ms}");
        self.stage_start = now;
    }
}

pub(crate) fn run(
    paths: &ResolvedPaths,
    config: &Config,
    env: &BTreeMap<String, String>,
    http_client: &(dyn HttpClient + Sync),
    ipset_runner: &dyn IpsetCommandRunner,
    firewall_runner: &dyn FirewallCommandRunner,
    timer: &mut SyncStageTimer,
) -> Result<SyncSummary, KidoboError> {
    let ipv4_spec = ipv4_set_spec(config);
    let ipv6_spec = ipv6_set_spec(config);

    ensure_runtime_artifacts(
        config,
        ipset_runner,
        firewall_runner,
        &ipv4_spec,
        &ipv6_spec,
    )?;
    timer.mark("ensure_ipset_artifacts");

    let fast_state_path = paths.cache_dir.join(BLOCKLIST_FAST_STATE_FILE);
    let normalize_result =
        normalize_local_blocklist_with_fast_state(&paths.blocklist_file, &fast_state_path)?;
    if normalize_result == BlocklistNormalizeResult::SkippedUnchanged {
        info!(
            "sync blocklist normalization skipped: unchanged path={}",
            paths.blocklist_file.display()
        );
    }
    timer.mark("normalize_local_blocklist");

    let internal = load_internal_blocklist(&paths.blocklist_file)?;
    timer.mark("load_internal_source");
    let remote = fetch_remote_networks_concurrently(
        &config.remote.urls,
        http_client,
        &paths.remote_cache_dir,
        env,
    );
    timer.mark("load_remote_sources");

    let mut safelist = config.safe.ips.clone();

    if config.safe.include_github_meta {
        match load_github_meta_safelist(
            http_client,
            &paths.remote_cache_dir,
            &config.safe.github_meta_url,
            &config.safe.github_meta_category_mode(),
            env,
        ) {
            Ok(github) => safelist.extend(github.networks),
            Err(err) => warn!("github meta safelist load failed softly: {err}"),
        }
    }
    timer.mark("load_safelist_sources");

    let internal_count = internal.len();
    let remote_count = remote.len();
    let asn_cache_stale_after =
        Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get()));
    let asn_cache_dir = paths.cache_dir.join("asn");
    let asn_resolver = Bgpq4AsnPrefixResolver::with_default_timeout();
    let mut asn_networks = Vec::new();
    for asn in &config.asn.banned {
        let cached = load_asn_prefixes_with_cache(
            *asn,
            &asn_cache_dir,
            asn_cache_stale_after,
            &asn_resolver,
        )?;
        if cached.stale {
            warn!("ASN cache refresh failed; using stale prefixes for AS{asn}");
        }
        asn_networks.extend(cached.prefixes);
    }
    asn_networks.sort_unstable();
    asn_networks.dedup();
    timer.mark("load_asn_sources");
    let asn_count = asn_networks.len();
    let safelist_count = safelist.len();

    let mut candidates = internal;
    candidates.extend(remote);
    candidates.extend(asn_networks);

    let effective = compute_effective_blocklists(&candidates, &safelist, config.ipset.enable_ipv6);
    timer.mark("compute_effective_blocklists");

    apply_runtime_state(
        config,
        &effective,
        &ipv4_spec,
        &ipv6_spec,
        ipset_runner,
        firewall_runner,
        timer,
    )?;

    info!(
        "sync source counts: internal={internal_count} remote={remote_count} asn={asn_count} safelist={safelist_count}"
    );
    info!(
        "sync final ipset counts: ipv4={pv4} ipv6={pv6}",
        pv4 = effective.ipv4.len(),
        pv6 = effective.ipv6.len()
    );

    Ok(SyncSummary {
        ipv4_entries: effective.ipv4.len(),
        ipv6_entries: effective.ipv6.len(),
    })
}

fn ensure_runtime_artifacts(
    config: &Config,
    ipset_runner: &dyn IpsetCommandRunner,
    firewall_runner: &dyn FirewallCommandRunner,
    ipv4_spec: &IpsetSetSpec,
    ipv6_spec: &IpsetSetSpec,
) -> Result<(), KidoboError> {
    ensure_ipset_exists(ipset_runner, ipv4_spec)?;
    if config.ipset.enable_ipv6 {
        ensure_ipset_exists(ipset_runner, ipv6_spec)?;
    }
    ensure_firewall_artifacts_for_families(firewall_runner, config.ipset.enable_ipv6)?;
    Ok(())
}

fn apply_runtime_state(
    config: &Config,
    effective: &EffectiveBlocklists,
    ipv4_spec: &IpsetSetSpec,
    ipv6_spec: &IpsetSetSpec,
    ipset_runner: &dyn IpsetCommandRunner,
    firewall_runner: &dyn FirewallCommandRunner,
    timer: &mut SyncStageTimer,
) -> Result<(), KidoboError> {
    if config.ipset.enable_ipv6 {
        ensure_within_maxelem(ipv6_spec, effective.ipv6.len())?;
    }
    ensure_within_maxelem(ipv4_spec, effective.ipv4.len())?;

    if config.ipset.enable_ipv6 {
        atomic_replace_ipset_values(ipset_runner, ipv6_spec, &effective.ipv6)?;
        timer.mark("apply_ipv6_ipset");
    }
    atomic_replace_ipset_values(ipset_runner, ipv4_spec, &effective.ipv4)?;
    timer.mark("apply_ipv4_ipset");

    ensure_firewall_wiring_for_families(
        firewall_runner,
        &config.ipset.set_name,
        &config.ipset.set_name_v6,
        config.ipset.enable_ipv6,
        chain_action(config),
    )?;
    if !config.ipset.enable_ipv6 {
        cleanup_disabled_ipv6_artifacts(
            firewall_runner,
            ipset_runner,
            &config.ipset.set_name,
            &config.ipset.set_name_v6,
        );
    }
    timer.mark("ensure_firewall_wiring");
    Ok(())
}

#[cfg(test)]
pub(crate) fn run_sync_with_dependencies(
    paths: &ResolvedPaths,
    config: &Config,
    env: &BTreeMap<String, String>,
    http_client: &(dyn HttpClient + Sync),
    ipset_runner: &dyn IpsetCommandRunner,
    firewall_runner: &dyn FirewallCommandRunner,
) -> Result<SyncSummary, KidoboError> {
    let mut timer = SyncStageTimer::new(false);
    run(
        paths,
        config,
        env,
        http_client,
        ipset_runner,
        firewall_runner,
        &mut timer,
    )
}

fn ipv4_set_spec(config: &Config) -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: config.ipset.set_name.clone(),
        set_type: config.ipset.set_type.clone(),
        family: IpsetFamily::Inet,
        hashsize: config.ipset.hashsize.get(),
        maxelem: config.ipset.maxelem.get(),
        timeout: config.ipset.timeout,
    }
}

fn ipv6_set_spec(config: &Config) -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: config.ipset.set_name_v6.clone(),
        set_type: config.ipset.set_type.clone(),
        family: IpsetFamily::Inet6,
        hashsize: config.ipset.hashsize.get(),
        maxelem: config.ipset.maxelem.get(),
        timeout: config.ipset.timeout,
    }
}

pub(crate) fn ensure_within_maxelem(
    spec: &IpsetSetSpec,
    entries: usize,
) -> Result<(), KidoboError> {
    if entries <= spec.maxelem as usize {
        return Ok(());
    }

    let family = match spec.family {
        IpsetFamily::Inet => "ipv4",
        IpsetFamily::Inet6 => "ipv6",
    };

    error!(
        "sync blocked: effective entry count exceeds maxelem: family={} set_name={} entries={} maxelem={}",
        family, spec.set_name, entries, spec.maxelem
    );

    Err(KidoboError::IpsetCapacityExceeded {
        family,
        set_name: spec.set_name.clone(),
        entries,
        maxelem: spec.maxelem,
    })
}

fn chain_action(config: &Config) -> ChainAction {
    match config.ipset.chain_action {
        FirewallAction::Drop => ChainAction::Drop,
        FirewallAction::Reject => ChainAction::Reject,
    }
}

fn cleanup_disabled_ipv6_artifacts(
    firewall_runner: &dyn FirewallCommandRunner,
    ipset_runner: &dyn IpsetCommandRunner,
    set_name_v4: &str,
    set_name_v6: &str,
) {
    if let Err(err) = cleanup_firewall_wiring(firewall_runner, FirewallFamily::Ipv6) {
        warn!("disabled IPv6 firewall cleanup failed softly: {err}");
    }

    if set_name_v6 == set_name_v4 {
        warn!("disabled IPv6 ipset cleanup skipped because its name matches the IPv4 set");
        return;
    }

    match ipset_runner.run("ipset", &["destroy", set_name_v6]) {
        Ok(result) if result.status.success() => {}
        Ok(_) => {}
        Err(err) => warn!("disabled IPv6 ipset cleanup failed softly for {set_name_v6}: {err}"),
    }
}

fn load_internal_blocklist(path: &Path) -> Result<Vec<CanonicalCidr>, KidoboError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let blocklist = crate::adapters::blocklist_file::BlocklistDocument::load(path)?;
    Ok(blocklist
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect())
}

pub(crate) fn fetch_remote_networks_concurrently<S: AsRef<str> + Sync>(
    urls: &[S],
    http_client: &(dyn HttpClient + Sync),
    cache_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Vec<CanonicalCidr> {
    if urls.is_empty() {
        return Vec::new();
    }

    let worker_count = remote_fetch_worker_count(urls.len());
    let next_idx = AtomicUsize::new(0);
    let mut networks = Vec::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    let Some(url) = urls.get(idx) else {
                        break;
                    };

                    let url = url.as_ref();
                    match fetch_iplist_with_cache(http_client, url, cache_dir, env) {
                        Ok(cached) => local.extend(cached.networks),
                        Err(err) => warn!("remote source fetch failed softly for {url}: {err}"),
                    }
                }
                local
            }));
        }

        for handle in handles {
            let local = match handle.join() {
                Ok(local) => local,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            networks.extend(local);
        }
    });

    networks.sort_unstable();
    networks.dedup();
    networks
}

fn remote_fetch_worker_count(url_count: usize) -> usize {
    let cpu_parallelism = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    remote_fetch_worker_count_for(url_count, cpu_parallelism)
}

pub(crate) fn remote_fetch_worker_count_for(url_count: usize, cpu_parallelism: usize) -> usize {
    let cpu_budget = cpu_parallelism.max(1);
    let max_workers = MAX_REMOTE_FETCH_WORKERS.min(cpu_budget);
    url_count.min(max_workers.max(1))
}
