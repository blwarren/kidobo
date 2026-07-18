use std::time::Duration;

use log::info;

use crate::adapters::command_runner::SudoCommandRunner;
use crate::adapters::config::load_config_from_file;
use crate::adapters::http_cache::ReqwestHttpClient;
use crate::adapters::lock::acquire_non_blocking;
use crate::adapters::path::{PathResolutionInput, resolve_paths};
use crate::app::sync::{SyncStageTimer, run as run_sync};
use crate::error::KidoboError;

pub fn run_sync_command(timer: bool) -> Result<(), KidoboError> {
    let mut stage_timer = SyncStageTimer::new(timer);
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    stage_timer.mark("resolve_paths");
    let config = load_config_from_file(&paths.config_file)?;
    stage_timer.mark("load_config");

    let _lock = acquire_non_blocking(&paths.lock_file)?;
    stage_timer.mark("acquire_lock");

    let http_client = ReqwestHttpClient::with_timeout(Duration::from_secs(u64::from(
        config.remote.timeout_secs.get(),
    )));
    let sudo_runner = SudoCommandRunner::default();

    let summary = run_sync(
        &paths,
        &config,
        &path_input.env,
        &http_client,
        &sudo_runner,
        &sudo_runner,
        &mut stage_timer,
    )?;
    stage_timer.mark("sync_pipeline_complete");

    info!(
        "sync completed: ipv4_entries={} ipv6_entries={}",
        summary.ipv4_entries, summary.ipv6_entries
    );

    Ok(())
}

#[cfg(test)]
pub(crate) use crate::app::sync::run_sync_with_dependencies;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::run_sync_with_dependencies;
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::adapters::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};
    use crate::adapters::ipset::{IpsetCommandRunner, IpsetFamily, IpsetSetSpec};
    use crate::adapters::iptables::FirewallCommandRunner;
    use crate::adapters::limited_io::read_to_string_with_limit;
    use crate::adapters::path::ResolvedPaths;
    use crate::app::sync::{
        MAX_REMOTE_FETCH_WORKERS, RESTORE_SCRIPT_READ_LIMIT, ensure_within_maxelem,
        fetch_remote_networks_concurrently, remote_fetch_worker_count_for,
    };
    use crate::core::config::{
        AsnCacheStaleAfterSecs, AsnConfig, Config, FirewallAction, HashsizePow2, IpsetConfig,
        MaxElem, RemoteConfig, RemoteTimeoutSecs, SafeConfig,
    };
    use crate::core::network::{CanonicalCidr, cidr_overlaps, parse_ip_cidr_token};
    use crate::error::KidoboError;

    struct MockHttpClient<'a> {
        responses: Mutex<BTreeMap<String, VecDeque<Result<HttpResponse, HttpClientError>>>>,
        events: &'a Mutex<Vec<String>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        delay_ms: u64,
    }

    impl<'a> MockHttpClient<'a> {
        fn new(
            responses: BTreeMap<String, VecDeque<Result<HttpResponse, HttpClientError>>>,
            events: &'a Mutex<Vec<String>>,
            delay_ms: u64,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                events,
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                delay_ms,
            }
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }

        fn update_max_in_flight(&self, current: usize) {
            let mut observed = self.max_in_flight.load(Ordering::SeqCst);
            while current > observed {
                match self.max_in_flight.compare_exchange(
                    observed,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(next) => observed = next,
                }
            }
        }
    }

    impl HttpClient for MockHttpClient<'_> {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            {
                let mut events = self
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                events.push(format!("http:{}", request.url));
            }

            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.update_max_in_flight(current);

            if self.delay_ms > 0 {
                thread::sleep(Duration::from_millis(self.delay_ms));
            }

            let response = {
                let mut guard = self
                    .responses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let queue = guard
                    .get_mut(&request.url)
                    .expect("response queue for requested URL");
                queue.pop_front().expect("queued HTTP response")
            };

            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            response
        }
    }

    struct MockCommandRunner<'a> {
        events: &'a Mutex<Vec<String>>,
        restore_scripts: Mutex<Vec<String>>,
        fail_restore_target: Option<String>,
        fail_firewall_append: bool,
    }

    impl<'a> MockCommandRunner<'a> {
        fn new(events: &'a Mutex<Vec<String>>) -> Self {
            Self {
                events,
                restore_scripts: Mutex::new(Vec::new()),
                fail_restore_target: None,
                fail_firewall_append: false,
            }
        }

        fn failing_restore_for(mut self, target: &str) -> Self {
            self.fail_restore_target = Some(target.to_string());
            self
        }

        fn failing_firewall_append(mut self) -> Self {
            self.fail_firewall_append = true;
            self
        }

        fn events(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn swap_targets(&self) -> Vec<String> {
            self.restore_scripts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter_map(|script| {
                    script
                        .lines()
                        .find(|line| line.starts_with("swap "))
                        .and_then(|line| line.split_whitespace().nth(2))
                        .map(ToString::to_string)
                })
                .collect()
        }

        fn entries_for_target_set(&self, target_set_name: &str) -> Vec<String> {
            let mut entries = self
                .restore_scripts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter_map(|script| {
                    let target = script
                        .lines()
                        .find(|line| line.starts_with("swap "))
                        .and_then(|line| line.split_whitespace().nth(2))?;
                    if target != target_set_name {
                        return None;
                    }

                    Some(
                        script
                            .lines()
                            .filter(|line| line.starts_with("add "))
                            .filter_map(|line| line.split_whitespace().nth(2))
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    )
                })
                .flatten()
                .collect::<Vec<_>>();
            entries.sort();
            entries
        }

        fn run_impl(&self, command: &str, args: &[&str]) -> CommandResult {
            {
                let mut events = self
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                events.push(format!("cmd:{} {}", command, args.join(" ")));
            }

            if command == "ipset" && args.first() == Some(&"restore") && args.len() == 3 {
                let script =
                    read_to_string_with_limit(Path::new(args[2]), RESTORE_SCRIPT_READ_LIMIT)
                        .expect("restore script readable");
                let target = script
                    .lines()
                    .find(|line| line.starts_with("swap "))
                    .and_then(|line| line.split_whitespace().nth(2));
                if target == self.fail_restore_target.as_deref() {
                    return failure("injected restore failure");
                }
                self.restore_scripts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(script);
                return success();
            }

            let effective_args = if args.starts_with(&["-w", "5"]) {
                &args[2..]
            } else {
                args
            };

            if self.fail_firewall_append
                && matches!(command, "iptables" | "ip6tables")
                && effective_args.first() == Some(&"-A")
            {
                return failure("injected firewall append failure");
            }

            match (command, effective_args.first().copied()) {
                ("ipset", Some("list")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "The set with the given name does not exist".to_string(),
                },
                ("ipset", Some("destroy")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "The set with the given name does not exist".to_string(),
                },
                ("iptables" | "ip6tables", Some("-S")) => {
                    if effective_args.get(1) == Some(&"INPUT") {
                        success()
                    } else {
                        let created = self
                            .events
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .iter()
                            .any(|event| event.starts_with(&format!("cmd:{command} -w 5 -N ")));
                        if created {
                            success()
                        } else {
                            CommandResult {
                                status: ProcessStatus::Exited(1),
                                stdout: String::new(),
                                stderr: "No chain/target/match by that name".to_string(),
                            }
                        }
                    }
                }
                ("iptables" | "ip6tables", Some("-D")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
                },
                _ => success(),
            }
        }
    }

    impl IpsetCommandRunner for MockCommandRunner<'_> {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    impl FirewallCommandRunner for MockCommandRunner<'_> {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    fn success() -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn failure(stderr: &str) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    fn test_paths(root: &Path) -> ResolvedPaths {
        ResolvedPaths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    fn test_config(urls: Vec<String>) -> Config {
        Config {
            ipset: IpsetConfig {
                set_name: "kidobo".to_string(),
                set_name_v6: "kidobo-v6".to_string(),
                enable_ipv6: true,
                chain_action: FirewallAction::Drop,
                set_type: "hash:net".to_string(),
                hashsize: HashsizePow2::new(65536).expect("valid hashsize"),
                maxelem: MaxElem::new(500000).expect("valid maxelem"),
                timeout: 0,
            },
            safe: SafeConfig {
                ips: vec![parse_ip_cidr_token("10.0.0.0/25").expect("valid safe cidr")],
                include_github_meta: false,
                github_meta_url: "https://api.github.com/meta".to_string(),
                github_meta_categories: None,
            },
            remote: RemoteConfig {
                urls,
                timeout_secs: RemoteTimeoutSecs::new(30).expect("valid timeout"),
            },
            asn: AsnConfig {
                banned: Vec::new(),
                cache_stale_after_secs: AsnCacheStaleAfterSecs::new(86_400).expect("valid stale"),
            },
        }
    }

    fn test_config_with_ipv6(urls: Vec<String>, enable_ipv6: bool) -> Config {
        Config {
            ipset: IpsetConfig {
                set_name: "kidobo".to_string(),
                set_name_v6: "kidobo-v6".to_string(),
                enable_ipv6,
                chain_action: FirewallAction::Drop,
                set_type: "hash:net".to_string(),
                hashsize: HashsizePow2::new(65536).expect("valid hashsize"),
                maxelem: MaxElem::new(500000).expect("valid maxelem"),
                timeout: 0,
            },
            safe: SafeConfig {
                ips: Vec::new(),
                include_github_meta: false,
                github_meta_url: "https://api.github.com/meta".to_string(),
                github_meta_categories: None,
            },
            remote: RemoteConfig {
                urls,
                timeout_secs: RemoteTimeoutSecs::new(30).expect("valid timeout"),
            },
            asn: AsnConfig {
                banned: Vec::new(),
                cache_stale_after_secs: AsnCacheStaleAfterSecs::new(86_400).expect("valid stale"),
            },
        }
    }

    fn assert_entries_disjoint_from_safelist(entries: &[String], safelist: &[CanonicalCidr]) {
        for entry in entries {
            let parsed = parse_ip_cidr_token(entry).expect("restore entry must parse as CIDR");
            for safe in safelist {
                match (parsed, *safe) {
                    (CanonicalCidr::V4(_), CanonicalCidr::V4(_))
                    | (CanonicalCidr::V6(_), CanonicalCidr::V6(_)) => {
                        assert!(
                            !cidr_overlaps(parsed, *safe),
                            "restore entry {parsed} overlaps safelist entry {safe}"
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn sync_prepares_artifacts_before_fetch_and_activates_after_swaps() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/64\n").expect("write blocklist");

        let url_a = "https://example.com/a.txt".to_string();
        let url_b = "https://example.com/b.txt".to_string();
        let config = test_config(vec![url_a.clone(), url_b.clone()]);

        let events = Mutex::new(Vec::new());

        let mut responses = BTreeMap::new();
        responses.insert(
            url_a.clone(),
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        );
        responses.insert(
            url_b.clone(),
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"2001:db8:1::/64\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        );

        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 2);

        let events = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        let first_http = events
            .iter()
            .position(|entry| entry.starts_with("http:"))
            .expect("http event");
        let iptables_create = events
            .iter()
            .position(|entry| entry.contains("cmd:iptables -w 5 -N kidobo-input"))
            .expect("iptables chain creation event");

        assert!(
            iptables_create < first_http,
            "firewall artifacts must be prepared before remote fetch"
        );
        let last_restore = events
            .iter()
            .rposition(|entry| entry.starts_with("cmd:ipset restore "))
            .expect("restore event");
        let firewall_activation = events
            .iter()
            .position(|entry| entry.contains("cmd:iptables -w 5 -A kidobo-input"))
            .expect("firewall activation event");
        assert!(last_restore < firewall_activation);

        let swap_targets = runner.swap_targets();
        assert_eq!(swap_targets, vec!["kidobo-v6", "kidobo"]);
        assert!(
            events
                .iter()
                .all(|entry| !entry.starts_with("cmd:ipset add ")),
            "sync must populate sets via ipset restore script in one shot"
        );
    }

    #[test]
    fn sync_completes_firewall_wiring_for_both_families_after_remote_fetch() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/64\n").expect("write blocklist");

        let url = "https://example.com/a.txt".to_string();
        let config = test_config(vec![url.clone()]);
        let events = Mutex::new(Vec::new());
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        let events = runner.events();
        let first_http = events
            .iter()
            .position(|entry| entry.starts_with("http:"))
            .expect("http event");
        let last_firewall = events
            .iter()
            .rposition(|entry| {
                entry.starts_with("cmd:iptables") || entry.starts_with("cmd:ip6tables")
            })
            .expect("firewall event");

        assert!(first_http < last_firewall);
    }

    #[test]
    fn sync_ensures_ipset_artifacts_before_remote_fetch() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/64\n").expect("write blocklist");

        let url = "https://example.com/a.txt".to_string();
        let config = test_config(vec![url.clone()]);
        let events = Mutex::new(Vec::new());
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        let events = runner.events();
        let first_http = events
            .iter()
            .position(|entry| entry.starts_with("http:"))
            .expect("http event");
        let last_ipset_ensure = events
            .iter()
            .rposition(|entry| {
                entry.starts_with("cmd:ipset list ") || entry.starts_with("cmd:ipset create ")
            })
            .expect("ipset ensure event");

        assert!(last_ipset_ensure < first_http);
    }

    #[test]
    fn remote_failures_are_soft_and_concurrency_is_bounded() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();

        let events = Mutex::new(Vec::new());

        let urls = (0..8)
            .map(|idx| format!("https://example.com/{idx}.txt"))
            .collect::<Vec<_>>();

        let mut responses = BTreeMap::new();
        for (idx, url) in urls.iter().enumerate() {
            if idx == 3 {
                responses.insert(
                    url.clone(),
                    VecDeque::from([Err(HttpClientError::Request {
                        reason: "offline".to_string(),
                    })]),
                );
            } else {
                responses.insert(
                    url.clone(),
                    VecDeque::from([Ok(HttpResponse {
                        status: StatusCode::OK,
                        body: format!("198.51.100.{}\n", idx + 1).into_bytes(),
                        etag: None,
                        last_modified: None,
                    })]),
                );
            }
        }

        let http_client = MockHttpClient::new(responses, &events, 25);

        let networks =
            fetch_remote_networks_concurrently(&urls, &http_client, cache_dir, &BTreeMap::new());

        assert_eq!(networks.len(), 7);
        assert!(http_client.max_in_flight() <= MAX_REMOTE_FETCH_WORKERS);
    }

    #[test]
    fn remote_worker_count_respects_cpu_budget() {
        assert_eq!(remote_fetch_worker_count_for(8, 1), 1);
        assert_eq!(remote_fetch_worker_count_for(8, 2), 2);
        assert_eq!(
            remote_fetch_worker_count_for(8, MAX_REMOTE_FETCH_WORKERS + 5),
            MAX_REMOTE_FETCH_WORKERS
        );
        assert_eq!(remote_fetch_worker_count_for(2, 8), 2);
    }

    #[test]
    fn minimal_behavioral_example_matches_architecture_contract() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/32\n").expect("write blocklist");

        let url = "https://example.com/minimal.txt".to_string();
        let mut config = test_config(vec![url.clone()]);
        config.safe.ips = vec![parse_ip_cidr_token("10.0.0.0/25").expect("valid safe cidr")];

        let events = Mutex::new(Vec::new());
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"10.0.0.128/25\n198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 1);
        assert_eq!(
            runner.entries_for_target_set("kidobo"),
            vec!["10.0.0.128/25".to_string(), "198.51.100.7/32".to_string()]
        );
        assert_eq!(
            runner.entries_for_target_set("kidobo-v6"),
            vec!["2001:db8::/32".to_string()]
        );

        let events = runner.events();
        assert!(events.iter().any(|entry| {
            entry
                .contains("cmd:iptables -w 5 -A kidobo-input -m set --match-set kidobo src -j DROP")
        }));
        assert!(events.iter().any(|entry| {
            entry.contains(
                "cmd:ip6tables -w 5 -A kidobo-input -m set --match-set kidobo-v6 src -j DROP",
            )
        }));
    }

    #[test]
    fn safelist_carves_all_candidate_routes_including_asn_cache() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::create_dir_all(paths.cache_dir.join("asn")).expect("mkdir asn cache");

        fs::write(&paths.blocklist_file, "10.1.0.0/24\n2001:db8:1::/64\n")
            .expect("write blocklist");
        fs::write(
            paths.cache_dir.join("asn/as64512.iplist"),
            "10.3.0.0/24\n2001:db8:3::/64\n",
        )
        .expect("write asn cache");

        let url = "https://example.com/safe-carve.txt".to_string();
        let mut config = test_config(vec![url.clone()]);
        config.asn.banned = vec![64512];
        config.safe.ips = vec![
            parse_ip_cidr_token("10.1.0.0/25").expect("safe"),
            parse_ip_cidr_token("10.2.0.0/25").expect("safe"),
            parse_ip_cidr_token("10.3.0.0/25").expect("safe"),
            parse_ip_cidr_token("2001:db8:1::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:2::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:3::/65").expect("safe"),
        ];

        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"10.2.0.0/24\n2001:db8:2::/64\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");
        assert_eq!(summary.ipv4_entries, 3);
        assert_eq!(summary.ipv6_entries, 3);

        assert_eq!(
            runner.entries_for_target_set("kidobo"),
            vec![
                "10.1.0.128/25".to_string(),
                "10.2.0.128/25".to_string(),
                "10.3.0.128/25".to_string(),
            ]
        );
        assert_eq!(
            runner.entries_for_target_set("kidobo-v6"),
            vec![
                "2001:db8:1:0:8000::/65".to_string(),
                "2001:db8:2:0:8000::/65".to_string(),
                "2001:db8:3:0:8000::/65".to_string(),
            ]
        );
    }

    #[test]
    fn sync_restore_scripts_exclude_combined_config_and_github_meta_safelist() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::create_dir_all(paths.cache_dir.join("asn")).expect("mkdir asn cache");

        fs::write(
            &paths.blocklist_file,
            "10.10.0.0/24\n2001:db8:10::/64\n2001:db8:20::/64\n",
        )
        .expect("write blocklist");
        fs::write(
            paths.cache_dir.join("asn/as64512.iplist"),
            "10.30.0.0/24\n2001:db8:40::/64\n",
        )
        .expect("write asn cache");

        let remote_url = "https://example.com/combined-safe-remote.txt".to_string();
        let github_meta_url = "https://example.com/github-meta.json".to_string();
        let mut config = test_config(vec![remote_url.clone()]);
        config.asn.banned = vec![64512];
        config.safe.ips = vec![
            parse_ip_cidr_token("10.10.0.0/25").expect("safe"),
            parse_ip_cidr_token("10.20.0.0/25").expect("safe"),
            parse_ip_cidr_token("10.30.0.0/25").expect("safe"),
            parse_ip_cidr_token("2001:db8:10::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:30::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:40::/65").expect("safe"),
        ];
        config.safe.include_github_meta = true;
        config.safe.github_meta_url = github_meta_url.clone();
        config.safe.github_meta_categories = Some(vec!["hooks".to_string()]);

        let github_safelist = vec![
            parse_ip_cidr_token("10.10.0.128/25").expect("safe"),
            parse_ip_cidr_token("10.20.0.128/25").expect("safe"),
            parse_ip_cidr_token("10.30.0.128/25").expect("safe"),
            parse_ip_cidr_token("2001:db8:10:0:8000::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:20::/64").expect("safe"),
            parse_ip_cidr_token("2001:db8:30:0:8000::/65").expect("safe"),
            parse_ip_cidr_token("2001:db8:40:0:8000::/65").expect("safe"),
        ];

        let responses = BTreeMap::from([
            (
                remote_url,
                VecDeque::from([Ok(HttpResponse {
                    status: StatusCode::OK,
                    body: b"10.20.0.0/24\n198.51.100.0/24\n2001:db8:30::/64\n2001:db8:50::/64\n"
                        .to_vec(),
                    etag: None,
                    last_modified: None,
                })]),
            ),
            (
                github_meta_url,
                VecDeque::from([Ok(HttpResponse {
                    status: StatusCode::OK,
                    body: br#"{
                        "hooks": [
                            "10.10.0.128/25",
                            "10.20.0.128/25",
                            "10.30.0.128/25",
                            "2001:db8:10:0:8000::/65",
                            "2001:db8:20::/64",
                            "2001:db8:30:0:8000::/65",
                            "2001:db8:40:0:8000::/65"
                        ],
                        "api": ["198.51.100.0/24", "2001:db8:50::/64"]
                    }"#
                    .to_vec(),
                    etag: None,
                    last_modified: None,
                })]),
            ),
        ]);

        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");
        assert_eq!(summary.ipv4_entries, 1);
        assert_eq!(summary.ipv6_entries, 1);

        let ipv4_entries = runner.entries_for_target_set("kidobo");
        let ipv6_entries = runner.entries_for_target_set("kidobo-v6");

        let mut combined_safelist = config.safe.ips.clone();
        combined_safelist.extend(github_safelist);
        assert_entries_disjoint_from_safelist(&ipv4_entries, &combined_safelist);
        assert_entries_disjoint_from_safelist(&ipv6_entries, &combined_safelist);

        assert_eq!(ipv4_entries, vec!["198.51.100.0/24".to_string()]);
        assert_eq!(ipv6_entries, vec!["2001:db8:50::/64".to_string()]);
    }

    #[test]
    fn sync_restore_scripts_are_disjoint_from_safelist_hosts_and_prefixes() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::create_dir_all(paths.cache_dir.join("asn")).expect("mkdir asn cache");

        fs::write(
            &paths.blocklist_file,
            "0.0.0.0/0\n10.0.0.0/8\n::/0\n2001:db8::/32\n",
        )
        .expect("write blocklist");
        fs::write(
            paths.cache_dir.join("asn/as64512.iplist"),
            "192.0.2.0/24\n2001:4860:1::/48\n",
        )
        .expect("write asn cache");

        let url = "https://example.com/edge-safe.txt".to_string();
        let mut config = test_config(vec![url.clone()]);
        config.asn.banned = vec![64512];
        config.safe.ips = vec![
            parse_ip_cidr_token("0.0.0.0/32").expect("safe"),
            parse_ip_cidr_token("255.255.255.255/32").expect("safe"),
            parse_ip_cidr_token("10.0.0.0/8").expect("safe"),
            parse_ip_cidr_token("192.0.2.0/24").expect("safe"),
            parse_ip_cidr_token("::/128").expect("safe"),
            parse_ip_cidr_token("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128").expect("safe"),
            parse_ip_cidr_token("2001:db8::/32").expect("safe"),
            parse_ip_cidr_token("2001:4860:1::/48").expect("safe"),
        ];

        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.0/24\n2001:4860::/32\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");
        assert!(summary.ipv4_entries > 0);
        assert!(summary.ipv6_entries > 0);

        let ipv4_entries = runner.entries_for_target_set("kidobo");
        let ipv6_entries = runner.entries_for_target_set("kidobo-v6");
        assert_entries_disjoint_from_safelist(&ipv4_entries, &config.safe.ips);
        assert_entries_disjoint_from_safelist(&ipv6_entries, &config.safe.ips);
    }

    #[test]
    fn sync_applies_reject_target_when_configured() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n").expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.ipset.chain_action = FirewallAction::Reject;

        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        let events = runner.events();
        assert!(events.iter().any(|entry| {
            entry.contains(
                "cmd:iptables -w 5 -A kidobo-input -m set --match-set kidobo src -j REJECT",
            )
        }));
        assert!(events.iter().any(|entry| {
            entry.contains(
                "cmd:ip6tables -w 5 -A kidobo-input -m set --match-set kidobo-v6 src -j REJECT",
            )
        }));
    }

    #[test]
    fn sync_respects_ipv6_disable_mode_end_to_end() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/32\n").expect("write blocklist");

        let url = "https://example.com/ipv6-off.txt".to_string();
        let config = test_config_with_ipv6(vec![url.clone()], false);
        let events = Mutex::new(Vec::new());
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n2001:db8:ffff::/48\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 0);
        assert_eq!(runner.swap_targets(), vec!["kidobo"]);
        assert_eq!(
            runner.entries_for_target_set("kidobo"),
            vec!["10.0.0.0/24".to_string(), "198.51.100.7/32".to_string()]
        );
        let events = runner.events();
        assert!(
            events
                .iter()
                .any(|entry| entry == "cmd:ip6tables -w 5 -D INPUT -j kidobo-input")
        );
        assert!(
            events
                .iter()
                .any(|entry| entry == "cmd:ipset destroy kidobo-v6")
        );
    }

    #[test]
    fn sync_fails_early_with_clear_error_when_effective_entries_exceed_maxelem() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n198.51.100.7\n").expect("write blocklist");

        let mut config = test_config_with_ipv6(Vec::new(), false);
        config.ipset.maxelem = MaxElem::new(1).expect("valid maxelem");

        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner_events = Mutex::new(Vec::new());
        let runner = MockCommandRunner::new(&runner_events);

        let err = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("sync must fail");

        assert!(matches!(
            err,
            KidoboError::IpsetCapacityExceeded {
                family: "ipv4",
                ref set_name,
                entries: 2,
                maxelem: 1
            } if set_name == "kidobo"
        ));
        assert!(runner.swap_targets().is_empty());
    }

    #[test]
    fn ipv4_capacity_failure_prevents_ipv6_swap_and_firewall_activation() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(
            &paths.blocklist_file,
            "10.0.0.0/24\n198.51.100.0/24\n2001:db8::/64\n",
        )
        .expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.ipset.maxelem = MaxElem::new(1).expect("valid maxelem");
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events);

        let err = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("sync must fail");

        assert!(matches!(
            err,
            KidoboError::IpsetCapacityExceeded { family: "ipv4", .. }
        ));
        assert!(runner.swap_targets().is_empty());
        assert!(runner.events().iter().all(|entry| {
            !entry.contains(" -A kidobo-input ") && !entry.contains(" -I INPUT 1 ")
        }));
    }

    #[test]
    fn ipv6_capacity_failure_prevents_all_swaps_and_firewall_activation() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(
            &paths.blocklist_file,
            "10.0.0.0/24\n2001:db8::/64\n2001:db8:1::/64\n",
        )
        .expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.ipset.maxelem = MaxElem::new(1).expect("valid maxelem");
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events);

        let err = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("sync must fail");

        assert!(matches!(
            err,
            KidoboError::IpsetCapacityExceeded {
                family: "ipv6",
                ref set_name,
                entries: 2,
                maxelem: 1
            } if set_name == "kidobo-v6"
        ));
        assert!(runner.swap_targets().is_empty());
        assert!(runner.events().iter().all(|entry| {
            !entry.contains(" -A kidobo-input ") && !entry.contains(" -I INPUT 1 ")
        }));
    }

    #[test]
    fn ipv6_restore_failure_stops_before_ipv4_restore_and_firewall_activation() {
        let (temp, paths) = populated_dual_stack_paths();
        let config = test_config(Vec::new());
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events).failing_restore_for("kidobo-v6");

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("IPv6 restore must fail");

        let events = runner.events();
        assert!(runner.swap_targets().is_empty());
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("cmd:ipset restore "))
                .count(),
            1
        );
        assert!(events.iter().all(|event| {
            !event.contains(" -A kidobo-input ") && !event.contains(" -I INPUT 1 ")
        }));
        drop(temp);
    }

    #[test]
    fn ipv4_restore_failure_after_ipv6_swap_still_prevents_firewall_activation() {
        let (temp, paths) = populated_dual_stack_paths();
        let config = test_config(Vec::new());
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events).failing_restore_for("kidobo");

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("IPv4 restore must fail");

        let events = runner.events();
        assert_eq!(runner.swap_targets(), vec!["kidobo-v6"]);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("cmd:ipset restore "))
                .count(),
            2
        );
        assert!(events.iter().all(|event| {
            !event.contains(" -A kidobo-input ") && !event.contains(" -I INPUT 1 ")
        }));
        drop(temp);
    }

    #[test]
    fn firewall_append_failure_never_inserts_an_input_jump() {
        let (temp, paths) = populated_dual_stack_paths();
        let config = test_config(Vec::new());
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events).failing_firewall_append();

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("firewall append must fail");

        assert_eq!(runner.swap_targets(), vec!["kidobo-v6", "kidobo"]);
        let events = runner.events();
        assert!(
            events
                .iter()
                .any(|event| event.contains("cmd:iptables -w 5 -A "))
        );
        assert!(events.iter().all(|event| !event.contains(" -I INPUT 1 ")));
        assert!(
            events
                .iter()
                .all(|event| !event.contains("cmd:ip6tables -w 5 -A "))
        );
        drop(temp);
    }

    #[test]
    fn github_metadata_failure_is_soft_and_local_sources_are_applied() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "198.51.100.0/24\n2001:db8::/64\n")
            .expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.safe.include_github_meta = true;
        let metadata_url = config.safe.github_meta_url.clone();
        let events = Mutex::new(Vec::new());
        let responses = BTreeMap::from([(
            metadata_url,
            VecDeque::from([Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
        )]);
        let http_client = MockHttpClient::new(responses, &events, 0);
        let runner = MockCommandRunner::new(&events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("GitHub metadata failure must be soft");

        assert_eq!(summary.ipv4_entries, 1);
        assert_eq!(summary.ipv6_entries, 1);
        assert_eq!(runner.swap_targets(), vec!["kidobo-v6", "kidobo"]);
    }

    fn populated_dual_stack_paths() -> (TempDir, ResolvedPaths) {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "198.51.100.0/24\n2001:db8::/64\n")
            .expect("write blocklist");
        (temp, paths)
    }

    #[test]
    fn hard_local_source_failure_does_not_activate_new_set_name() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "not-a-network\n").expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.ipset.set_name = "kidobo-new".to_string();
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("sync must fail");

        assert!(runner.swap_targets().is_empty());
        assert!(runner.events().iter().all(|entry| {
            !entry.contains("--match-set kidobo-new") && !entry.contains(" -I INPUT 1 ")
        }));
    }

    #[test]
    fn disabled_ipv6_cleanup_never_destroys_ipv4_set_name() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n").expect("write blocklist");

        let mut config = test_config_with_ipv6(Vec::new(), false);
        config.ipset.set_name_v6 = config.ipset.set_name.clone();
        let events = Mutex::new(Vec::new());
        let http_client = MockHttpClient::new(BTreeMap::new(), &events, 0);
        let runner = MockCommandRunner::new(&events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert!(
            runner
                .events()
                .iter()
                .all(|entry| entry != "cmd:ipset destroy kidobo")
        );
    }

    #[test]
    fn ensure_within_maxelem_allows_equal_entry_count() {
        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 2,
            timeout: 0,
        };

        ensure_within_maxelem(&spec, 2).expect("must pass");
    }
}
