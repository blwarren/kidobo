use std::fs;
use std::hint::black_box;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kidobo_core::config::Config;
use kidobo_core::lookup::{LookupSourceEntry, run_lookup};
use kidobo_core::network::{
    CanonicalCidr, Ipv4Cidr, Ipv6Cidr, collapse_ipv4, parse_ip_cidr_strict, subtract_safelist_ipv4,
    subtract_safelist_ipv6,
};
use kidobo_core::sync::compute_effective_blocklists;

const BENCH_BLOCKLIST_READ_LIMIT: usize = 8 * 1024 * 1024;
const BENCH_REMOTE_IPLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

fn generate_ipv4_cidrs(count: usize) -> Vec<Ipv4Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u32;
        let network = (10_u32 << 24) | ((idx & 0x00ff_ffff) << 8);
        cidrs.push(Ipv4Cidr::new(Ipv4Addr::from(network), 24).expect("valid benchmark prefix"));
    }
    cidrs
}

fn generate_ipv6_cidrs(count: usize) -> Vec<Ipv6Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u128;
        let network = 0x20010db8000000000000000000000000_u128 | (idx << 64);
        cidrs.push(Ipv6Cidr::new(Ipv6Addr::from(network), 64).expect("valid benchmark prefix"));
    }
    cidrs
}

fn generate_candidates(v4_count: usize, v6_count: usize) -> Vec<CanonicalCidr> {
    let mut out = Vec::with_capacity(v4_count + v6_count);
    out.extend(
        generate_ipv4_cidrs(v4_count)
            .into_iter()
            .map(CanonicalCidr::V4),
    );
    out.extend(
        generate_ipv6_cidrs(v6_count)
            .into_iter()
            .map(CanonicalCidr::V6),
    );
    out
}

fn deterministic_shuffle<T>(data: &mut [T]) {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in (1..data.len()).rev() {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        let j = (state as usize) % (i + 1);
        data.swap(i, j);
    }
}

fn generate_disjoint_ipv4_hosts(count: usize) -> Vec<Ipv4Cidr> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(
            Ipv4Cidr::new(Ipv4Addr::from((i as u32) * 4), 32).expect("valid benchmark prefix"),
        );
    }
    out
}

fn generate_contiguous_ipv4_hosts(count: usize) -> Vec<Ipv4Cidr> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        out.push(Ipv4Cidr::new(Ipv4Addr::from(i as u32), 32).expect("valid benchmark prefix"));
    }
    out
}

fn generate_almost_sorted_ipv4_hosts(count: usize) -> Vec<Ipv4Cidr> {
    let mut out = generate_disjoint_ipv4_hosts(count);
    if out.len() < 4 {
        return out;
    }

    let stride = 100_usize;
    for i in (stride..out.len()).step_by(stride) {
        out.swap(i - 1, i);
    }

    out
}

fn benchmark_collapse_ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("collapse_ipv4");
    for size in [10_000_usize, 50_000_usize, 100_000_usize] {
        let disjoint_sorted = generate_disjoint_ipv4_hosts(size);
        let disjoint_almost_sorted = generate_almost_sorted_ipv4_hosts(size);
        let contiguous_sorted = generate_contiguous_ipv4_hosts(size);
        let mut disjoint_shuffled = disjoint_sorted.clone();
        deterministic_shuffle(&mut disjoint_shuffled);

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("disjoint_sorted", size),
            &disjoint_sorted,
            |b, cidrs| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(cidrs)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_almost_sorted", size),
            &disjoint_almost_sorted,
            |b, cidrs| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(cidrs)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_shuffled", size),
            &disjoint_shuffled,
            |b, cidrs| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(cidrs)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("contiguous_sorted", size),
            &contiguous_sorted,
            |b, cidrs| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(cidrs)));
                });
            },
        );
    }
    group.finish();
}

fn benchmark_effective_blocklists(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_effective_blocklists");
    for size in [5_000_usize, 20_000_usize] {
        let candidates = generate_candidates(size, size / 5);
        let safelist = candidates
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 11 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates.len() + safelist.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(compute_effective_blocklists(
                    black_box(&candidates),
                    black_box(&safelist),
                    black_box(true),
                ));
            });
        });
    }
    group.finish();
}

fn benchmark_subtract_safelist(c: &mut Criterion) {
    let mut group = c.benchmark_group("subtract_safelist");

    for size in [10_000_usize, 50_000_usize] {
        let candidates_v4 = generate_ipv4_cidrs(size);
        let safelist_v4 = candidates_v4
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 7 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v4.len() + safelist_v4.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv4", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv4(
                    black_box(&candidates_v4),
                    black_box(&safelist_v4),
                ));
            });
        });
    }

    for size in [2_000_usize, 10_000_usize] {
        let candidates_v6 = generate_ipv6_cidrs(size);
        let safelist_v6 = candidates_v6
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 9 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v6.len() + safelist_v6.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv6", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv6(
                    black_box(&candidates_v6),
                    black_box(&safelist_v6),
                ));
            });
        });
    }

    group.finish();
}

fn benchmark_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_lookup");
    for source_count in [10_000_usize, 25_000_usize] {
        let label: Arc<str> = Arc::from("bench:internal");
        let sources = generate_ipv4_cidrs(source_count)
            .into_iter()
            .map(|cidr| LookupSourceEntry {
                source_label: Arc::clone(&label),
                source_line: cidr.to_string(),
                cidr: CanonicalCidr::V4(cidr),
            })
            .collect::<Vec<_>>();

        let mut targets = Vec::with_capacity(4_000);
        for i in 0..2_000_u32 {
            let host = (10_u32 << 24) | ((i & 0xffff) << 8) | 7;
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }
        for i in 0..2_000_u32 {
            let host = (198_u32 << 24) | (51_u32 << 16) | ((i & 0xff) << 8) | (i & 0xff);
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }

        group.throughput(Throughput::Elements((sources.len() + targets.len()) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(source_count),
            &source_count,
            |b, _| {
                b.iter(|| {
                    black_box(run_lookup(black_box(&targets), black_box(&sources)));
                });
            },
        );
    }
    group.finish();
}

#[derive(Clone)]
struct RealWorldDataset {
    candidates: Vec<CanonicalCidr>,
    safelist: Vec<CanonicalCidr>,
    ipv4_cidrs: Vec<Ipv4Cidr>,
    ipv4_cidrs_by_source: Vec<Vec<Ipv4Cidr>>,
}

fn repeat_vec<T: Clone>(values: &[T], scale: usize) -> Vec<T> {
    let mut out = Vec::with_capacity(values.len() * scale);
    for _ in 0..scale {
        out.extend_from_slice(values);
    }
    out
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn find_real_world_config(root: &Path) -> Option<PathBuf> {
    let root_config = root.join("config.toml");
    if root_config.exists() {
        return Some(root_config);
    }

    let nested = root.join("config/config.toml");
    if nested.exists() {
        return Some(nested);
    }

    None
}

fn read_to_string_with_limit(path: &Path, limit: usize) -> io::Result<String> {
    let len = fs::metadata(path)?.len();
    if len > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} byte limit"),
        ));
    }

    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(len as usize);
    file.read_to_end(&mut bytes)?;
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn parse_non_strict_line(input: &str) -> Option<CanonicalCidr> {
    let token = input.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    parse_ip_cidr_strict(token)
}

fn parse_lines_non_strict(text: &str) -> Vec<CanonicalCidr> {
    text.lines().filter_map(parse_non_strict_line).collect()
}

fn format_cidrs(cidrs: &[CanonicalCidr]) -> String {
    let mut rendered = String::new();
    for (idx, cidr) in cidrs.iter().enumerate() {
        if idx > 0 {
            rendered.push('\n');
        }
        rendered.push_str(&cidr.to_string());
    }
    rendered.push('\n');
    rendered
}

fn read_response_body_with_limit(
    response: &mut reqwest::blocking::Response,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunk = [0_u8; 8192];

    loop {
        let read = response.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        if body.len().checked_add(read).is_none_or(|next| next > limit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response body exceeds {limit} byte limit"),
            ));
        }

        body.extend_from_slice(&chunk[..read]);
    }

    Ok(body)
}

fn fetch_remote_cache_from_config(root: &Path, config: &Config) {
    if config.remote.urls.is_empty() {
        return;
    }

    let cache_dir = root.join("cache/remote");
    if let Err(err) = fs::create_dir_all(&cache_dir) {
        eprintln!("real-world bench: failed to create remote cache dir: {err}");
        return;
    }

    let timeout = Duration::from_secs(u64::from(config.remote.timeout_secs.get()));
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            eprintln!("real-world bench: failed to build HTTP client: {err}");
            return;
        }
    };

    let mut fetched = 0_usize;
    let mut failed = 0_usize;

    for (idx, url) in config.remote.urls.iter().enumerate() {
        match client.get(url).send() {
            Ok(mut response) if response.status().is_success() => {
                match read_response_body_with_limit(&mut response, BENCH_REMOTE_IPLIST_READ_LIMIT) {
                    Ok(body) => {
                        let normalized =
                            format_cidrs(&parse_lines_non_strict(&String::from_utf8_lossy(&body)));
                        if let Err(err) =
                            fs::write(cache_dir.join(format!("bench-{idx:03}.iplist")), normalized)
                        {
                            failed += 1;
                            eprintln!(
                                "real-world bench: failed to write remote cache for {url}: {err}"
                            );
                        } else {
                            fetched += 1;
                        }
                    }
                    Err(err) => {
                        failed += 1;
                        eprintln!("real-world bench: failed to read remote body for {url}: {err}");
                    }
                }
            }
            Ok(response) => {
                failed += 1;
                eprintln!(
                    "real-world bench: remote fetch failed softly for {url}: status {}",
                    response.status()
                );
            }
            Err(err) => {
                failed += 1;
                eprintln!("real-world bench: remote fetch failed softly for {url}: {err}");
            }
        }
    }

    eprintln!(
        "real-world bench: remote fetch complete fetched={fetched} failed={failed} urls_total={}",
        config.remote.urls.len()
    );
}

fn load_real_world_dataset() -> Option<RealWorldDataset> {
    let root = std::env::var("KIDOBO_BENCH_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".local-scenarios/real"));

    let config_path = find_real_world_config(&root)?;
    let config_text = read_to_string_with_limit(&config_path, BENCH_BLOCKLIST_READ_LIMIT).ok()?;
    let config = Config::from_toml_str(&config_text).ok()?;
    if env_truthy("KIDOBO_BENCH_FETCH_REMOTE") {
        fetch_remote_cache_from_config(&root, &config);
    }

    let blocklist_path = root.join("data/blocklist.txt");
    let blocklist_text =
        read_to_string_with_limit(&blocklist_path, BENCH_BLOCKLIST_READ_LIMIT).ok()?;
    let mut candidates = parse_lines_non_strict(&blocklist_text);
    let mut ipv4_cidrs_by_source = Vec::new();
    let mut local_ipv4 = candidates
        .iter()
        .filter_map(|cidr| match cidr {
            CanonicalCidr::V4(v4) => Some(*v4),
            CanonicalCidr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    local_ipv4.sort_unstable();
    ipv4_cidrs_by_source.push(local_ipv4);

    let remote_cache_dir = root.join("cache/remote");
    if remote_cache_dir.is_dir() {
        let mut files = fs::read_dir(remote_cache_dir)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "iplist"))
            .collect::<Vec<_>>();
        files.sort();
        for file in files {
            if let Ok(text) = read_to_string_with_limit(&file, BENCH_REMOTE_IPLIST_READ_LIMIT) {
                let parsed = parse_lines_non_strict(&text);
                let mut source_ipv4 = parsed
                    .iter()
                    .filter_map(|cidr| match cidr {
                        CanonicalCidr::V4(v4) => Some(*v4),
                        CanonicalCidr::V6(_) => None,
                    })
                    .collect::<Vec<_>>();
                source_ipv4.sort_unstable();
                ipv4_cidrs_by_source.push(source_ipv4);
                candidates.extend(parsed);
            }
        }
    }

    let ipv4_cidrs = candidates
        .iter()
        .filter_map(|cidr| match cidr {
            CanonicalCidr::V4(v4) => Some(*v4),
            CanonicalCidr::V6(_) => None,
        })
        .collect::<Vec<_>>();

    eprintln!(
        "real-world bench dataset: candidates={} safelist={} ipv4_cidrs={}",
        candidates.len(),
        config.safe.ips.len(),
        ipv4_cidrs.len()
    );

    Some(RealWorldDataset {
        candidates,
        safelist: config.safe.ips,
        ipv4_cidrs,
        ipv4_cidrs_by_source,
    })
}

fn benchmark_real_world(c: &mut Criterion) {
    let Some(dataset) = load_real_world_dataset() else {
        eprintln!(
            "Skipping real-world benches: set KIDOBO_BENCH_ROOT (default .local-scenarios/real)"
        );
        return;
    };

    let mut collapse_group = c.benchmark_group("real_world_collapse_ipv4");
    collapse_group.throughput(Throughput::Elements(dataset.ipv4_cidrs.len() as u64));
    let source_sorted_concat = dataset
        .ipv4_cidrs_by_source
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    collapse_group.bench_function("as_loaded", |b| {
        b.iter(|| {
            black_box(collapse_ipv4(black_box(&dataset.ipv4_cidrs)));
        });
    });
    let mut sorted = dataset.ipv4_cidrs.clone();
    sorted.sort_unstable();
    collapse_group.bench_function("pre_sorted", |b| {
        b.iter(|| {
            black_box(collapse_ipv4(black_box(&sorted)));
        });
    });
    let mut shuffled = dataset.ipv4_cidrs.clone();
    deterministic_shuffle(&mut shuffled);
    collapse_group.bench_function("shuffled", |b| {
        b.iter(|| {
            black_box(collapse_ipv4(black_box(&shuffled)));
        });
    });
    collapse_group.bench_function("source_sorted_concat", |b| {
        b.iter(|| {
            black_box(collapse_ipv4(black_box(&source_sorted_concat)));
        });
    });
    collapse_group.finish();

    let mut effective_group = c.benchmark_group("real_world_compute_effective_blocklists");
    effective_group.throughput(Throughput::Elements(
        (dataset.candidates.len() + dataset.safelist.len()) as u64,
    ));
    effective_group.bench_function("ipv4_ipv6_enabled", |b| {
        b.iter(|| {
            black_box(compute_effective_blocklists(
                black_box(&dataset.candidates),
                black_box(&dataset.safelist),
                black_box(true),
            ));
        });
    });
    effective_group.bench_function("ipv4_only", |b| {
        b.iter(|| {
            black_box(compute_effective_blocklists(
                black_box(&dataset.candidates),
                black_box(&dataset.safelist),
                black_box(false),
            ));
        });
    });
    effective_group.finish();

    let scales = [1_usize, 2_usize, 5_usize, 10_usize];

    let mut collapse_scaled_group = c.benchmark_group("real_world_collapse_ipv4_scaled");
    for scale in scales {
        let cidrs = repeat_vec(&dataset.ipv4_cidrs, scale);
        collapse_scaled_group.throughput(Throughput::Elements(cidrs.len() as u64));
        collapse_scaled_group.bench_with_input(
            BenchmarkId::new("as_loaded", scale),
            &cidrs,
            |b, input| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(input)));
                });
            },
        );

        let mut shuffled = cidrs.clone();
        deterministic_shuffle(&mut shuffled);
        collapse_scaled_group.bench_with_input(
            BenchmarkId::new("shuffled", scale),
            &shuffled,
            |b, input| {
                b.iter(|| {
                    black_box(collapse_ipv4(black_box(input)));
                });
            },
        );
    }
    collapse_scaled_group.finish();

    let mut effective_scaled_group =
        c.benchmark_group("real_world_compute_effective_blocklists_scaled");
    for scale in scales {
        let candidates = repeat_vec(&dataset.candidates, scale);
        let safelist = repeat_vec(&dataset.safelist, scale);
        effective_scaled_group.throughput(Throughput::Elements(
            (candidates.len() + safelist.len()) as u64,
        ));
        effective_scaled_group.bench_with_input(
            BenchmarkId::new("ipv4_only", scale),
            &(candidates, safelist),
            |b, input| {
                b.iter(|| {
                    black_box(compute_effective_blocklists(
                        black_box(&input.0),
                        black_box(&input.1),
                        black_box(false),
                    ));
                });
            },
        );
    }
    effective_scaled_group.finish();
}

criterion_group!(
    core_perf,
    benchmark_collapse_ipv4,
    benchmark_real_world,
    benchmark_effective_blocklists,
    benchmark_subtract_safelist,
    benchmark_lookup
);
criterion_main!(core_perf);
