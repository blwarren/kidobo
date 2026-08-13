# Changelog

## [Unreleased]

- Source builds now require Rust 1.97.1, which includes the upstream fix for an LLVM miscompilation.
- Remote HTTP fetches now reject redirects outside the configured URL's origin,
  preventing providers from redirecting sync requests to unrelated internal services.

## [0.12.1] - 2026-07-19

### Fixed

- Sync no longer deadlocks when a remote-source worker logs a warning while the
  main thread waits for remote fetches to finish.

## [0.12.0] - 2026-07-19

### Fixed

- Timed-out external commands now terminate their descendant process group, so
  inherited output pipes cannot leave a Kidobo operation hanging after its
  timeout.
- The installer now verifies a downloaded binary before atomically replacing
  the installed copy, preserving the previous binary when download,
  extraction, staging, or verification fails.
- Cancelling `just publish-release`, or encountering a validation failure,
  restores the branch from which the release command was started.
- Large offline lookups now group matches per target, stream rendered output,
  and avoid duplicate source buffers, reducing high-match runtime and peak
  memory use without changing human or TSV output.

### Changed

- Removed the `kidobo analyze overlap` command and its now-empty top-level
  `analyze` command group. New default configs no longer include
  `remote.cache_stale_after_secs`; existing configs that contain the setting
  remain accepted for compatibility.

## [0.11.1] - 2026-07-10

### Changed

- `just publish-release` now refreshes the package version in `Cargo.lock`
  before staging and validating a release.
- Remote blocklist loading now accepts IP addresses and CIDRs in the first
  column of CSV feeds, and expected absent temporary ipsets no longer produce
  warnings during atomic replacement.
- The documented curl-pipe installer now runs correctly on older Bash releases
  when Bash reads it from standard input.
- `just publish-release` now runs the local test suite once using the same
  quality gate as the GitHub release workflow, instead of repeating it under
  coverage before GitHub performs its independent post-push verification.

## [0.11.0] - 2026-07-10

### Fixed

- Config validation now rejects malformed `http://`/`https://` remote and
  GitHub meta URLs, unknown configuration keys, and IPv4/IPv6 ipset name
  collisions. IPv4-only configs still permit an unused derived IPv6 set name
  longer than the kernel limit.
- `kidobo doctor` no longer requires or sudo-probes `iptables-save` and
  `iptables-restore`, which are not used by the one-shot runtime path.
- `kidobo init` no longer requires `bgpq4` before any ASN blocklist sources are
  configured, and its generated default config now includes the remote cache
  staleness setting.
- Custom GitHub meta URLs no longer reuse metadata-less raw cache files that
  may have been written for the default GitHub meta endpoint.
- The install script now selects checksum entries by exact archive filename
  instead of using a regex match.
- Sync now validates existing ipset type and family, checks both family limits
  before swapping either set, and activates firewall rules only after source
  loading and atomic set replacement succeed.
- Firewall rule updates now wait briefly for the xtables lock and insert new
  enforcement before removing superseded rules, avoiding fail-open gaps when a
  command fails partway through an update.
- Non-empty remote feeds with no valid CIDRs and malformed GitHub category data
  now retain the last usable cache instead of overwriting it with an empty list.
- `kidobo flush` now reports incomplete cleanup as a failure, and uninstall
  preserves runtime files when direct firewall cleanup cannot be confirmed.
- The read-only doctor cache check now rejects missing traversal permissions and
  reports plausible, but unproven, effective writability as `SKIP`.
- The unchecked integer `from_parts` CIDR constructors are no longer public;
  callers must use the prefix-validating `Ipv4Cidr::new` and `Ipv6Cidr::new` APIs.

### Changed

- Releases can now be prepared, validated, committed, tagged, and atomically
  pushed with `just publish-release X.Y.Z`; an optional leading `v` is accepted,
  local commits ahead of `origin/main` are included, and the command uses a
  temporary worktree with confirmation before publication. It switches to
  `main` automatically and leaves the completed checkout there.
- `kidobo lookup` now defaults to a readable, wrapped results table with
  explicit match statuses and summary counts. TTY output highlights statuses,
  `NO_COLOR` disables styling, and `--format tsv` preserves the previous
  tab-separated output for scripts.
- `kidobo lookup` now reports raw overlaps with configured safelist entries,
  compatible cached GitHub meta safelist data, and cached prefixes for
  configured ASN bans, in addition to the local blocklist and cached remote
  sources. Lookup remains offline-only and retains its local/remote fallback
  when config is missing or invalid, with warnings when config-backed cache
  coverage is unavailable.

## [0.10.1] - 2026-04-15

### Changed

- Updated the `rustls-webpki` dependency to `0.103.12` to address recent certificate name-constraint vulnerabilities in TLS verification. (Advisories: RUSTSEC-2026-0098 and RUSTSEC-2026-0099)

## [0.10.0] - 2026-03-31

### Fixed

- `kidobo sync` now fails on invalid persisted local blocklist entries with the
  file path, line number, and offending content instead of silently dropping
  malformed non-header lines during normalization.
- `kidobo init` now generates default systemd units only when `kidobo` is
  installed at `/usr/local/bin/kidobo` or `/usr/bin/kidobo`, preventing broken
  `ExecStart` entries from arbitrary build paths.
- Remote feed, GitHub meta, and ASN cache writes now use atomic replacement,
  and cache readers now reject hash-mismatched or malformed cached content
  instead of silently reusing partial or corrupted cache state.

### Changed

- `kidobo ban` and `kidobo unban` now support `--file <PATH>` for batch
  IP/CIDR updates using one target per line, with invalid file inputs rejected
  before any local blocklist write occurs.
- `kidobo ban`, `kidobo unban`, and file-driven blocklist target loading now
  reject trailing junk after an IP/CIDR target instead of silently accepting
  only the first token.
- `kidobo analyze overlap` is now strictly read-only again; the
  `--apply-fully-covered-local` option has been removed.
- `kidobo doctor` is now read-only by default and no longer creates cache
  directories or probe files while checking cache path readiness.
- `kidobo lookup` remains offline-only and no longer requires a valid config
  file to inspect the local blocklist and cached remote sources.
- `KIDOBO_ALLOW_REPO_CONFIG_FALLBACK` has been removed. Use `KIDOBO_ROOT` for
  alternate config/data/cache roots.
- Large local blocklist rewrite paths now avoid extra retained-line copies,
  reducing peak memory use and improving rewrite speed for large `ban`/`unban`
  and related cleanup operations.

## [0.9.0] - 2026-02-25

### Changed

- `kidobo sync` now supports `--timer`, which emits per-stage timing logs (`stage_ms` and cumulative `total_ms`) across path/config/lock setup and major sync pipeline phases.

## [0.8.0] - 2026-02-23

### Changed

- `kidobo lookup --file` now prints a `NO_MATCH` line for each valid target IP/CIDR that has no overlap with any loaded local/cached source, and ends with a brief summary line: total unique valid targets, unique matched targets, and matched percentage.
- `kidobo lookup` CLI argument validation now uses an explicit one-of input mode (`<IP_OR_CIDR>` or `--file <PATH>`) so usage/help and missing-argument errors reflect the intended mutually exclusive modes.
- `kidobo doctor` now logs a compact summary line (`overall`, total checks, failed checks, skipped checks) instead of logging the full JSON payload a second time; stdout remains the single source for full JSON report output.
- IPv4 interval merge/collapse sorting now uses a hybrid strategy: `sort_unstable` for smaller interval sets and radix sorting for larger sets, reducing sort overhead on high-cardinality source unions.
- Core performance benchmarks now include a dedicated `merge_intervals_ipv4` Criterion group to isolate `merge_intervals_u32` behavior across deterministic interval shapes (`disjoint_sorted`, `disjoint_shuffled`, `overlap_sorted`) at larger input sizes.
- Core performance benchmarks now also support a real-world dataset mode (via `KIDOBO_BENCH_ROOT`, default `.local-scenarios/real`) that benchmarks `merge_intervals_u32` and `compute_effective_blocklists` against local blocklist + cached remote `.iplist` inputs and parsed safelist config.
- Real-world benchmark mode now supports optional remote cache population from configured feeds (`KIDOBO_BENCH_FETCH_REMOTE=1`) before measurement, so benchmark datasets can mirror configured local+remote source volume.
- Benchmark coverage now includes `disjoint_almost_sorted` and real-world scale-up variants (`1x/2x/5x/10x`) for merge and effective blocklist computations to better characterize sort sensitivity and growth behavior.
- `merge_intervals_ipv4` benchmarks now include a radix-sort prototype path (`*_radix`) to compare radix-vs-`sort_unstable` tradeoffs under deterministic and real-world interval orders.
- Real-world merge benchmarks now include `source_sorted_concat` (and radix equivalent), modeling source-wise sorted lists concatenated in deterministic source order.

## [0.7.0] - 2026-02-23

### Added

- `kidobo ban` / `kidobo unban` now support ASN targets via `--asn` (accepting
  both bare values like `213412` and prefixed values like `AS213412`), with
  persistent config-backed ASN ban state in `[asn].banned`.
- Sync now treats ASN bans as first-class blocklist sources by resolving ASN
  prefixes through `bgpq4`, caching per-ASN prefix data under cache state, and
  refreshing stale ASN cache entries (default every `86400` seconds).

### Fixed

- Config validation now parses `safe.ips` entries as strict IP/CIDR tokens during config load and fails fast on invalid entries, instead of silently dropping invalid safelist values at sync time.

### Changed

- Internal runtime typing is stricter for validated config and adapter boundaries: `ipset.hashsize`/`ipset.maxelem` and remote timeout/stale windows now use validated newtypes, HTTP response status uses typed status codes, and command execution status uses an explicit process-status enum.
- `kidobo doctor` now includes a required binary check for `bgpq4`, and
  `kidobo init` now fails fast when `bgpq4` is missing from `PATH`.

## [0.6.0] - 2026-02-20

### Added

- New offline overlap analysis command: `kidobo analyze overlap`.
- Optional overlap outputs: `--print-fully-covered-local` and
  `--print-reduced-local`.
- New apply option: `kidobo analyze overlap --apply-fully-covered-local` to
  remove local entries fully covered by cached remote sources (then run
  `kidobo sync` to apply to firewall/ipset runtime state).

### Changed

- CLI help text is clearer and more descriptive.
- Logging behavior is more predictable and configurable:
  `KIDOBO_LOG_FORMAT=auto|human|journal` and
  `KIDOBO_LOG_COLOR=auto|always|never`.

## [0.5.3] - 2026-02-19

### Fixed

- `kidobo sync` now writes generated `ipset restore` scripts through buffered I/O, reducing kernel write-call overhead introduced by per-line restore emission while preserving atomic swap behavior.

## [0.5.2] - 2026-02-19

### Changed

- `kidobo sync` now uses a fast local blocklist-change check (`size` + `mtime`) and skips the canonicalize/collapse rewrite pass when the local blocklist file is unchanged since the last sync.

## [0.5.1] - 2026-02-19

### Changed

- `kidobo lookup` now streams matches directly to output while preserving deterministic ordering, instead of accumulating all matches in memory first. This reduces peak RAM use and avoids large global sort/dedup overhead on large target/source combinations.
- `kidobo sync` now uses lightweight `ipset list <set> -terse` probing for set existence checks (with compatibility fallback), avoiding expensive full-set listings in the common path.
- Remote sync fetch worker selection is now CPU-aware (`available_parallelism`) while still capped by `MAX_REMOTE_FETCH_WORKERS`, reducing oversubscription pressure on single-core hosts.
- Ipset restore script generation now skips redundant sort/dedup work when entries are already sorted and unique, reducing CPU and allocation overhead on the sync hot path.
- Remote cache normalization now formats canonical CIDRs without building an intermediate `Vec<String>`, reducing temporary allocations during source processing.

## [0.5.0] - 2026-02-18

### Added

- `scripts/install.sh` now supports `--uninstall` for full teardown: best-effort flush of firewall/ipset state, systemd timer cleanup, removal of kidobo config/data/cache directories, and removal of the installed binary from `KIDOBO_INSTALL_DIR` (default `/usr/local/bin`).

### Changed

- TLS backend selection now uses `reqwest` with `rustls-no-provider` and an explicit `rustls` `ring` provider, avoiding `aws-lc`/OpenSSL-licensed transitive crypto code while preserving offline behavior and command surface.
- Updated `Cargo.lock` to use `bumpalo` `3.20.1` (from `3.20.0`) to clear a yanked transitive dependency warning in supply-chain checks.
- Core interval carving and collapse paths now avoid redundant merge/sort passes and per-fragment temporary vectors, reducing CPU and allocation pressure during `sync`.
- `kidobo sync` now streams effective CIDRs directly into `ipset restore` generation (without building intermediate `Vec<String>` entries), reducing peak memory use for large sets.
- Remote source fetch workers now use lock-free index scheduling and per-worker local buffers before final merge, reducing mutex contention under multi-source sync loads.
- Lookup source entries now share source-label storage across file lines, and lookup matching deduplicates by source/target indices before allocating output strings.
- Remote `.iplist` cache loads now keep only parsed network vectors in memory (instead of retaining full cached text alongside parsed CIDRs).
- Added reproducible local performance tooling: Criterion benchmarks for core hot paths (`cargo bench --bench core_perf` via `scripts/perf/run-benchmarks.sh`), a deterministic lookup RSS/time probe (`scripts/perf/measure-lookup-rss.sh`), and a local regression gate script (`scripts/perf/check-regressions.sh`) that fails when slowdown/RSS/time thresholds are exceeded.

### Fixed

- `scripts/install.sh --init` now recovers from the known `kidobo init` failure mode where `systemctl reset-failed kidobo-sync.service` exits with `Unit ... not loaded`, and continues by enabling `kidobo-sync.timer`.

## [0.4.0] - 2026-02-17

### Added

- `kidobo sync` now rewrites the local blocklist file before each run by collapsing/deduplicating entries, sorting IPv4 before IPv6, trimming whitespace, and preserving any header comments so the on-disk list is the minimal canonical representation of the same IP set.
- Added interactive `kidobo ban` / `kidobo unban` commands to manage the local blocklist file (with `--yes` to auto-remove partial matches) so operators can modify the list without editing files manually.

## [0.3.0] - 2026-02-17

### Added

- Added configurable firewall chain action via `ipset.chain_action` with
  allowed values `DROP` (default) and `REJECT` for kidobo chain rules.

### Fixed

- Path resolution no longer hard-fails when the process current directory is
  unavailable unless repo config fallback is explicitly enabled. This allows
  `kidobo init` and other default-path flows to run deterministically.

## [0.2.1] - 2026-02-17

### Changed

- `kidobo lookup` now labels remote matches with the original source URL from
  cache metadata (instead of hashed cache filenames), improving provenance in
  offline lookup output.
- Documentation and maintenance scripts now explicitly use
  `cargo +nightly udeps --all-targets --all-features` for dependency-usage
  checks to match CI behavior.
- Remote conditional-fetch behavior is now shared through a common adapter
  helper, reducing duplicated cache revalidation logic between remote feed and
  GitHub meta loaders.
- `kidobo sync` remote ingestion now keeps parsed CIDRs from cache fetch results
  and avoids reparsing normalized `.iplist` text in worker threads.
- Lookup matching now pre-indexes source CIDR intervals per family, reducing
  repeated overlap scanning work for multi-target lookups.
- Sync/carve normalization now removes redundant collapse/sort/merge passes in
  the core blocklist pipeline while preserving deterministic output ordering.
- Removed the unused `reqwest` `json` feature from dependency configuration.

### Fixed

- Remote feed metadata cache parse/read failures now degrade gracefully to
  metadata-free operation, preserving stale `.iplist` fallback behavior instead
  of hard-failing the source load.
- `kidobo` now exits with code `130` when `SIGINT` is received during command
  execution (after the current command step returns), not only before dispatch.

## [0.2.0] - 2026-02-16

### Changed

- `kidobo init` now runs `systemctl daemon-reload` and
  `systemctl reset-failed kidobo-sync.service` before
  `systemctl enable --now kidobo-sync.timer` when using default system paths
  (the `KIDOBO_ROOT` sandbox flow still skips `systemctl`).
- Added `kidobo flush --cache-only` to clear remote feed cache without
  touching firewall/ipset artifacts.

## [0.1.3] - 2026-02-16

### Changed

- Release automation now resolves release notes from the tag name
  (`release-notes/<tag>.md`) and supports manual reruns for existing tags via
  `workflow_dispatch`.
- `kidobo init` now runs `systemctl daemon-reload` and
  `systemctl enable --now kidobo-sync.timer` automatically when using default
  system paths (the `KIDOBO_ROOT` sandbox flow still skips `systemctl`).

## [0.1.2] - 2026-02-16

### Changed

- Logs are now emitted in a plain `level=<LEVEL> msg=<text>` format without
  ANSI styling or duplicated timestamps, which is easier to read in systemd
  journal output.
- Added configurable remote HTTP request timeout via `remote.timeout_secs`
  (default `30`, range `[1, 3600]`).
- `kidobo init` now prints a deterministic summary of created and unchanged
  paths on successful completion.

### Fixed

- `kidobo sync` now fails early with a clear message when effective IPv4/IPv6
  entries exceed configured `ipset.maxelem`, instead of relying only on a later
  `ipset restore` command failure.
- Command execution now drains `stdout` and `stderr` concurrently while processes
  run, preventing pipe-buffer deadlocks/timeouts on large command output.

## [0.1.1] - 2026-02-16

### Added

- `kidobo init` now creates all operational bootstrap artifacts in one run:
  lock file (`sync.lock`), `kidobo-sync.service`, and `kidobo-sync.timer`.
- `kidobo init` systemd service generation now uses the detected `kidobo`
  executable path and includes `KIDOBO_ROOT` in the unit when set.

### Changed

- GitHub meta safelist source is now configurable via
  `safe.github_meta_url` (default remains `https://api.github.com/meta`).
- `kidobo sync` now uses `safe.github_meta_url` from config instead of a
  hard-coded endpoint.

### Fixed

- Config validation now rejects invalid `safe.github_meta_url` values that do
  not start with `http://` or `https://`.

## [0.1.0] - 2026-02-16

### Added

- Initial public release of `kidobo` CLI.

