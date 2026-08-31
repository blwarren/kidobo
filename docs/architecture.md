# Architecture

Kidobo is a resolver-v3 Cargo workspace with one released package and three private implementation
crates. The root `kidobo` package remains the version and release source of truth; every internal crate
is fixed at `0.0.0` with `publish = false`.

## Dependency direction

Dependencies point inward:

```text
kidobo (Clap, prompts, rendering, process setup)
  ├── kidobo-adapters (filesystem, HTTP, subprocesses, firewall, systemd)
  └── kidobo-app (requests, outcomes, ports, use-case policy)
        └── kidobo-core (pure deterministic domain computation)

kidobo-adapters
  ├── kidobo-app
  └── kidobo-core
```

`kidobo-core` performs no filesystem, network, process, clock, or terminal I/O. It uses `url::Url` only
for deterministic configuration validation; HTTP clients and transport remain in `kidobo-adapters`.

`kidobo-app` owns command sequencing and failure policy. Its public-in-workspace interfaces are typed
requests, typed outcomes, focused capability ports, and internal source registries. It never depends on
adapters or Clap.

`kidobo-adapters` implements ports with bounded filesystem and HTTP reads, atomic writes, cache formats,
locks, bgpq4, ipset, iptables, and systemd. Adapter errors are mapped to application port errors at the
boundary.

The root package parses arguments, reads confirmations, renders human/TSV/JSON output, maps exit codes,
and composes production dependencies. `CliIo` supplies injected input, output, error, terminal, and color
capabilities for command-dispatch tests. Logger and SIGINT handler installation remain in the production
wrapper.

## Adding a command

1. Add request, outcome, and narrowly scoped ports to `kidobo-app`.
2. Test orchestration with fake ports and an event ledger, including failure-stop behavior.
3. Implement each side-effecting port in `kidobo-adapters` and test it with temporary paths or scripted
   executors.
4. Add only argument conversion, dependency composition, prompts, rendering, and exit mapping to the root
   package.
5. Add binary acceptance coverage for compatibility-sensitive syntax or output.

Do not add a global runtime supertrait or universal virtual filesystem. A use case should receive only the
capabilities it needs.

## Source registries

Sync and offline lookup use separate registries so lookup cannot acquire an HTTP client or command runner.
Registration order is provider evaluation order, IDs must be unique, and application code applies required
versus best-effort policy. Offline entries are sorted by source label and source line before lookup so output
remains deterministic regardless of filesystem iteration order.

| Provider | Sync role and policy | Offline lookup |
| --- | --- | --- |
| Local blocklist | Candidate, required | Local entries |
| Remote feeds | Candidate, best effort | Compatible cached entries only |
| Config safelist | Safelist, required | Included with valid config |
| GitHub metadata | External safelist, best effort with admission checks | Compatible cache only |
| ASN bans | Candidate, required with stale fallback | Configured ASN caches only |

To add a built-in source, implement the appropriate provider trait, assign a stable unique ID, register it
in the relevant adapter registry builder, and add role, policy, ordering, fallback, and offline-boundary
tests. Registries are internal Rust extension points, not plugin ABIs or user configuration.

## Sync safety sequence

The application sync use case explicitly preserves this order:

1. Resolve paths and valid config, then acquire the nonblocking lock.
2. Ensure sets and chains without activating new wiring.
3. Load every registered source and apply provider failure policy.
4. Admit externally controlled safelists without allowing them to empty a
   nonempty enabled-family baseline, then compute family-separated effective lists.
5. Validate both enabled-family capacities before either swap.
6. Promote every accepted staged cache manifest; any promotion failure aborts.
7. Atomically replace IPv6, then IPv4.
8. Activate and normalize fail-closed firewall wiring.
9. Best-effort clean disabled-family artifacts.

The enforcement adapter retains the 31-character ipset name constraint, temporary restore-and-swap
replacement, per-set atomicity, and fail-closed chain and INPUT jump ordering. To normalize a family's
shared `INPUT` chain without numeric-position deletion, it temporarily creates `kidobo-input-stage`, points
that chain at `kidobo-input`, and activates the staging jump before replacing stable jumps by exact rule
specification. A successful activation leaves exactly one stable jump at position 1 and removes the staging
jump and chain. Cleanup handles both names so an interrupted prior activation cannot leave unmanaged
artifacts. Tests use recording ports and scripted command runners; development validation must never invoke
live firewall or systemd mutations.

## Remote cache generations

Validated remote-feed and GitHub metadata writes use a private generation adapter. A complete generation is
written and synced in a sibling staging directory and atomically published under its content SHA-256 ID.
The application selects it with an atomically replaced and synced `current.json` manifest only after all
source semantics and both enabled-family capacities pass, and before either set replacement. Remote feeds are stored below
`v2/remote/<url-hash>/generations/<sha256>/`; GitHub metadata is stored below
`v2/github-meta/generations/<sha256>/`. Each manifest names a current and optional previous generation.

Readers validate the manifest, generation identifiers, bounded members, configured URL, checksums, and
GitHub category scope before accepting data. They try current, then previous, then the legacy flat-file
layout. New writes use only v2, while legacy files remain readable and unchanged for compatibility. After a
successful promotion, only the current and previous generations are retained; incomplete or unselected
staging directories are never selected and are removed opportunistically by online cache work. Normal cache
flush removes the containing remote-cache directory and therefore both layouts.

Remote feeds are parsed into an incrementally deduplicated set. For configured
`maxelem = M`, one feed accepts at most `max(16384, min(2M, 1000000))` data
lines and `max(4096, min(2M, 1000000))` unique canonical CIDRs. The combined
remote set accepts at most `max(8192, min(4M, 2000000))` CIDRs. URLs are fetched
in deterministic chunks of at most five workers so memory retains one chunk
plus the bounded aggregate. Per-feed rejection uses a compatible selected
cache; aggregate rejection aborts before enforcement.

GitHub metadata is an externally controlled safelist. Fresh and cached batches
share the same 4,096-entry, IPv4 `/8`, IPv6 `/16`, and one-sixteenth-per-family
coverage envelope. The application separately rejects an otherwise valid batch
when it would empty an enabled family that remains nonempty after applying only
the operator's `safe.ips` baseline.

## Validation and release

Use `just check` at each implementation checkpoint and `just ci` for final integration. The local CI recipe
checks formatting, lints, dependency policy, audits, and tests. `just publish-release X.Y.Z` prepares the
candidate in a temporary worktree, runs that gate, repeats the release-note check, then performs the
release-only coverage, rustdoc, isolated binary-exercise, and static compatibility gates. The exercises use a temporary runtime
root, loopback feed, fake privileged commands, and Debian 11/Alpine 3.22 containers. The publisher packages the tested static Linux x86_64 binary
and uses GitHub CLI to upload, verify, and publish the release. Run `just release-notes-check` after every
repository change.
