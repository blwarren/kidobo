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

`kidobo-core` performs no filesystem, network, process, clock, or terminal I/O. Its disabled-feature
`reqwest` dependency is used only for the existing URL parser type; HTTP clients and transport remain in
`kidobo-adapters`.

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
| GitHub metadata | Safelist, best effort | Compatible cache only |
| ASN bans | Candidate, required with stale fallback | Configured ASN caches only |

To add a built-in source, implement the appropriate provider trait, assign a stable unique ID, register it
in the relevant adapter registry builder, and add role, policy, ordering, fallback, and offline-boundary
tests. Registries are internal Rust extension points, not plugin ABIs or user configuration.

## Sync safety sequence

The application sync use case explicitly preserves this order:

1. Resolve paths and valid config, then acquire the nonblocking lock.
2. Ensure sets and chains without activating new wiring.
3. Load every registered source and apply provider failure policy.
4. Compute family-separated effective lists.
5. Validate both enabled-family capacities before either swap.
6. Atomically replace IPv6, then IPv4.
7. Activate and normalize fail-closed firewall wiring.
8. Best-effort clean disabled-family artifacts.

The enforcement adapter retains the 31-character ipset name constraint, temporary restore-and-swap
replacement, per-set atomicity, and fail-closed chain and INPUT jump ordering. Tests use recording ports and
scripted command runners; development validation must never invoke live firewall or systemd mutations.

## Validation and release

Use `just check` at each implementation checkpoint and `just ci coverage` for final integration. The recipes
operate across the workspace, while `just build-release` continues to produce the released binary at
`target/release/kidobo`. Run `just release-notes-check` after every repository change.
