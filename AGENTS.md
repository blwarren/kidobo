# kidobo — AI Agent Contract (Late Pre-1.0 Hardening)

## 1. Stage and Priority

Kidobo is a released, operational pre-1.0 product with a public installer and release workflow. Treat
the current stage as late stabilization, not initial product development. Priority order:

1. Firewall safety and fail-closed correctness
2. Deterministic core logic
3. Compatibility for existing operators
4. Reliable install, upgrade, uninstall, and release
5. Maintainable, reviewable diffs

Prefer regression closure, safety hardening, and documentation over speculative features or broad
redesigns. New commands, configuration surface, or runtime modes require explicit scope.

## 2. Hard Invariants (Non-Negotiable)

* Use the pinned stable toolchain in `rust-toolchain.toml`; keep it synchronized with
  `package.rust-version` and explicit CI/release workflow pins.
* The process remains one-shot. The supported systemd timer may invoke the existing `Type=oneshot`
  sync service; do not add a resident daemon, watcher, or internal scheduler.
* Keep the public command surface and exit meanings stable: `0` for success/help/version, `1` for
  runtime or check failure, `2` for usage errors, and `130` for SIGINT.
* Treat documented CLI behavior, configuration keys/defaults, system paths, machine-readable output,
  generated systemd units, and install/uninstall behavior as compatibility-sensitive surfaces.
* IPv4 and IPv6 logic remain strictly separated.
* Preserve sync ordering: resolve paths/config → acquire the nonblocking lock → ensure set/chain
  existence without activating new wiring → normalize and load all sources → compute family-separated
  effective sets (merge, safelist carve, and minimal CIDR regeneration) → preflight every
  enabled-family capacity → atomically replace each set → activate and normalize firewall wiring →
  clean up disabled-family artifacts → log → unlock.
* Ipset atomicity is per set, not a transaction across both families. Preserve the temporary suffix,
  the 31-character name limit, restore+swap replacement, and best-effort temporary-set destruction.
  Check every enabled-family `maxelem` limit before swapping either family.
* After a successful sync, each managed family has one `kidobo-input` chain, one set-match action rule,
  and exactly one `INPUT` jump at position 1. Preserve fail-closed replacement ordering: establish new
  enforcement before deleting old copies, even if a partial failure can leave duplicates.
* `lookup` remains offline-only; `doctor` remains read-only.
  `ban`/`unban` update source/config state only and never enforce changes before `sync`.

No silent behavioral changes.

## 3. Architecture Boundaries

`kidobo-core` owns pure, deterministic domain computation with no filesystem, network, process, clock, or
terminal I/O:

* canonicalization
* family split
* interval merge
* safelist subtraction
* minimal CIDR regeneration
* lookup
* configuration parsing and validation from in-memory text

`kidobo-adapters` owns bounded filesystem, HTTP, cache, locking, ipset, iptables, and subprocess I/O.

`kidobo-app` owns command requests, typed outcomes, focused ports, provider registries, failure policy, and
ordered workflows. It accepts replaceable I/O boundaries where tests need safe substitutes.

The root `kidobo` package owns argument parsing, dependency composition, prompts, rendering, logging and
interrupt setup, and exit-code mapping. It contains no domain or workflow decisions.

Dependencies point inward: `kidobo-core` imports no outer layer; `kidobo-app` imports neither adapters nor
the root CLI. Keep reusable computation out of adapters and CLI code; keep side effects out of core. See
`docs/architecture.md` for the command and source extension recipes.

## 4. Determinism and Error Model

* Commands that require configuration fail fast on invalid config. Preserve commands intentionally
  designed to work without config, including `lookup` and `flush --cache-only`.
* Missing required binaries and lock contention in mutating workflows are hard failures.
* Individual remote-feed and GitHub metadata failures are soft: warn, continue, and retain the last
  usable cache. Invalid non-empty responses must not replace good cached data.
* Cleanup attempts every scoped step. `flush` returns `1` when required cleanup remains incomplete,
  and uninstall preserves runtime files when live cleanup cannot be confirmed. Ancillary cleanup or
  cache-maintenance failures may remain soft only where the workflow explicitly documents and tests
  that behavior.
* No `panic!` except internal invariants.
* Outputs must remain deterministic unless explicitly documented.

## 5. Validation and Testing

`Justfile` is the canonical interface for local and CI validation. Do not duplicate its Cargo commands
in new scripts or documentation.

After Rust, test, or executable-script changes, run:

```bash
just check
```

When runtime behavior, dependencies, the toolchain, CI, or release policy changes, run the extended
gate instead:

```bash
just ci coverage
```

Documentation-only changes do not require Rust gates unless they affect executable examples, generated
artifacts, or build/release behavior. Every repository change still requires
`just release-notes-check` as described in Section 7.

Never validate by invoking real `sync`, `flush`, `init`, the installer, `ipset`, `iptables`,
`ip6tables`, `sudo`, or `systemctl` against the development host. Use injected runners, fake binaries,
and a temporary `KIDOBO_ROOT`. Live validation requires explicit direction and a disposable environment.

Safety-critical tests must preserve:

* collapse + safelist carving
* IPv4/IPv6 separation
* minimal CIDR regeneration
* atomic set-name, capacity-preflight, restore, and swap constraints
* sync and fail-closed firewall ordering
* idempotent cleanup and incomplete-cleanup exit behavior
* path resolution semantics

## 6. Adversarial Testing Strategy (Required for Core and Safety-Critical Changes)

When modifying interval math, safelist subtraction, collapse logic, lookup behavior, or any safety-critical runtime logic:

1. Assume the implementation is wrong.
2. Propose plausible incorrect implementations that would still pass existing tests.
3. Add the smallest test that would fail under each incorrect implementation.

Specifically consider:

* ignoring later safelist entries
* order-dependent logic
* off-by-one interval carve errors
* subset/supernet assumptions
* unsorted input handling
* adjacency merge errors
* IPv4/IPv6 cross-family leakage
* partial failures that create a fail-open window
* mutating one family before validating the other

Tests must constrain behavior, not just happy paths.

If a change does not increase behavioral surface, no adversarial expansion is required.

### Mutation Testing Result Triage

Agents must not run mutation testing themselves. The user owns all `cargo-mutants` execution and any other
mutation-test runs. Agents may use mutation-test result reports produced by the user, such as `missed`,
`timeout`, or `unviable` reports, to identify risks and guide code or test improvements.

Do not chase cargo-mutants results merely to improve the mutation score. Treat mutation testing as a risk-discovery tool, not a target metric.

cargo-mutants reports mutants as `caught`, `missed`, `unviable`, or `timeout`. Triage `missed` and `timeout` results first because they are actionable. Treat `unviable` mutants as inconclusive unless they reveal dead, over-constrained, or confusing production code. Only interpret results after the unmutated baseline passes reliably; flaky or environment-dependent tests make mutation results unreliable.

Because this project wraps firewall commands, user-run mutation testing must use tests that fake command execution or otherwise run in a disposable environment. Mutation testing must not exercise real firewall changes on a developer machine or CI runner.

For each relevant `missed` mutant, decide whether it indicates:

* A missing or weak assertion.
* An untested boundary condition.
* An untested error path.
* Overly broad mocking.
* Dead, redundant, or unclear production code.
* A mutant that is equivalent or not worth testing.

Add or revise tests when the missed mutation changes behavior that matters to firewall safety, operator-visible CLI behavior, config validation, lock handling, source loading, safelist subtraction, CIDR collapse/regeneration, IPv4/IPv6 separation, lookup results, ipset atomicity, iptables chain/jump correctness, cleanup, or deterministic output.

Prefer improving tests when the mutant involves:

* Boundary changes such as `<` to `<=`, `>` to `>=`, or off-by-one behavior.
* Boolean logic changes.
* Removed method calls with observable effects.
* Changed constants used in firewall, ipset, CIDR, config, or path rules.
* Changed `Result` handling, fallback behavior, or exit-code behavior.
* Altered parsing, canonicalization, normalization, matching, sorting, merging, or deduplication outcomes.
* Removed side effects in adapters where the side effect is part of the public firewall or filesystem contract.

It is acceptable to ignore or suppress missed mutants when there is a clear reason, including:

* The mutant is behaviorally equivalent to the original code.
* The mutation affects generated code, mechanical DTOs, or dependency-injection wiring.
* The mutation affects logging, tracing, diagnostics, or cosmetic text that is not part of the stable CLI contract.
* The mutation affects defensive code for a state that cannot be reached through supported paths.
* The mutation affects performance-only behavior better covered by benchmarks or profiling.
* The mutation is in low-risk presentation or convenience code where additional tests would be brittle or low value.
* The test needed to kill the mutant would over-specify implementation details rather than observable behavior.

When ignoring a missed mutant, leave a brief rationale in the response or code review summary. Do not silently ignore surprising missed mutants in core logic.

If a mutant is missed because the production code is redundant, unreachable, or unclear, prefer simplifying the production code over adding artificial tests.

If a missed mutant affects important behavior that is difficult to test with unit tests, consider a higher-level test, contract test, integration test, fixture-based CLI test, or explicit manual verification note rather than forcing an unnatural unit test.

For `timeout` results, first determine whether the mutant exposes an actual termination, retry, or lock-release risk. If the timeout is an uninteresting mutation that predictably hangs and cannot produce a useful test, suppress it with the narrowest practical `#[mutants::skip]`, `--exclude`, or `--exclude-re` rule and document the reason. Preview persistent filters with `cargo mutants --list`.

## 7. CI and Release Discipline

* Required workflows must pass before merge.
* Release notes only for user-visible production impact.
* `CHANGELOG.md` is generated only. Do not hand-edit it.
* Update `release-notes/unreleased.md` only when the change has user-visible production impact.
* After any repo changes, run `just release-notes-check`.
  This is the canonical changelog workflow: it normalizes `release-notes/*`,
  regenerates `CHANGELOG.md`, and fails if those generated files were rewritten.
* If `release-notes-check` rewrites `CHANGELOG.md` or `release-notes/*`, include those rewrites in the
  diff.
* Do not bump versions or create tags unless explicitly requested. When requested, keep
  `Cargo.toml`, `Cargo.lock`, README install examples, and the tag-named release notes aligned.
* No broad refactors without necessity.
* Prefer narrow diffs.

## 8. Forbidden Changes

Do not:

* introduce daemon behavior
* weaken atomic ipset guarantees
* introduce fail-open firewall replacement ordering
* modify unrelated firewall chains
* change cache format, fallback, or staleness semantics without explicit approval
* run live firewall or systemd validation on the development host

## 9. Agent Handoff

After making changes:

1. Explain what changed and why.
2. List validation commands run.
3. Call out skipped gates.
4. State whether `just release-notes-check` was run and whether it rewrote `CHANGELOG.md` or `release-notes/*`.
5. Provide a commit message.
6. **Do not** run `git commit` unless instructed.
