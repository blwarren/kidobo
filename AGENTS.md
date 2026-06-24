# kidobo — AI Agent Contract (Pre-1.0 Hardening)

## 1. Stage and Priority

Pre-1.0 stabilization. Priority order:

1. Firewall safety and correctness
2. Deterministic core logic
3. Reliable install/release
4. Maintainable, reviewable diffs

## 2. Hard Invariants (Non-Negotiable)

* Rust stable toolchain.
* One-shot CLI only (no daemon/service behavior).
* Public commands and exit codes remain stable (`0,1,2,130`).
* IPv4 and IPv6 logic remain strictly separated.
* Sync ordering semantics remain intact (config → lock → ensure artifacts → load sources → safelist subtract → collapse/dedupe → atomic restore+swap → cleanup → log → unlock).
* Ipset atomicity must never be weakened (temp set suffix, ≤31 char names, restore+swap, no corruption).
* Firewall contract remains: single `kidobo-input` chain, exactly one INPUT jump at position 1, deterministic cleanup.
* Lookup is offline-only.

No silent behavioral changes.

## 3. Architecture Boundary

Core = pure, deterministic compute (no I/O):

* canonicalization
* family split
* interval merge
* safelist subtraction
* minimal CIDR regeneration
* lookup overlap

Adapters = all I/O (filesystem, HTTP, locking, ipset, iptables, sudo wrapper).

Do not mix compute and side effects.

## 4. Determinism and Error Model

* Fail fast on invalid config or missing binaries.
* Lock contention fails.
* Per-remote failures are soft (warn + continue).
* Cleanup is best effort.
* No `panic!` except internal invariants.
* Outputs must remain deterministic unless explicitly documented.

## 5. Testing Requirements

Minimum gates for any change:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Extended gates when runtime logic, deps, or CI policy change:

```bash
cargo deny check advisories bans licenses sources
cargo audit
cargo llvm-cov --all-features --fail-under-lines 85
```

Core logic tests must cover:

* collapse + safelist carving
* IPv4/IPv6 separation
* minimal CIDR regeneration
* atomic set-name constraints
* sync ordering + idempotent flush
* path resolution semantics

## 6. Adversarial Testing Strategy (Required for Core Logic Changes)

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
* After any repo changes, run `./scripts/dev.sh release-notes-check`.
  This is the canonical changelog workflow: it normalizes `release-notes/*`,
  regenerates `CHANGELOG.md`, and fails if those generated files were rewritten.
* If `release-notes-check` rewrites `CHANGELOG.md` or `release-notes/*`, include those rewrites in the diff.
* Version bumps use provided script.
* No broad refactors without necessity.
* Prefer narrow diffs.

### 8. Forbidden Changes

Do not:

* introduce daemon behavior
* weaken atomic ipset guarantees
* modify unrelated firewall chains
* change cache semantics without explicit approval

### 9. Agent Handoff

After coding:

1. Explain what changed and why.
2. List validation commands run.
3. Call out skipped gates.
4. State whether `./scripts/dev.sh release-notes-check` was run and whether it rewrote `CHANGELOG.md` or `release-notes/*`.
5. Provide a commit message.
6. **Do not** run `git commit` unless instructed.
