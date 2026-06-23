# kidobo — AI Agent Contract (Pre-1.0 Hardening)

## 1. Stage and Priority

Pre-1.0 stabilization. Priority order:

1. Firewall safety and correctness
2. Deterministic core logic
3. Reliable install/release
4. Maintainable, reviewable diffs

## 2. Hard Invariants (Non-Negotiable)

**Never reference this file in commits or repo content.**

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

Do not chase a surviving mutant merely to improve the mutation score. Treat mutation testing as a risk-discovery tool, not a target metric.

For each relevant surviving mutant, decide whether it indicates:

* A missing or weak assertion.
* An untested boundary condition.
* An untested error path.
* Overly broad mocking.
* Dead, redundant, or unclear production code.
* A mutant that is equivalent or not worth testing.

Add or revise tests when the surviving mutation changes behavior that matters to users, operators, persisted data, alerting decisions, parser correctness, time handling, frequency/band logic, callsign/entity/reference matching, deduplication, quiet-hours behavior, stale-data behavior, or repository/migration correctness.

Prefer improving tests when the mutant involves:

* Boundary changes such as `<` to `<=`, `>` to `>=`, or off-by-one behavior.
* Boolean logic changes.
* Removed method calls with observable effects.
* Changed constants used in domain rules.
* Changed exception or error-handling behavior.
* Altered persistence behavior.
* Altered alert matching or notification suppression.
* Altered parsing, normalization, matching, or deduplication outcomes.

It is acceptable to ignore or suppress surviving mutants when there is a clear reason, including:

* The mutant is behaviorally equivalent to the original code.
* The mutation affects generated code, mechanical DTOs, dependency-injection wiring, or framework glue.
* The mutation affects logging, tracing, diagnostics, or cosmetic text that is not part of the contract.
* The mutation affects defensive code for a state that cannot be reached through supported paths.
* The mutation affects performance-only behavior better covered by benchmarks or profiling.
* The mutation is in low-risk presentation or convenience code where additional tests would be brittle or low value.
* The test needed to kill the mutant would over-specify implementation details rather than observable behavior.

When ignoring a survivor, leave a brief rationale in the response or code review summary. Do not silently ignore surprising surviving mutants in core logic.

If a mutant survives because the production code is redundant, unreachable, or unclear, prefer simplifying the production code over adding artificial tests.

If a mutant survives in important behavior that is difficult to test with unit tests, consider a higher-level test, contract test, integration test, fixture-based parser test, or explicit manual verification note rather than forcing an unnatural unit test.


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
* Conventional Commits required.
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
5. Provide a Conventional Commit message.
6. **Do not** run `git commit` unless instructed.
