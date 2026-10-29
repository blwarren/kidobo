# Development workflow

Use this guide for implementation, test changes, validation, mutation-result reviews, and release
preparation. [AGENTS.md](../AGENTS.md) contains the always-applicable safety boundaries and routes
other tasks to their relevant guides. Runtime design and ordering belong in
[Architecture](architecture.md); operator behavior belongs in [Operations](operations.md),
[Configuration](configuration.md), and the [compatibility contract](compatibility.md).

## Toolchain and validation

Development uses Rust 1.99.1, pinned in [rust-toolchain.toml](../rust-toolchain.toml) with
Clippy, rustfmt, rust-analyzer, and the `x86_64-unknown-linux-musl` target. The minimum supported
Rust version is 1.97.1 in the Cargo manifests. Keep code compatible with that minimum and verify
it with `RUSTUP_TOOLCHAIN=1.97.1 just test` when changing toolchain compatibility.

[Justfile](../Justfile) is the canonical command interface. Do not duplicate its Cargo commands in
new scripts or documentation. See the [command reference](../scripts/README.md) for prerequisites,
available recipes, and release recovery.

From the checkout root, install the pinned task runner and validation tools, then check the
checkout. These tool versions follow the repository's [release-age policy](dependency-release-age.md).

```bash
cargo install --locked just --version 1.55.1
just _install-cooldown _install-deny _install-audit
just check
just ci
just release-notes-check
```

The tests use injected runners, fake privileged commands, temporary roots, and loopback services.
Use the separate [E2E guide](e2e.md) for disposable-VM setup; ordinary local checks do not require
running the VM matrix.

Select checks according to the change:

| Change | Required validation before handoff |
| --- | --- |
| Rust, tests, or executable scripts without the broader impacts below | `just check` |
| Runtime behavior, dependencies, toolchain, CI, or release policy | `just ci` |
| Documentation only | Check affected links, anchors, and fenced-code languages; no Rust gate unless executable examples, generated artifacts, or build/release behavior are affected. Use the applicable row above for those impacts. |
| Every repository change | `just release-notes-check`, in addition to the applicable checks above. |

`just check` formats, runs the non-E2E workspace test suite, and lints. `just ci` checks
formatting, lints, dependency policy, advisories, and application correctness through `just test-app`;
it satisfies the Rust gate without requiring a separate `just check` run. Application tests cover
the core, application, adapter, and CLI libraries plus the explicitly listed CLI integration targets
in `test-app`. Add new application integration targets to that recipe. CI excludes tests of the
installer/uninstaller, release and performance scripts, architecture/package rules, Git hooks,
and E2E infrastructure. For installer or repository-tooling changes, also run `just test`, which
includes documentation tests and all non-E2E local fixtures. For E2E-system changes, run
`just test --include-e2e` to exercise the complete workspace suite, including the harness units
and local E2E fixtures. This flag does not launch the VM matrix. Plain `just test` excludes the
`kidobo-e2e` package and root `e2e_*` integration targets from compilation and execution.
Regardless of the editing checks above, `just ci` must pass locally before a push or merge.
The pre-commit hook runs `just commit-check`: staged and working-tree whitespace checks,
then `just format-check` and `just test-fast` when staged Rust sources, Cargo manifests/lockfile,
toolchain/Cargo configuration, or the Justfile change. Documentation-only commits avoid Cargo.
The fast tests cover core, application, and CLI library units; pre-push runs `just ci`, adding
adapter and CLI process tests. Installer and repository-tooling tests run through `just test`
or `just check`; local E2E-tool tests require `just test --include-e2e`. Hook checks use the working
tree, so review partial staging before committing. Formatting checks never rewrite files.
The publisher suppresses Git hooks only for its own final commit and push after explicit candidate
validation; ordinary pushes still run `just ci`.

Coverage, strict rustdoc, the isolated release-binary exercise, static compatibility checks,
and required coverage in the [Incus distro lifecycle matrix](e2e.md)
are publication gates; they are not part of `just ci`. Ordinary formatting, lint, coverage,
and rustdoc include the harness. Recipes that depend on `test`, including `just check` and
`just update`, use its non-E2E default. The publisher's explicit `--skip-e2e` path has a separate
validation selection; see [publication commands](../scripts/README.md#publication).
Read the [E2E scope contract](e2e.md#scope-and-non-goals) before changing the runner, fixtures,
provisioning, images, reporting, or release integration.

CI/CD remains local. Dependabot version updates are the sole GitHub-hosted automation exception;
do not add GitHub Actions workflows without explicit approval. Dependency changes must also follow
[release-age enforcement](dependency-release-age.md); a passing CI run does not verify publication age.

Report which required gates actually ran, their outcomes, and any skipped gates. Running individual
checks does not establish that the aggregate recipe ran.

### Lint coverage

Every package uses `[lints] workspace = true` to inherit the shared policy in `Cargo.toml`.
This covers libraries, the binary, integration tests, and benchmarks. The policy forbids unsafe
code, denies dead code and `clippy::all`, and warns on `clippy::pedantic`; `just lint` denies
all warnings. It also denies `allow_attributes_without_reason`, `assertions_on_result_states`,
`cargo_common_metadata`, `wildcard_dependencies`, `collection_is_never_read`, `needless_collect`,
and `needless_pass_by_ref_mut`.

Library roots retain `missing_docs` and conditional production restrictions in
`cfg_attr(not(test), deny(...))`. Tests and benchmarks may use assertions, `expect`, and diagnostic
output. Use function-local lint expectations with a reason (`#[expect(lint, reason = "...")]`)
so obsolete exceptions produce warnings. A cohesive scenario or embedded shell fixture can justify
a length exception; avoid extracting helpers solely to meet a line limit.

## Safety-critical regressions

For changes to interval math, safelist subtraction, collapse, lookup, or safety-critical runtime
logic, identify plausible incorrect implementations that existing tests might accept. This applies
to bug fixes and refactors as well as new behavior. Add the smallest observable regression case for
each relevant gap. Additional cases are unnecessary when existing tests already reject the plausible
regressions; unchanged public behavior alone is not an exemption.

Preserve coverage of these contracts:

| Area | Failure modes to consider |
| --- | --- |
| Collapse, safelist subtraction, and minimal CIDR regeneration | Ignoring later safelist entries, off-by-one carving, subset/supernet assumptions, order dependence, unsorted inputs, and adjacency errors. |
| IPv4 and IPv6 | Cross-family leakage and mutating one family before validating both enabled-family capacities. |
| Ipset replacement | Name/suffix limits, restore and swap constraints, and best-effort temporary-set destruction. |
| Firewall activation and cleanup | Fail-open replacement windows, incorrect chain/rule/jump counts or order, partial failures, repeated cleanup, and incomplete-cleanup exit behavior. |
| Paths and lookup | Relocation semantics, offline source boundaries, matching, and deterministic results. |

Use injected ports/runners, fake binaries, and temporary roots for side effects, following the
[command extension recipe](architecture.md#adding-a-command). Operator commands in the documentation
are not development-host test instructions. Never exercise the live host's firewall or systemd;
live validation requires explicit direction and a disposable environment.

## Mutation results

Mutation execution belongs to the user. Review their reports only after the unmutated baseline
passes reliably. Prioritize `missed` and `timeout`; `unviable` is inconclusive unless it reveals
dead, over-constrained, or confusing code. Review the [mutation exclusion guidance](mutation-triage.md)
and inspect [.cargo/mutants.toml](../.cargo/mutants.toml) when reviewing exclusions.

For each relevant result, identify the changed contract and classify the cause: weak assertions,
missing boundary/error coverage, overly broad mocks, redundant/unreachable code, or equivalent
behavior. Focus on firewall safety, configuration, locks, sources, cache fallback, CIDR computation,
family separation, lookup, cleanup, exit meanings, and deterministic operator output. Boundary,
Boolean, constant, parsing, ordering, `Result`, and removed-side-effect mutations deserve scrutiny
when they affect those contracts.

Improve behavioral coverage for meaningful gaps. Use a higher-level or fixture-based test when a
unit test would be artificial; state an unverified path when only manual validation is practical.
Simplify demonstrated redundant or unreachable code within the authorized scope instead of adding
tests that exist only to increase the mutation score.

Equivalent behavior, generated/mechanical code, unreachable states, performance-only differences,
and diagnostics or cosmetic output outside the stable contract may justify no new test. Record
the evidence and rationale for each ignored or excluded result; do not silently dismiss core gaps
or exclude behavior merely because its current test is difficult.

For timeouts, first check termination, retry, cancellation, and lock-release risks. Add bounded
coverage for real defects. Artificial nontermination may justify a narrowly scoped
`#[mutants::skip]`, `--exclude`, or `--exclude-re` filter with a documented reason. Agents may use
`cargo mutants --list` to preview filter selection; this enumerates mutants without running mutation
tests and does not prove they are caught. User-run mutations must also use fake side effects or a
disposable environment.

## Release notes and publication

Update [release-notes/unreleased.md](../release-notes/unreleased.md) only for user-visible production
impact. Internal testing, instruction, and documentation maintenance alone do not need release notes.
[CHANGELOG.md](../CHANGELOG.md) is generated and must not be hand-edited.

Group release-note entries under appropriate `###` headings: `Added`, `Changed`, `Deprecated`,
`Removed`, `Fixed`, or `Security`. Include only categories with entries, and classify each entry by
its user-visible impact.

After every repository change, run `just release-notes-check`. It normalizes `release-notes/*`,
regenerates `CHANGELOG.md`, then checks those paths for unstaged differences against the Git index.
A failure can reflect pre-existing unstaged edits as well as new generator rewrites. Inspect the
diff, retain intended note edits and generated changes, and rerun after those changes are staged.
Report whether this invocation changed file contents separately from its exit status.

Do not bump versions or create tags unless explicitly requested. When requested, keep `Cargo.toml`,
`Cargo.lock`, README install examples, and tag-named release notes aligned.

Publication is a separate, explicitly requested operation. Authenticate GitHub CLI with
`gh auth login`, then use `just publish-release X.Y.Z` from a clean branch. The publisher prepares
and validates a candidate in a temporary worktree, asks for confirmation, pushes the release commit
and tag atomically, verifies uploaded assets, and publishes the release. Every attempt runs its
selected gates; prior validation does not qualify a new attempt. See
[publication commands](../scripts/README.md#publication) for prerequisites, retained application
gates with `--skip-e2e`, and recovery before or after refs are pushed. The
[E2E guide](e2e.md) owns matrix coverage, image updates, and retained VM evidence.

## Maintaining documentation

Write for operators first, then contributors. Keep installation and a short working example in
the README, operator tasks in Operations, accepted settings in Configuration, and implementation
and validation guidance in the developer guides. Link to the authoritative procedure instead of
repeating it across several documents.

Document current behavior, decisions readers need to make, and recovery steps. Keep task journals,
individual test-run transcripts, scores, and one-time dependency checks in change reviews or run
artifacts. Retain enduring rationale beside the procedure it explains; release notes record
user-visible changes by version. Check examples against the implementation and update links when
moving sections.
