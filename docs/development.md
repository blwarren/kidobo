# Development workflow

Use this guide for implementation, test changes, validation, mutation-result reviews, and release
preparation. [AGENTS.md](../AGENTS.md) contains the always-applicable safety boundaries and routes
other tasks to their relevant guides. Runtime design and ordering belong in
[Architecture](architecture.md); operator behavior belongs in [Operations](operations.md),
[Configuration](configuration.md), and the [compatibility contract](compatibility.md).

## Toolchain and validation

Use the pinned stable toolchain in [rust-toolchain.toml](../rust-toolchain.toml) for development.
Preserve `package.rust-version` as the minimum supported Rust version; the development pin may be
newer. The [README](../README.md#development) records the current versions and MSRV check.

[Justfile](../Justfile) is the canonical command interface. Do not duplicate its Cargo commands in
new scripts or documentation. See the [command reference](../scripts/README.md) for prerequisites,
available recipes, and release recovery.

Select checks according to the change:

| Change | Required validation before handoff |
| --- | --- |
| Rust, tests, or executable scripts without the broader impacts below | `just check` |
| Runtime behavior, dependencies, toolchain, CI, or release policy | `just ci` |
| Documentation only | Check affected links, anchors, and fenced-code languages; no Rust gate unless executable examples, generated artifacts, or build/release behavior are affected. Use the applicable row above for those impacts. |
| Every repository change | `just release-notes-check`, in addition to the applicable checks above. |

`just check` formats, tests, and lints. `just ci` checks formatting, lints, dependency policy,
advisories, and tests; it satisfies the Rust gate without requiring a separate `just check` run.
Regardless of the editing checks above, `just ci` must pass locally before a push or merge.
Coverage, strict rustdoc, the isolated release-binary exercise, and static compatibility checks
are publication gates; they are not part of `just ci`.

CI/CD remains local. Dependabot version updates are the sole GitHub-hosted automation exception;
do not add GitHub Actions workflows without explicit approval. Dependency changes must also follow
[release-age enforcement](dependency-release-age.md); a passing CI run does not verify publication age.

Report which required gates actually ran, their outcomes, and any skipped gates. Running individual
checks does not establish that the aggregate recipe ran.

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
dead, over-constrained, or confusing code. Preserve [historical triage evidence](mutation-triage.md)
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

After every repository change, run `just release-notes-check`. It normalizes `release-notes/*`,
regenerates `CHANGELOG.md`, then checks those paths for unstaged differences against the Git index.
A failure can reflect pre-existing unstaged edits as well as new generator rewrites. Inspect the
diff, retain intended note edits and generated changes, and rerun after those changes are staged.
Report whether this invocation changed file contents separately from its exit status.

Do not bump versions or create tags unless explicitly requested. When requested, keep `Cargo.toml`,
`Cargo.lock`, README install examples, and tag-named release notes aligned.

The publisher prepares a candidate in a temporary worktree, runs local CI and the release-note check,
then runs the publication-only gates listed above. The binary exercises use a temporary runtime root,
loopback feed, fake privileged commands, and Debian/Alpine containers. The publisher packages the
tested static Linux x86_64 binary and uses GitHub CLI to upload, verify, and publish it. See
[commands and recovery](../scripts/README.md) for publication prerequisites and recovery steps.
