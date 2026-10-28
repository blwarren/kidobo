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

`just check` formats, runs the complete workspace test suite, and lints. `just ci` checks
formatting, lints, dependency policy, advisories, and application correctness through `just test-app`;
it satisfies the Rust gate without requiring a separate `just check` run. Application tests cover
the core, application, adapter, and CLI libraries plus the explicitly listed CLI integration targets
in `test-app`. Add new application integration targets to that recipe. CI excludes tests of the
installer/uninstaller, release and performance scripts, architecture/package rules, Git hooks,
and E2E infrastructure. For changes affecting those areas, also run `just test` to exercise the
complete workspace suite, including documentation tests and local infrastructure fixtures.
Regardless of the editing checks above, `just ci` must pass locally before a push or merge.
The pre-commit hook runs `just commit-check`: staged and working-tree whitespace checks,
then `just format-check` and `just test-fast` when staged Rust sources, Cargo manifests/lockfile,
toolchain/Cargo configuration, or the Justfile change. Documentation-only commits avoid Cargo.
The fast tests cover core, application, and CLI library units; pre-push runs `just ci`, adding
adapter and CLI process tests. Installer, repository tooling, and local E2E-tool tests run through
`just test` or `just check`. Hook checks use the working tree, so review partial staging before
committing. Formatting checks never rewrite files.
The publisher suppresses Git hooks only for its own final commit and push after explicit candidate
validation or verified resume; ordinary pushes still run `just ci`.
Coverage, strict rustdoc, the isolated release-binary exercise, static compatibility checks,
and required coverage in the [Incus distro lifecycle matrix](e2e.md)
are publication gates; they are not part of `just ci`. Fedora and AlmaLinux coverage is advisory
and runs separately through `just e2e`, outside publication, with enforcing SELinux on those
targets. Full seven-platform qualification requires every selected target to pass; reports expose
that outcome separately from the four-target release gate. Prepared-image reuse and bounded
two-VM concurrency reduce repeated work without omitting application checks. The matrix can be omitted
with the explicit publisher option `--skip-e2e`.

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

The publisher prepares a candidate in a temporary worktree, runs local CI and the release-note check,
then runs the publication-only gates listed above. The binary exercises use a temporary runtime root,
loopback feed, fake privileged commands, and Debian/Alpine containers. The publisher packages the
tested static Linux x86_64 binary and, by default, selects the four required Debian and Ubuntu
Incus VM targets against that archive. Separate `just e2e` runs also cover advisory Fedora and AlmaLinux.
Guest prerequisite checks run before application lifecycles so required environment failures
stop the batch early. The publisher then uses GitHub CLI to upload, verify, and publish the archive.
`just publish-release X.Y.Z --skip-e2e` skips only the matrix and its Incus/agent-ISO
prerequisites, keeping all other gates. See the [command reference](../scripts/README.md)
for skip reporting. A failed matrix retains the exact packaged candidate and its validation
identity for `just publish-release X.Y.Z --resume-e2e RUN_ID`. Resume verifies the unchanged
source and candidate before reusing completed local gates and compatible successful distro
results within the preparation freshness limit; it does not rebuild or repackage the candidate.
Add `--refresh-e2e-images` to force new prepared images and rerun required E2E coverage while
retaining compatible local gates and the archive. This option cannot combine with `--skip-e2e`.
See [candidate resume](e2e.md#resume-a-candidate)
for eligibility and historical-run limits. The VM suite operates real guest
firewalls and systemd only inside disposable VMs. Read [setup and diagnosis](e2e.md) for VM
requirements and retained run evidence, and [commands and recovery](../scripts/README.md)
for publication prerequisites and recovery steps.
