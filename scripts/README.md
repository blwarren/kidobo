# Development Commands

`Justfile` is the canonical entrypoint for local validation and publication. Follow the
[development workflow](../docs/development.md) for validation requirements, test strategy, and
release-note handling.

Start with [developer setup](../docs/development.md#toolchain-and-validation) for the toolchain
and pinned validation tools. Use `just --list` to list recipes.

## Structure

- `Justfile`: local validation, release-note, udeps, publication, and mutation-test recipes.
- `cooldown.toml`: fail-closed seven-day minimum publish age for dependency updates.
- `scripts/install.sh`: public install/uninstall flow used by operators.
- `scripts/test.sh`: non-E2E test selection, with `--include-e2e` for the full workspace suite.
- `scripts/publish-release.sh`: guarded, transactional release preparation and publication.
- `scripts/release-validation.sh`: internal application-only CI, coverage, and rustdoc selection
  for the publisher's `--skip-e2e` path.
- `scripts/package-release.sh`: shared static archive packaging for candidates and publication.
- `scripts/check-release-compat.sh`: static ELF and Debian/Alpine release compatibility gate.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

- `just commit-check` (nonmutating pre-commit whitespace and staged-change-selected fast Rust checks)
- `just test-fast` (core, application, and CLI unit tests)
- `just test-app` (core, application, adapter, and CLI correctness tests; excludes installation and repository tooling)
- `just test` (non-E2E workspace tests, including documentation, installer, and repository tooling tests)
- `just test --include-e2e` (complete workspace tests, including E2E-system units and local fixtures; no VM matrix)
- `just check` (format, non-E2E workspace tests, and lint)
- `just ci` (local formatting, lint, dependency-policy, audit, and application correctness test gate)
- `just coverage` (release-only 90% minimum for stable region, function, and line metrics)
- `just exercise-release` (release-only build and isolated binary exercise)
- `just release-compat` (release-only static ELF, Debian 11, and Alpine 3.22 gate)
- `just e2e-setup` (configure suite-owned Incus infrastructure; see [distro testing](../docs/e2e.md))
- `just e2e-images-check` (report vendor-image updates and new stable distro releases; no image imports or VMs)
- `just e2e-images-refresh [DISTRO]` (verify/import one or all configured vendor sources and update pins for review; no VMs)
- `just e2e` (start the candidate build and complete distro matrix in detached tmux session
  `kidobo-e2e`; attach with `tmux attach -t kidobo-e2e` to watch progress; the session closes
  automatically and saves output and exit status under `target/e2e/launcher-*/`)
- `just e2e --required-only` (build and test only required targets in the detached session)
- `just e2e --archive ARCHIVE --tag TAG` (run fresh VMs against an existing archive without rebuilding it)
- `just e2e-artifact ARCHIVE TAG` (select every required target against an existing archive)
- `just e2e-published [tag]` (test a published release; default latest)
- `just e2e-clean RUN_ID` (clean recorded VMs for one run)
- `just rustdoc` (workspace documentation with warnings denied)
- `just update` (install the pinned cooldown tool, update dependencies at least seven days old, and test)
- `just udeps` (manual nightly-toolchain dependency-usage audit)
- `just release-notes-check` (required after repository changes and during release validation)
- `just publish-release X.Y.Z` (complete local preparation, validation, required Incus coverage, upload, verification, and publication)
- `just publish-release X.Y.Z --skip-e2e` (skip all E2E-specific validation and execution; application checks, shared dependency checks, and publication safeguards remain enabled)
- `just mutants`
- `just mutants --shard 1/4`

Use `just update` rather than raw `cargo update`; stable Cargo does not enforce
the repository's publish-age policy by itself. Dependabot's cooldown does not
apply to security-update PRs, but those PRs must still meet the repository's
seven-day rule before adoption unless a narrowly scoped exception has a
documented reason or an explicit user override. Security urgency alone does
not grant an automatic exception. See the [dependency release-age
guide](../docs/dependency-release-age.md) for verification and exception handling.

## Performance checks

Run these scripts from the checkout root. Save a Criterion baseline before changing the code,
then compare the changed checkout against it:

```bash
scripts/perf/run-benchmarks.sh main
# After making the change:
scripts/perf/check-regressions.sh --baseline main --max-slowdown-pct 8
```

The regression checker also runs the lookup RSS/time probe. To run that probe independently,
or apply explicit limits during a comparison:

```bash
scripts/perf/measure-lookup-rss.sh
scripts/perf/check-regressions.sh --baseline main --max-rss-kib 20000 --max-elapsed-s 0.10
```

Choose limits for the workload and host; the numbers above are examples. The lookup probe
builds the release binary unless `KIDOBO_PERF_BINARY` selects an existing executable. It uses
a temporary runtime root, performs offline human/TSV lookup, and reports elapsed seconds and
maximum RSS in KiB for each format. `KIDOBO_PERF_BLOCKS` and `KIDOBO_PERF_TARGETS` select dataset
sizes; optional `KIDOBO_PERF_CPU_CORE` pins the probe to a CPU, and `KIDOBO_PERF_MEM_LIMIT_KIB`
sets its virtual-memory limit. The probe requires `/usr/bin/time`; CPU pinning also needs `taskset`.

Performance comparisons require Python 3 (standard library only). The scripts respect
`CARGO_TARGET_DIR`; the regression checker removes previous `new` estimates and requires fresh,
parseable results for every saved baseline case. Regenerate baselines in a fresh target directory
when benchmark case names change. Thresholds compare mean point estimates and do not establish
statistical significance. Keep datasets and machine load comparable. Use
`scripts/perf/check-regressions.sh --help` for available thresholds and `--skip-rss-probe`.

## Publication

Authenticate GitHub CLI with `gh auth login`, then run `just publish-release X.Y.Z` from a clean
branch. The publisher installs the pinned deny, audit, and coverage tools before validation.
Publication requires a Linux x86_64 host. Release builds require `musl-gcc` and the pinned
`x86_64-unknown-linux-musl` Rust target. The compatibility gate additionally
requires `readelf` and Docker access; it runs only offline Kidobo commands in
the containers and never invokes firewall or systemd operations.
Publication requires host `tar`. By default, it also requires configured Incus VM access and
`genisoimage` or `mkisofs` for agent configuration disks. Required distro lifecycle coverage
must pass against the exact packaged archive before refs are pushed or assets uploaded. See
[host preparation](../docs/e2e.md#host-preparation) for all VM prerequisites and
[coverage and outcomes](../docs/e2e.md#coverage-and-outcomes) for required versus advisory targets.

`just publish-release X.Y.Z --skip-e2e` excludes the E2E validation and tools defined in the
[E2E scope contract](../docs/e2e.md#scope-and-non-goals). Application CI, non-E2E coverage with
the same 90% region/function/line thresholds, and strict application rustdoc still run through
private recipes backed by `scripts/release-validation.sh`.
Shared dependency audits and license/policy checks remain enabled; reading shared Cargo manifests
and lockfile metadata is allowed. Release-note validation, static builds, the release-binary
exercise, compatibility, packaging, confirmation, source/artifact mutation detection, upload
verification, and recovery remain unchanged.

The publisher reports `E2E validation skipped` before validation and at final confirmation,
covering both infrastructure checks and VM execution. Default publication and standalone
`just ci`, `just coverage`, and `just rustdoc` retain their existing scope. Standalone `just test`
requires `--include-e2e` to include E2E-system tests.
This override does not reuse or imply evidence from an earlier matrix run.

The private `_release-ci-without-e2e`, `_release-coverage-without-e2e`, and
`_release-rustdoc-without-e2e` recipes share a selection covering the four application packages
and root integration targets other than `e2e_*`. New packages and targets must be accounted for
by that selection and its inventory regressions; maintain the exclusions in the
[E2E scope contract](../docs/e2e.md#scope-and-non-goals).

Packaging reads the validated candidate binary from `CARGO_TARGET_DIR` when
set, or `target` otherwise. Relative target directories resolve inside the
candidate worktree; recovery artifacts retain the location below.

Every publication attempt reruns its validation gates and builds/packages the candidate. The
publisher checks the validated source tree and artifact hashes again before publishing; it does
not reuse prior gates or E2E results. A failure or cancellation before refs are pushed removes
newly created release artifacts but preserves E2E logs and frozen evidence. Retry with the normal
publication command after addressing the failure.

A pre-existing `target/release-artifacts/<tag>/` directory is not deleted or overwritten. If it
belongs to an older pre-push attempt, preserve it by moving it aside before starting again. If
refs were already pushed, use the recovery workflow below instead of retrying publication.

## Release Recovery

The publisher retains the archive, checksum, and release notes under
`target/release-artifacts/<tag>/` whenever Git refs have been pushed but the GitHub release was
not confirmed published. In that case it prints commands specialized for that release. The
equivalent manual recovery flow after refs have been pushed is:

```bash
release_tag="${RELEASE_TAG:?set RELEASE_TAG to vX.Y.Z}"
release_artifacts="target/release-artifacts/${release_tag}"
release_archive="kidobo-${release_tag}-linux-x86_64.tar.gz"

gh release view "${release_tag}" --repo blwarren/kidobo

# Use this only when no draft exists.
gh release create "${release_tag}" \
    "${release_artifacts}/${release_archive}" \
    "${release_artifacts}/SHA256SUMS" \
    --repo blwarren/kidobo \
    --draft \
    --verify-tag \
    --title "${release_tag}" \
    --notes-file "${release_artifacts}/release-notes.md"

# Use this instead when the draft already exists.
gh release upload "${release_tag}" \
    "${release_artifacts}/${release_archive}" \
    "${release_artifacts}/SHA256SUMS" \
    --repo blwarren/kidobo \
    --clobber

release_downloads="${release_artifacts}/downloaded"
mkdir -p "${release_downloads}"
gh release download "${release_tag}" \
    --repo blwarren/kidobo \
    --dir "${release_downloads}" \
    --clobber \
    --pattern "${release_archive}" \
    --pattern SHA256SUMS
cmp "${release_artifacts}/SHA256SUMS" "${release_downloads}/SHA256SUMS"
(cd "${release_downloads}" && sha256sum --check SHA256SUMS)
tar -tzf "${release_downloads}/${release_archive}"
release_extract="${release_downloads}/extracted"
mkdir -p "${release_extract}"
tar -C "${release_extract}" -xzf "${release_downloads}/${release_archive}"
"${release_extract}/kidobo-${release_tag}-linux-x86_64/kidobo" --version
gh release edit "${release_tag}" \
    --repo blwarren/kidobo \
    --draft=false \
    --latest
```

Before the final edit, confirm that the archive listing contains only the binary,
README, and license under the expected top-level directory, and that the version
output matches the tag. For a suffixed prerelease, add `--prerelease` when
creating the draft and omit `--latest` when publishing it.
