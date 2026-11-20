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

Authenticate GitHub CLI with `gh auth login` and ensure local `main` contains every change
intended for the release. Run `just publish-release X.Y.Z` from a clean checkout. The publisher
switches to local `main` and requires it to include the current `origin/main` before preparing
the candidate. It installs the pinned deny, audit, and coverage tools before validation.
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
not reuse prior gates or E2E results. A failure or cancellation before the push is attempted removes
newly created release artifacts but preserves E2E logs and frozen evidence. Retry with the normal
publication command after addressing the failure.

After a failed push response, the publisher reads the remote main, annotated tag, and peeled tag.
An exact match allows publication to continue. If it cannot confirm the refs, the publisher stops
and retains the tag and artifacts. Verify the reported object IDs on the remote before retrying.

A pre-existing `target/release-artifacts/<tag>/` directory is not deleted or overwritten. If it
belongs to an older pre-push attempt, preserve it by moving it aside before starting again. If
refs were already pushed, use the recovery workflow below instead of retrying publication.

## Release Recovery

The publisher retains the archive, checksum, and release notes under
`target/release-artifacts/<tag>/` whenever Git refs have been pushed but the GitHub release was
not confirmed published. Use the repository and tag printed by the publisher. From the checkout
root, set `RELEASE_TAG` and run these blocks in the same Bash session.

```bash
release_tag="${RELEASE_TAG:?set RELEASE_TAG to the pushed tag}"
release_repo="${RELEASE_REPO:-blwarren/kidobo}"
release_artifacts="target/release-artifacts/${release_tag}"
release_root="kidobo-${release_tag}-linux-x86_64"
release_archive="${release_root}.tar.gz"
create_flags=()
publish_flags=()
if [[ "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    publish_flags+=(--latest)
else
    create_flags+=(--prerelease)
fi
gh release view "${release_tag}" --repo "${release_repo}" --json url,isDraft
```

If the release is already published, recovery is complete. If GitHub confirms that the release
is absent, create the draft. Resolve authentication or network errors before proceeding.

```bash
gh release create "${release_tag}" \
    "${release_artifacts}/${release_archive}" "${release_artifacts}/SHA256SUMS" \
    --repo "${release_repo}" --draft --verify-tag --title "${release_tag}" \
    --notes-file "${release_artifacts}/release-notes.md" "${create_flags[@]}"
```

If a draft already exists, replace its assets.

```bash
if [[ "$(gh release view "${release_tag}" --repo "${release_repo}" --json isDraft --jq .isDraft)" == true ]]; then
    gh release upload "${release_tag}" \
        "${release_artifacts}/${release_archive}" "${release_artifacts}/SHA256SUMS" \
        --repo "${release_repo}" --clobber
fi
```

After a successful create or upload, run the following block when ready to publish. It downloads
the draft assets into a fresh directory under the retained artifacts and stops on any failed check.

```bash
(
    set -euo pipefail
    [[ "$(gh release view "${release_tag}" --repo "${release_repo}" --json isDraft --jq .isDraft)" == true ]]
    release_downloads="$(mktemp -d "${release_artifacts}/downloaded-XXXXXXXX")"
    gh release download "${release_tag}" --repo "${release_repo}" --dir "${release_downloads}" \
        --pattern "${release_archive}" --pattern SHA256SUMS
    cmp "${release_artifacts}/SHA256SUMS" "${release_downloads}/SHA256SUMS"
    cd "${release_downloads}"
    sha256sum --check SHA256SUMS
    printf '%s\n' "${release_root}/" "${release_root}/LICENSE" \
        "${release_root}/README.md" "${release_root}/kidobo" | LC_ALL=C sort > expected-listing
    tar -tzf "${release_archive}" | LC_ALL=C sort > actual-listing
    diff -u expected-listing actual-listing
    tar -xzf "${release_archive}"
    actual_version="$("./${release_root}/kidobo" --version)"
    if [[ "${actual_version}" != "kidobo ${release_tag#v}" ]]; then
        echo "Unexpected binary version: ${actual_version}" >&2
        exit 1
    fi
    gh release edit "${release_tag}" --repo "${release_repo}" --draft=false "${publish_flags[@]}"
)
```
