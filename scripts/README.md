# Development Commands

`Justfile` is the canonical entrypoint for local validation and publication. Follow the
[development workflow](../docs/development.md) for validation requirements, test strategy, and
release-note handling.

Install `just` and the pinned CI tools before running local CI, and authenticate
GitHub CLI before publishing. The publisher installs the coverage tool when it
is needed:

```bash
cargo install --locked just --version 1.55.1
just _install-cooldown _install-deny _install-audit
gh auth login
```

## Structure

- `Justfile`: local validation, release-note, udeps, publication, and mutation-test recipes.
- `cooldown.toml`: fail-closed seven-day minimum publish age for dependency updates.
- `scripts/install.sh`: public install/uninstall flow used by operators.
- `scripts/publish-release.sh`: guarded, transactional release preparation and publication.
- `scripts/package-release.sh`: shared static archive packaging for candidates and publication.
- `scripts/check-release-compat.sh`: static ELF and Debian/Alpine release compatibility gate.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

Performance comparisons require Python 3 (standard library only) and current results for
every saved baseline case. They respect `CARGO_TARGET_DIR`, remove previous `new` estimates
before running Criterion, and fail on missing comparisons or unparsable estimates.
Thresholds compare mean point estimates;
they do not establish statistical significance. Keep datasets and machine load comparable.
The duplicate scaled real-world cases at scale 1 were removed; fixed real-world cases retain
their names. Regenerate baselines in a fresh target directory when migrating old estimates
that include those retired scaled cases.

- `just commit-check` (nonmutating pre-commit whitespace and staged-change-selected fast Rust checks)
- `just test-fast` (core, application, and CLI unit tests)
- `just test-app` (core, application, adapter, and CLI correctness tests; excludes installation and repository tooling)
- `just test` (complete workspace tests, including documentation, installer, and local infrastructure tests)
- `just check` (format, complete workspace tests, and lint)
- `just ci` (local formatting, lint, dependency-policy, audit, and application correctness test gate)
- `just coverage` (release-only 90% minimum for stable region, function, and line metrics)
- `just exercise-release` (release-only build and isolated binary exercise)
- `just release-compat` (release-only static ELF, Debian 11, and Alpine 3.22 gate)
- `just e2e-setup` (configure suite-owned Incus infrastructure; see [distro testing](../docs/e2e.md))
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
- `just publish-release X.Y.Z --skip-e2e` (skip only the matrix and its Incus/agent-ISO prerequisites; other validation and upload verification remain enabled)
- `just mutants`
- `just mutants --shard 1/4`

Use `just update` rather than raw `cargo update`; stable Cargo does not enforce
the repository's publish-age policy by itself. Dependabot's cooldown does not
apply to security-update PRs, but those PRs must still meet the repository's
seven-day rule before adoption unless a narrowly scoped exception has a
documented reason or an explicit user override. Security urgency alone does
not grant an automatic exception. See the [dependency release-age
guide](../docs/dependency-release-age.md) for verification and exception handling.

Publication requires a Linux x86_64 host. Release builds require `musl-gcc` and the pinned
`x86_64-unknown-linux-musl` Rust target. The compatibility gate additionally
requires `readelf` and Docker access; it runs only offline Kidobo commands in
the containers and never invokes firewall or systemd operations.
Publication requires host `tar`. By default, it also requires configured Incus VM access, a
`genisoimage` or `mkisofs` utility for agent configuration disks, and passing required distro
lifecycle coverage against the exact packaged archive before pushing refs or uploading assets.
The default required targets are Debian 12 and 13 and Ubuntu 24.04 and 26.04. Publication and
`just e2e-artifact` select only those required targets. Use a separate `just e2e` run for all seven
configured targets, including advisory Fedora 44 and AlmaLinux 9 and 10 with enforcing SELinux.
Advisory prerequisite and application failures do not fail that broader run; reports separately
identify required-gate success and all-selected-target success. Full seven-platform qualification
requires every target to pass. Cleanup, shared infrastructure, and evidence archive failures still
fail the run. At most two VMs run by default, each with 2 vCPUs and 4 GiB RAM, with a memory
preflight and 1 GiB host headroom. Each worker completes fresh provisioning, environment validation,
application checks, diagnostics, and cleanup for one target before taking another. Individual target
failures do not suppress other targets. Ownership-checked startup recovery removes abandoned suite
VMs and preserves retained/foreign guests. No prepared-image or prior-result reuse remains.
Read the [E2E scope contract](../docs/e2e.md#scope-and-non-goals) before changing this workflow.

An explicit `--skip-e2e` argument skips only that matrix and its Incus/agent-ISO prerequisites;
CI, release-note validation, coverage, strict rustdoc, the release-binary exercise,
static compatibility, packaging, and upload verification still run. The publisher labels the
skip before validation and repeats it before the final confirmation. This override does not reuse
or imply evidence from an earlier matrix run. E2E command
transcript and results remain under the original checkout's `target/e2e/<run-id>/`,
including when the publisher removes its temporary worktree. Start with `summary.txt` and
the paths and local line references into `targets/<distro>/transcript.log`. Each target owns
its full transcript and structured results; the terminal and root transcript show progress and
outcomes. Frozen inputs and available supplemental diagnostics are retained in `evidence.tar.gz`.
Supplemental diagnostic failures are warnings; required assertions, authoritative reporting,
artifact integrity, evidence archival, and cleanup remain mandatory. See
[live progress and retained evidence](../docs/e2e.md#diagnose-and-clean-up).
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

## GitHub Automation

Kidobo does not use checked-in GitHub Actions workflows. Run `just ci` before
ordinary pushes and `just publish-release X.Y.Z` for releases. Dependabot update
PRs remain enabled as the sole GitHub-hosted automation exception.

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
