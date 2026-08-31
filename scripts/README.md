# Development Commands

`Justfile` is the canonical entrypoint for local validation and publication.
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
- `scripts/check-release-compat.sh`: static ELF and Debian/Alpine release compatibility gate.
- `scripts/changelog/*`: release-notes normalization and changelog generation.
- `scripts/perf/*`: benchmark and lookup RSS regression tooling.
- `.cargo/mutants.toml`: cargo-mutants mutation-testing configuration.

## Common Commands

- `just check`
- `just ci` (local formatting, lint, dependency-policy, audit, and test gate)
- `just coverage` (release-only 90% minimum for stable region, function, and line metrics)
- `just exercise-release` (release-only build and isolated binary exercise)
- `just release-compat` (release-only static ELF, Debian 11, and Alpine 3.22 gate)
- `just rustdoc` (workspace documentation with warnings denied)
- `just update` (install the pinned cooldown tool, update dependencies at least seven days old, and test)
- `just udeps` (manual nightly-toolchain dependency-usage audit)
- `just release-notes-check` (required after repository changes and during release validation)
- `just publish-release X.Y.Z` (complete local release preparation, validation, upload, verification, and publication)
- `just mutants`
- `just mutants --shard 1/4`

Use `just update` rather than raw `cargo update`; stable Cargo does not enforce
the repository's publish-age policy by itself. Dependabot security updates
bypass the cooldown automatically. For an urgent local security update, add a
temporary exact-version exception to `cooldown.toml`, run `just update`, and
remove the exception before committing:

```toml
[[allow.exact]]
crate = "affected-crate"
version = "1.2.3"
```

Release builds require `musl-gcc` and the pinned
`x86_64-unknown-linux-musl` Rust target. The compatibility gate additionally
requires `readelf` and Docker access; it runs only offline Kidobo commands in
the containers and never invokes firewall or systemd operations.

## GitHub Automation

Kidobo does not use checked-in GitHub Actions workflows. Run `just ci` before
ordinary pushes and `just publish-release X.Y.Z` for releases. Dependabot update
PRs remain enabled as the sole GitHub-hosted automation exception.

## Release Recovery

The publisher retains the archive, checksum, and release notes under
`target/release-artifacts/<tag>/` whenever Git refs have been pushed but the
GitHub release was not confirmed published. It prints commands specialized for
that release. The equivalent manual recovery flow is:

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
