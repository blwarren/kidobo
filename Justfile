# Show available development recipes.
default:
    @just --list

# Update dependencies, then run the test suite.
update: && test
    @cargo update --verbose

# Build the release binary.
build-release:
    @cargo build --release --locked --package kidobo --bin kidobo

# Run clippy with the repository lint policy.
lint:
    @cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run the workspace test suite, including documentation tests.
test:
    @cargo test --workspace --locked --quiet

# Format Rust sources.
format:
    @cargo fmt --all

# Run cargo-deny policy checks.
deny:
    @cargo deny check advisories bans licenses sources

# Run cargo-audit.
audit:
    @cargo audit

# Install and run cargo-udeps with nightly Rust.
udeps:
    @rustup toolchain install nightly --component rust-src
    @cargo +nightly install --locked cargo-udeps --version "${CARGO_UDEPS_VERSION:-0.1.60}"
    @cargo +nightly udeps --workspace --all-targets --all-features

# Format, test, and lint local changes.
check: format test lint

# Run the full CI validation sequence.
ci: && build-release lint deny audit test
    @cargo fmt --all --check

# Run the stable llvm-cov region, function, and line coverage gates.
coverage:
    @cargo llvm-cov --workspace --all-features --fail-under-regions 90 --fail-under-functions 90 --fail-under-lines 90

# Run local mutation tests. Agents must not run this recipe.
mutants *args:
    @env CARGO_MUTANTS_JOBS="${CARGO_MUTANTS_JOBS:-4}" cargo mutants -vV {{ args }}

# Prepare, validate, commit, tag, and atomically publish a release.
publish-release version:
    @./scripts/publish-release.sh "{{ version }}"

# Normalize release notes, regenerate the changelog, and verify the diff.
release-notes-check: _release-notes-format _release-notes-generate
    #!/usr/bin/env bash
    set -euo pipefail
    if ! git diff --quiet -- CHANGELOG.md release-notes; then
      printf '[release-notes] Release notes and/or CHANGELOG.md were rewritten; stage updates and rerun.\n'
      git --no-pager diff -- CHANGELOG.md release-notes
      exit 1
    fi

# Normalize release-note files.
_release-notes-format:
    @./scripts/changelog/format-release-notes.sh

# Regenerate CHANGELOG.md.
_release-notes-generate:
    @./scripts/changelog/generate.sh

# Install cargo-deny for CI and release validation.
_install-deny:
    @cargo install --locked cargo-deny --version "${CARGO_DENY_VERSION:-0.19.0}"

# Install cargo-audit for CI and release validation.
_install-audit:
    @cargo install --locked cargo-audit --version "${CARGO_AUDIT_VERSION:-0.22.1}"
