# Show available development recipes.
default:
    @just --list

# Run fast local checks used by the pre-commit hook.
pre-commit-fast: fmt-check clippy release-notes-check

# Run the pre-push test suite.
pre-push-tests: test-suite

# Run post-coding local validation gates.
post-coding-gates: fmt clippy test-suite deny release-build release-notes-check
    @printf '[post-coding] post-coding check complete\n'

# Run minimum validation gates.
gates-minimum: fmt clippy test-suite doc-test release-check

# Run extended validation gates.
gates-extended: gates-minimum deny audit coverage

# Run CI quality gates.
ci-quality: fmt-check release-notes-check clippy test-suite doc-test release-check

# Run CI supply-chain checks.
ci-supply-chain: _install-deny _install-audit deny audit

# Run CI unused dependency checks.
ci-udeps: _install-udeps udeps-check

# Install nightly Rust and run local unused dependency checks.
udeps: _install-nightly ci-udeps

# Run local mutation tests. Agents must not run this recipe.
mutants *args:
    @printf '[mutants] cargo mutants -vV %s\n' "{{args}}"
    @env CARGO_MUTANTS_JOBS="${CARGO_MUTANTS_JOBS:-4}" cargo mutants -vV {{args}}

# Normalize release notes, regenerate the changelog, and verify the diff.
release-notes-check: _release-notes-format _release-notes-generate
    #!/usr/bin/env bash
    set -euo pipefail
    if ! git diff --quiet -- CHANGELOG.md release-notes; then
      printf '[release-notes] Release notes and/or CHANGELOG.md were rewritten; stage updates and rerun.\n'
      git --no-pager diff -- CHANGELOG.md release-notes
      exit 1
    fi

# Format Rust sources.
fmt:
    @printf '[fmt] cargo fmt --all\n'
    @cargo fmt --all

# Check Rust formatting.
fmt-check:
    @printf '[fmt] cargo fmt --all --check\n'
    @cargo fmt --all --check

# Run clippy with the repo lint policy.
clippy:
    @printf '[clippy] cargo clippy --all-targets --all-features -- -D warnings\n'
    @cargo clippy --all-targets --all-features -- -D warnings

# Run the main test suite.
test-suite:
    @printf '[test] cargo test --lib --bins --tests --all-features\n'
    @cargo test --lib --bins --tests --all-features

# Run documentation tests.
doc-test:
    @printf '[test] cargo test --doc\n'
    @cargo test --doc

# Check the release build.
release-check:
    @printf '[build] cargo check --release --locked\n'
    @cargo check --release --locked

# Build the release binary.
release-build:
    @printf '[build] cargo build --release --locked\n'
    @cargo build --release --locked

# Run cargo-deny policy checks.
deny:
    @printf '[supply-chain] cargo deny check advisories bans licenses sources\n'
    @cargo deny check advisories bans licenses sources

# Run cargo-audit.
audit:
    @printf '[supply-chain] cargo audit\n'
    @cargo audit

# Run llvm-cov line coverage gate.
coverage:
    @printf '[coverage] cargo llvm-cov --all-features --fail-under-lines 85\n'
    @cargo llvm-cov --all-features --fail-under-lines 85

# Normalize release-note files.
_release-notes-format:
    @printf '[release-notes] ./scripts/changelog/format-release-notes.sh\n'
    @./scripts/changelog/format-release-notes.sh

# Regenerate CHANGELOG.md.
_release-notes-generate:
    @printf '[release-notes] ./scripts/changelog/generate.sh\n'
    @./scripts/changelog/generate.sh

# Install cargo-deny for CI.
_install-deny:
    @printf '[tools] cargo install --locked cargo-deny --version %s\n' "${CARGO_DENY_VERSION:-0.19.0}"
    @cargo install --locked cargo-deny --version "${CARGO_DENY_VERSION:-0.19.0}"

# Install cargo-audit for CI.
_install-audit:
    @printf '[tools] cargo install --locked cargo-audit --version %s\n' "${CARGO_AUDIT_VERSION:-0.22.1}"
    @cargo install --locked cargo-audit --version "${CARGO_AUDIT_VERSION:-0.22.1}"

# Install cargo-udeps for CI.
_install-udeps:
    @printf '[tools] cargo +nightly install --locked cargo-udeps --version %s\n' "${CARGO_UDEPS_VERSION:-0.1.60}"
    @cargo +nightly install --locked cargo-udeps --version "${CARGO_UDEPS_VERSION:-0.1.60}"

# Install the nightly toolchain used by cargo-udeps.
_install-nightly:
    @printf '[tools] rustup toolchain install nightly --component rust-src\n'
    @rustup toolchain install nightly --component rust-src

# Run cargo-udeps.
udeps-check:
    @printf '[udeps] cargo +nightly udeps --all-targets --all-features\n'
    @cargo +nightly udeps --all-targets --all-features
