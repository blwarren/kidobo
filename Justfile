# Show available development recipes.
default:
    @just --list

# Update dependencies after the publish-age cooldown, then run the test suite.
update: _install-cooldown && test
    @cargo cooldown update --verbose

# Build the release binary.
build-release:
    @env CC_x86_64_unknown_linux_musl=musl-gcc CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc cargo build --release --locked --package kidobo --bin kidobo --target x86_64-unknown-linux-musl

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

# Exercise the locally built release binary with isolated runtime fixtures.
exercise-release: build-release
    @env KIDOBO_TEST_BINARY="${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kidobo" cargo test --locked --test cli_runtime sync_remote_worker_warning_does_not_deadlock -- --exact

# Reject dynamic Linux artifacts and exercise the static binary on supported baselines.
release-compat: build-release
    @./scripts/check-release-compat.sh "${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kidobo"

# Configure suite-owned Incus infrastructure (requires an installed Incus server).
e2e-setup:
    @cargo run --locked -p kidobo-e2e -- setup

# Package the current static candidate and exercise every configured distro.
e2e *args: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    binary="${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kidobo"
    version="$("${binary}" --version)"
    tag="v${version#kidobo }"
    mkdir -p "target/e2e-candidate/${tag}"
    output="$(mktemp -d "target/e2e-candidate/${tag}/run-XXXXXXXX")"
    ./scripts/package-release.sh "${binary}" "${tag}" "${output}"
    cargo run --locked -p kidobo-e2e -- run --archive "${output}/kidobo-${tag}-linux-x86_64.tar.gz" --tag "${tag}" {{ args }}

# Test the exact archive selected for publication; always run the full matrix.
e2e-artifact archive tag:
    @cargo run --locked -p kidobo-e2e -- run --archive "{{ archive }}" --tag "{{ tag }}"

# Exercise genuine GitHub installation of a published release.
e2e-published tag="latest" *args:
    @cargo run --locked -p kidobo-e2e -- run --published --tag "{{ tag }}" {{ args }}

# Delete only the recorded VMs belonging to an E2E run.
e2e-clean run_id:
    @cargo run --locked -p kidobo-e2e -- clean "{{ run_id }}"

# Build workspace documentation with rustdoc warnings denied.
rustdoc:
    @env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Run the complete local CI validation sequence.
ci: && lint deny audit test
    @cargo fmt --all --check

# Run the stable llvm-cov region, function, and line coverage gates.
coverage:
    @cargo llvm-cov --workspace --all-features --fail-under-regions 90 --fail-under-functions 90 --fail-under-lines 90

# Run local mutation tests. Agents must not run this recipe.
mutants *args:
    @env CARGO_MUTANTS_JOBS="${CARGO_MUTANTS_JOBS:-4}" cargo mutants -vV {{ args }}

# Prepare, validate, package, and publish a release locally.
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

# Install cargo-cooldown for guarded dependency updates.
_install-cooldown:
    @cargo install --locked cargo-cooldown --version "${CARGO_COOLDOWN_VERSION:-0.3.4}"

# Install cargo-audit for CI and release validation.
_install-audit:
    @cargo install --locked cargo-audit --version "${CARGO_AUDIT_VERSION:-0.22.1}"

# Install cargo-llvm-cov for CI and release validation.
_install-coverage:
    @rustup component add llvm-tools-preview
    @cargo install --locked cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION:-0.8.4}"
