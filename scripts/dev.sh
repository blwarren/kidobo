#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "${repo_root}"

CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.19.0}"
CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.22.1}"
CARGO_UDEPS_VERSION="${CARGO_UDEPS_VERSION:-0.1.60}"
CARGO_MUTANTS_VERSION="${CARGO_MUTANTS_VERSION:-27.1.0}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/dev.sh <command>

Commands:
  pre-commit-fast    Run fast local checks used by pre-commit hook
  pre-push-tests     Run pre-push test suite
  post-coding-gates  Run post-coding local validation gates
  gates-minimum      Run minimum validation gates
  gates-extended     Run extended validation gates
  release-notes-check
                     Normalize release notes, regenerate changelog, verify clean diff
  ci-quality         Run CI quality gates
  ci-supply-chain    Run CI supply-chain checks
  ci-udeps           Run CI unused dependency checks
  udeps              Install and run local unused dependency checks
  ci-mutants [args...]
                     Install and run CI mutation tests, passing optional args to cargo-mutants
  mutants [args...]  Run local mutation tests, passing optional args to cargo-mutants
  help               Show this help
USAGE
}

log_step() {
  local scope="$1"
  shift
  printf '[%s] %s\n' "${scope}" "$*"
}

run_cmd() {
  local scope="$1"
  shift
  log_step "${scope}" "$*"
  "$@"
}

release_notes_check() {
  run_cmd "release-notes" ./scripts/changelog/format-release-notes.sh
  run_cmd "release-notes" ./scripts/changelog/generate.sh

  if ! git diff --quiet -- CHANGELOG.md release-notes; then
    log_step "release-notes" "Release notes and/or CHANGELOG.md were rewritten; stage updates and rerun."
    git --no-pager diff -- CHANGELOG.md release-notes
    return 1
  fi
}

run_pre_commit_fast() {
  run_cmd "pre-commit" cargo fmt --all --check
  run_cmd "pre-commit" cargo clippy --all-targets --all-features -- -D warnings
  release_notes_check
}

run_pre_push_tests() {
  run_cmd "pre-push" cargo test --lib --bins --tests --all-features
}

run_post_coding_gates() {
  run_cmd "post-coding" cargo fmt --all
  run_cmd "post-coding" cargo clippy --all-targets --all-features -- -D warnings
  run_cmd "post-coding" cargo test --lib --bins --tests --all-features
  run_cmd "post-coding" cargo deny check advisories bans licenses sources
  run_cmd "post-coding" cargo build --release --locked
  release_notes_check
  log_step "post-coding" "post-coding check complete"
}

run_gates_minimum() {
  run_cmd "gates-minimum" cargo fmt --all
  run_cmd "gates-minimum" cargo clippy --all-targets --all-features -- -D warnings
  run_cmd "gates-minimum" cargo test --lib --bins --tests --all-features
  run_cmd "gates-minimum" cargo test --doc
  run_cmd "gates-minimum" cargo check --release --locked
}

run_gates_extended() {
  run_gates_minimum
  run_cmd "gates-extended" cargo deny check advisories bans licenses sources
  run_cmd "gates-extended" cargo audit
  run_cmd "gates-extended" cargo llvm-cov --all-features --fail-under-lines 85
}

run_ci_quality() {
  run_cmd "ci-quality" cargo fmt --all --check
  run_cmd "ci-quality" ./scripts/changelog/format-release-notes.sh
  run_cmd "ci-quality" ./scripts/changelog/generate.sh
  run_cmd "ci-quality" git diff --exit-code -- CHANGELOG.md release-notes
  run_cmd "ci-quality" cargo clippy --all-targets --all-features -- -D warnings
  run_cmd "ci-quality" cargo test --lib --bins --tests --all-features
  run_cmd "ci-quality" cargo test --doc
  run_cmd "ci-quality" cargo check --release --locked
}

run_ci_supply_chain() {
  run_cmd "ci-supply-chain" cargo install --locked cargo-deny --version "${CARGO_DENY_VERSION}"
  run_cmd "ci-supply-chain" cargo install --locked cargo-audit --version "${CARGO_AUDIT_VERSION}"
  run_cmd "ci-supply-chain" cargo deny check advisories bans licenses sources
  run_cmd "ci-supply-chain" cargo audit
}

run_ci_udeps() {
  run_cmd "ci-udeps" cargo +nightly install --locked cargo-udeps --version "${CARGO_UDEPS_VERSION}"
  run_cmd "ci-udeps" cargo +nightly udeps --all-targets --all-features
}

run_udeps() {
  run_cmd "udeps" rustup toolchain install nightly --component rust-src
  run_ci_udeps
}

run_mutants() {
  run_cmd "mutants" cargo mutants -vV "$@"
}

run_ci_mutants() {
  run_cmd "ci-mutants" cargo install --locked cargo-mutants --version "${CARGO_MUTANTS_VERSION}"
  run_cmd "ci-mutants" cargo mutants -vV --in-place "$@"
}

main() {
  local command="${1:-help}"
  if [[ $# -gt 0 ]]; then
    shift
  fi

  if [[ "${command}" != "mutants" && "${command}" != "ci-mutants" && ( "${1:-}" == "-h" || "${1:-}" == "--help" ) ]]; then
    usage
    return 0
  fi

  if [[ "${command}" != "mutants" && "${command}" != "ci-mutants" && $# -gt 0 ]]; then
    echo "unexpected extra arguments for '${command}': $*" >&2
    usage >&2
    return 2
  fi

  case "${command}" in
    pre-commit-fast)
      run_pre_commit_fast
      ;;
    pre-push-tests)
      run_pre_push_tests
      ;;
    post-coding-gates)
      run_post_coding_gates
      ;;
    gates-minimum)
      run_gates_minimum
      ;;
    gates-extended)
      run_gates_extended
      ;;
    release-notes-check)
      release_notes_check
      ;;
    ci-quality)
      run_ci_quality
      ;;
    ci-supply-chain)
      run_ci_supply_chain
      ;;
    ci-udeps)
      run_ci_udeps
      ;;
    udeps)
      run_udeps
      ;;
    ci-mutants)
      run_ci_mutants "$@"
      ;;
    mutants)
      run_mutants "$@"
      ;;
    help|-h|--help)
      usage
      ;;
    *)
      echo "unknown command: ${command}" >&2
      usage >&2
      return 2
      ;;
  esac
}

main "$@"
