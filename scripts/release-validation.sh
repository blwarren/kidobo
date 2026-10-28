#!/usr/bin/env bash
set -euo pipefail

# The publisher's --skip-e2e path. Developer recipes retain workspace-wide checks.
if [[ $# != 1 || ! "$1" =~ ^(ci|coverage|rustdoc)$ ]]; then
    echo 'Usage: release-validation.sh ci|coverage|rustdoc' >&2
    exit 2
fi
action=$1
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Keep package selection shared by lint, coverage, and documentation. The inventory
# regression rejects new workspace packages until their validation scope is decided.
packages=(-p kidobo -p kidobo-adapters -p kidobo-app -p kidobo-core)
format_roots=(src/lib.rs src/main.rs)
for package in kidobo-adapters kidobo-app kidobo-core; do
    format_roots+=("crates/${package}/src/lib.rs")
done
tests=()
extras=()
shopt -s nullglob
for file in tests/*.rs; do
    name=${file##*/}
    [[ "$name" != e2e_* ]] || continue
    tests+=(--test "${name%.rs}")
    format_roots+=("$file")
done
for kind in bench example; do
    if [[ "$kind" == bench ]]; then directory=benches; else directory=examples; fi
    for file in "${directory}"/*.rs; do
        name=${file##*/}
        [[ "$name" != e2e_* ]] || continue
        extras+=("--${kind}" "${name%.rs}")
        format_roots+=("$file")
    done
done

case "$action" in
    ci)
        rustfmt --check --edition 2024 "${format_roots[@]}"
        cargo clippy --locked "${packages[@]}" --all-features --lib --bins \
            "${tests[@]}" "${extras[@]}" -- -D warnings
        just deny
        just audit
        just test-app
        ;;
    coverage)
        cargo llvm-cov --locked "${packages[@]}" --all-features --lib --bins "${tests[@]}" \
            --fail-under-regions 90 --fail-under-functions 90 --fail-under-lines 90
        ;;
    rustdoc)
        RUSTDOCFLAGS='-D warnings' cargo doc --locked "${packages[@]}" --all-features --no-deps
        ;;
esac
