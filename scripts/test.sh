#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )) || [[ $# == 1 && "$1" != --include-e2e ]]; then
    echo 'Usage: just test [--include-e2e]' >&2
    exit 2
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ $# == 1 ]]; then
    exec cargo test --workspace --locked --quiet
fi

# Select targets before compilation so root E2E fixtures are excluded too.
tests=()
shopt -s nullglob
for file in tests/*.rs; do
    name=${file##*/}
    [[ "$name" != e2e_* ]] || continue
    tests+=(--test "${name%.rs}")
done
cargo test --workspace --exclude kidobo-e2e --locked --quiet --lib --bins "${tests[@]}"
# Cargo does not allow --doc alongside other target selectors.
cargo test --workspace --exclude kidobo-e2e --locked --quiet --doc
