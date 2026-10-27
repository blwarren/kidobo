#!/usr/bin/env bash
set -euo pipefail

git diff --cached --check
git diff --check

rust_changed=false
while IFS= read -r -d '' path; do
  case "${path}" in
    *.rs|Cargo.toml|*/Cargo.toml|Cargo.lock|rust-toolchain*|.cargo/*|Justfile)
      rust_changed=true
      ;;
  esac
done < <(git diff --cached --no-renames --name-only --diff-filter=ACMD -z)

if [[ "${rust_changed}" == true ]]; then
  just format-check test-fast
fi
