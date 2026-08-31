#!/usr/bin/env bash
set -euo pipefail

binary="${1:-${CARGO_TARGET_DIR:-target}/x86_64-unknown-linux-musl/release/kidobo}"

for required_command in docker readelf mktemp; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "missing required command: ${required_command}" >&2
        exit 1
    fi
done

if [[ ! -x "${binary}" ]]; then
    echo "release compatibility binary is missing or not executable: ${binary}" >&2
    exit 1
fi

if readelf -l "${binary}" | grep -Fq 'Requesting program interpreter'; then
    echo "release binary has an ELF interpreter and is not static" >&2
    exit 1
fi
if readelf -d "${binary}" 2>/dev/null | grep -Fq '(NEEDED)'; then
    echo "release binary has dynamic NEEDED libraries and is not static" >&2
    exit 1
fi

binary_directory="$(cd "$(dirname "${binary}")" && pwd -P)"
binary_name="$(basename "${binary}")"
fixture_root="$(mktemp -d)"
cleanup() {
    rm -rf "${fixture_root}"
}
trap cleanup EXIT

mkdir -p "${fixture_root}/root/data" "${fixture_root}/root/cache/remote"
printf '203.0.113.0/24\n' > "${fixture_root}/root/data/blocklist.txt"

for image in debian:11-slim alpine:3.22; do
    echo "[release-compat] exercising ${image}"
    docker run --rm --network none --read-only \
        --volume "${binary_directory}/${binary_name}:/usr/local/bin/kidobo:ro" \
        "${image}" /usr/local/bin/kidobo --version >/dev/null
    docker run --rm --network none --read-only \
        --volume "${binary_directory}/${binary_name}:/usr/local/bin/kidobo:ro" \
        "${image}" /usr/local/bin/kidobo --help >/dev/null
    lookup_output="$(
        docker run --rm --network none --read-only \
            --volume "${binary_directory}/${binary_name}:/usr/local/bin/kidobo:ro" \
            --volume "${fixture_root}:/fixture:ro" \
            --env KIDOBO_ROOT=/fixture/root \
            "${image}" /usr/local/bin/kidobo lookup 203.0.113.7 --format tsv
    )"
    if [[ "${lookup_output}" != $'203.0.113.7\tinternal:blocklist\t203.0.113.0/24' ]]; then
        echo "unexpected offline lookup output on ${image}: ${lookup_output}" >&2
        exit 1
    fi
done

echo "[release-compat] static Debian 11 and Alpine 3.22 checks passed"
