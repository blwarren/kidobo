#!/usr/bin/env bash
# Shared candidate/publication archive construction. Run from the repository root.
set -euo pipefail
if [[ $# -ne 3 || ! "$2" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo 'Usage: scripts/package-release.sh BINARY vX.Y.Z OUTPUT_DIRECTORY' >&2
    exit 2
fi
binary="$1"
tag="$2"
output="$3"
if [[ ! -x "${binary}" ]]; then
    echo "release binary is not executable: ${binary}" >&2
    exit 1
fi
headers="$(readelf -l "${binary}")"
if [[ "${headers}" == *INTERP* || "${headers}" == *'Requesting program interpreter'* ]]; then
    echo 'release binary has an ELF interpreter; a static binary is required' >&2
    exit 1
fi
dynamic="$(readelf -d "${binary}")"
if [[ "${dynamic}" == *NEEDED* ]]; then
    echo 'release binary has dynamic dependencies' >&2
    exit 1
fi
root="kidobo-${tag}-linux-x86_64"
staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
mkdir -p "${staging}/${root}" "${output}"
install -m 0755 "${binary}" "${staging}/${root}/kidobo"
install -m 0644 README.md LICENSE "${staging}/${root}/"
tar -C "${staging}" -czf "${output}/${root}.tar.gz" "${root}"
(cd "${output}" && sha256sum "${root}.tar.gz" > SHA256SUMS)
