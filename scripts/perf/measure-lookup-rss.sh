#!/usr/bin/env bash
set -euo pipefail

if [[ ! -x /usr/bin/time ]]; then
  echo "error: /usr/bin/time is required for max RSS reporting" >&2
  exit 1
fi

blocks="${KIDOBO_PERF_BLOCKS:-50000}"
targets="${KIDOBO_PERF_TARGETS:-10000}"
cpu_core="${KIDOBO_PERF_CPU_CORE:-}"
mem_limit_kib="${KIDOBO_PERF_MEM_LIMIT_KIB:-}"

if [[ "${blocks}" -le 0 || "${targets}" -le 1 ]]; then
  echo "error: KIDOBO_PERF_BLOCKS must be > 0 and KIDOBO_PERF_TARGETS must be > 1" >&2
  exit 1
fi

if [[ -n "${cpu_core}" ]] && ! [[ "${cpu_core}" =~ ^[0-9]+$ ]]; then
  echo "error: KIDOBO_PERF_CPU_CORE must be a non-negative integer" >&2
  exit 1
fi

if [[ -n "${mem_limit_kib}" ]] && ! [[ "${mem_limit_kib}" =~ ^[0-9]+$ ]]; then
  echo "error: KIDOBO_PERF_MEM_LIMIT_KIB must be a positive integer in KiB" >&2
  exit 1
fi

if [[ -n "${mem_limit_kib}" && "${mem_limit_kib}" -le 0 ]]; then
  echo "error: KIDOBO_PERF_MEM_LIMIT_KIB must be > 0" >&2
  exit 1
fi

if [[ -n "${cpu_core}" ]] && ! command -v taskset >/dev/null 2>&1; then
  echo "error: taskset is required when KIDOBO_PERF_CPU_CORE is set" >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

export KIDOBO_ROOT="${tmp_root}/root"
binary="${KIDOBO_PERF_BINARY:-target/release/kidobo}"
blocklist_path="${KIDOBO_ROOT}/data/blocklist.txt"
targets_path="${tmp_root}/targets.txt"

if [[ -z "${KIDOBO_PERF_BINARY:-}" ]]; then
  cargo build --release --locked --bin kidobo >/dev/null
fi
if [[ ! -x "${binary}" ]]; then
  echo "error: lookup probe binary is not executable: ${binary}" >&2
  exit 1
fi

mkdir -p "${KIDOBO_ROOT}/config" "${KIDOBO_ROOT}/data" "${KIDOBO_ROOT}/cache/remote"
printf '%s\n' \
  '[ipset]' \
  "set_name = 'kidobo'" \
  '[safe]' \
  'include_github_meta = false' \
  > "${KIDOBO_ROOT}/config/config.toml"

awk -v count="${blocks}" 'BEGIN {
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "203.%d.%d.0/24\n", a, b;
  }
}' > "${blocklist_path}"

half_targets=$((targets / 2))
awk -v count="${half_targets}" 'BEGIN {
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "203.%d.%d.7\n", a, b;
  }
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "198.51.%d.%d\n", a, b;
  }
}' > "${targets_path}"

run_probe() {
  local format="$1"
  local lookup_output_path="${tmp_root}/lookup-${format}.out"
  local time_output_path="${tmp_root}/time-${format}.out"

  /usr/bin/time -f "${format}_elapsed_s=%e
${format}_max_rss_kib=%M" \
    bash -lc '
      set -euo pipefail
      lookup_cmd=("$1" lookup --file "$2" --format "$5")
      if [[ -n "$4" ]]; then
        ulimit -Sv "$4"
      fi
      if [[ -n "$3" ]]; then
        exec taskset -c "$3" "${lookup_cmd[@]}"
      fi
      exec "${lookup_cmd[@]}"
    ' -- "${binary}" "${targets_path}" "${cpu_core}" "${mem_limit_kib}" "${format}" \
    > "${lookup_output_path}" 2> "${time_output_path}"

  printf '%s_output_lines=%s\n' \
    "${format}" \
    "$(wc -l < "${lookup_output_path}" | tr -d ' ')"
  cat "${time_output_path}"
}

printf 'blocklist_entries=%s\n' "${blocks}"
printf 'target_entries=%s\n' "$((half_targets * 2))"
if [[ -n "${cpu_core}" ]]; then
  printf 'cpu_core=%s\n' "${cpu_core}"
else
  printf 'cpu_core=unconstrained\n'
fi
if [[ -n "${mem_limit_kib}" ]]; then
  printf 'mem_limit_kib=%s\n' "${mem_limit_kib}"
else
  printf 'mem_limit_kib=unconstrained\n'
fi
run_probe human
run_probe tsv
