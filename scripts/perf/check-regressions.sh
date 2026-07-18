#!/usr/bin/env bash
set -euo pipefail

baseline="main"
max_slowdown_pct="10"
max_rss_kib=""
max_elapsed_s=""
run_rss_probe="1"
bench_name="core_perf"

usage() {
  cat <<'USAGE'
Usage:
  scripts/perf/check-regressions.sh [options]

Options:
  --baseline <name>            Criterion baseline name to compare against (default: main)
  --max-slowdown-pct <value>   Allowed slowdown percentage for benchmark mean point estimate (default: 10)
  --max-rss-kib <value>        Optional per-format max RSS threshold (KiB) for lookup probe
  --max-elapsed-s <value>      Optional per-format max elapsed seconds threshold for lookup probe
  --skip-rss-probe             Skip lookup RSS/time probe checks
  --bench-name <name>          Cargo bench target name (default: core_perf)
  -h, --help                   Show this help

Examples:
  scripts/perf/check-regressions.sh --baseline main --max-slowdown-pct 8
  scripts/perf/check-regressions.sh --baseline main --max-rss-kib 20000 --max-elapsed-s 0.10
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline)
      baseline="$2"
      shift 2
      ;;
    --max-slowdown-pct)
      max_slowdown_pct="$2"
      shift 2
      ;;
    --max-rss-kib)
      max_rss_kib="$2"
      shift 2
      ;;
    --max-elapsed-s)
      max_elapsed_s="$2"
      shift 2
      ;;
    --skip-rss-probe)
      run_rss_probe="0"
      shift
      ;;
    --bench-name)
      bench_name="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

echo "[perf-check] running cargo bench --bench ${bench_name} -- --baseline ${baseline}"
cargo bench --bench "${bench_name}" -- --baseline "${baseline}" >/tmp/kidobo-perf-bench.log 2>&1 || {
  cat /tmp/kidobo-perf-bench.log
  exit 1
}

echo "[perf-check] evaluating benchmark regressions (max ${max_slowdown_pct}% slowdown)"

regressions=0
checked=0

while IFS= read -r baseline_estimates; do
  new_estimates="${baseline_estimates%/${baseline}/estimates.json}/new/estimates.json"
  if [[ ! -f "${new_estimates}" ]]; then
    continue
  fi

  label="${baseline_estimates#target/criterion/}"
  label="${label%/${baseline}/estimates.json}"

  baseline_mean="$(grep -o '"point_estimate":[0-9.]*' "${baseline_estimates}" | head -n1 | cut -d: -f2)"
  new_mean="$(grep -o '"point_estimate":[0-9.]*' "${new_estimates}" | head -n1 | cut -d: -f2)"

  if [[ -z "${baseline_mean}" || -z "${new_mean}" ]]; then
    echo "[perf-check] WARN could not parse estimates for ${label}" >&2
    continue
  fi

  checked=$((checked + 1))
  slowdown_pct="$(awk -v n="${new_mean}" -v b="${baseline_mean}" 'BEGIN { printf "%.4f", ((n - b) / b) * 100 }')"

  if awk -v s="${slowdown_pct}" -v t="${max_slowdown_pct}" 'BEGIN { exit !(s > t) }'; then
    regressions=$((regressions + 1))
    echo "[perf-check] FAIL ${label}: ${slowdown_pct}% slowdown (baseline=${baseline_mean}ns new=${new_mean}ns)"
  else
    echo "[perf-check] OK   ${label}: ${slowdown_pct}%"
  fi
done < <(find target/criterion -type f -path "*/${baseline}/estimates.json" | sort)

if [[ ${checked} -eq 0 ]]; then
  echo "[perf-check] error: no baseline estimates found for '${baseline}' under target/criterion" >&2
  echo "[perf-check] hint: run scripts/perf/run-benchmarks.sh ${baseline} first" >&2
  exit 1
fi

if [[ "${run_rss_probe}" == "1" ]]; then
  echo "[perf-check] running lookup RSS/time probe"
  rss_output="$(scripts/perf/measure-lookup-rss.sh)"
  echo "${rss_output}"

  for format in human tsv; do
    rss_kib="$(awk -F= -v key="${format}_max_rss_kib" '$1==key{print $2}' <<< "${rss_output}")"
    elapsed_s="$(awk -F= -v key="${format}_elapsed_s" '$1==key{print $2}' <<< "${rss_output}")"

    if [[ -z "${rss_kib}" || -z "${elapsed_s}" ]]; then
      regressions=$((regressions + 1))
      echo "[perf-check] FAIL lookup ${format}: probe metrics are incomplete"
      continue
    fi

    if [[ -n "${max_rss_kib}" ]] && awk -v v="${rss_kib}" -v t="${max_rss_kib}" 'BEGIN { exit !(v > t) }'; then
      regressions=$((regressions + 1))
      echo "[perf-check] FAIL lookup ${format}_max_rss_kib=${rss_kib} exceeds threshold ${max_rss_kib}"
    fi

    if [[ -n "${max_elapsed_s}" ]] && awk -v v="${elapsed_s}" -v t="${max_elapsed_s}" 'BEGIN { exit !(v > t) }'; then
      regressions=$((regressions + 1))
      echo "[perf-check] FAIL lookup ${format}_elapsed_s=${elapsed_s} exceeds threshold ${max_elapsed_s}"
    fi
  done
fi

if [[ ${regressions} -gt 0 ]]; then
  echo "[perf-check] detected ${regressions} regression(s)"
  exit 1
fi

echo "[perf-check] no significant regressions detected"
