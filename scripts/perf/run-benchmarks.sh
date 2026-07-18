#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/perf/run-benchmarks.sh
  scripts/perf/run-benchmarks.sh <save-baseline-name>
  scripts/perf/run-benchmarks.sh <compare-baseline-name> <save-baseline-name>

Examples:
  scripts/perf/run-benchmarks.sh local
  scripts/perf/run-benchmarks.sh main pr-123
USAGE
}

case "$#" in
  0)
    cargo bench --bench core_perf
    ;;
  1)
    cargo bench --bench core_perf -- --save-baseline "$1"
    ;;
  2)
    cargo bench --bench core_perf -- --baseline "$1"
    cargo bench --bench core_perf -- --save-baseline "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
