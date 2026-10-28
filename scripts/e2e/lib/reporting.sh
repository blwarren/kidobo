e2e_check_start() {
  e2e_checks+=("$1")
  printf 'E2E_CHECK\t%s\tSTART\t%s\n' "$1" "$2" >&9
}

e2e_check_pass() {
  local index=$((${#e2e_checks[@]} - 1))
  printf 'E2E_CHECK\t%s\tPASS\t%s\n' "${e2e_checks[$index]}" "$1" >&9
  unset 'e2e_checks[index]'
}

e2e_report_exit() {
  local status=$1 check
  for check in "${e2e_checks[@]}"; do
    printf 'E2E_CHECK\t%s\tFAIL\t%s; guest exit status=%s\n' "$check" "$e2e_failure_reason" "$status" >&9
  done
}

e2e_plan_checks() {
  python3 - "${E2E_CHECK_MANIFEST:-$ROOT/checks.json}" "$2" "$1" <<'PYPLAN'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    manifest = json.load(source)
if manifest["version"] != 1:
    raise SystemExit("unsupported guest check manifest")
for name, count in manifest["profiles"][sys.argv[2]][sys.argv[3]].items():
    for _ in range(count):
        print(f"E2E_CHECK\t{name}\tPLAN\tscenario scheduled; expectation follows at START", file=sys.stderr)
PYPLAN
}

fail() { e2e_failure_reason=$*; printf 'e2e lifecycle: %s\n' "$*" >&2; exit 1; }
