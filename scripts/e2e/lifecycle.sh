#!/usr/bin/env bash
set -euo pipefail

# Keep tracing and check evidence out of stdout and redirected command diagnostics.
exec 9>&2
BASH_XTRACEFD=9
PS4='+ TRACE ${BASH_SOURCE:-main}:${LINENO}:${FUNCNAME[0]:-main}: '
set -x

e2e_checks=()
e2e_failure_reason='command failed or guest interrupted before assertion completion'
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
trap 'e2e_report_exit "$?"' EXIT

readonly ROOT=/opt/kidobo-e2e MARKER=/etc/kidobo-e2e-owned
readonly MARKER_CONTENT=kidobo-e2e-v1
readonly RELEASE="$ROOT/release" BASELINE="$ROOT/baseline" STATE="$ROOT/state"
readonly TEST_NS=kidobo-e2e HOST_IF=ke2eh0 PEER_IF=ke2ep0
readonly V4_HOST=198.18.77.1 V4_PEER=198.18.77.2 V4_CONTROL=198.18.77.3
readonly V6_HOST=fd42:6b69:646f:626f::1 V6_PEER=fd42:6b69:646f:626f::2 V6_CONTROL=fd42:6b69:646f:626f::3
readonly TRAFFIC_PORT=39471 HTTP_PORT=39472 BAD_HTTP_PORT=39473 SOURCE_PORT=39474 IRR_PORT=39475
readonly CONFIG=/etc/kidobo/config.toml BLOCKLIST=/var/lib/kidobo/blocklist.txt
readonly SET4=kidobo-e2e SET6=kidobo-e2e-v6

fail() { e2e_failure_reason=$*; printf 'e2e lifecycle: %s\n' "$*" >&2; exit 1; }
[[ -f "$MARKER" ]] || fail "missing guest ownership marker $MARKER"
cmp -s "$MARKER" <(printf '%s\n' "$MARKER_CONTENT") || fail "invalid guest ownership marker content in $MARKER"
[[ ! -e /run/systemd/container ]] || fail 'refusing to run inside a container; E2E requires a VM'
[[ $# -eq 3 ]] || fail 'usage: lifecycle.sh PHASE TAG MODE(candidate|published)'
phase=$1 tag=$2 mode=$3
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || fail "invalid release tag: $tag"
[[ "$mode" == candidate || "$mode" == published ]] || fail "invalid mode: $mode"
e2e_plan_checks "$phase" "$mode"
installer="$RELEASE/installer.sh"
[[ -x "$installer" ]] || fail "missing executable installer $installer"
install_target() {
  if [[ "$mode" == candidate ]]; then
    KIDOBO_RELEASE_BASE_URL="http://127.0.0.1:$HTTP_PORT" "$installer" --version "$tag" "$@"
  else
    env -u KIDOBO_RELEASE_BASE_URL "$installer" --version "$tag" "$@"
  fi
}

fixture_curl() {
  curl --noproxy '*' --connect-timeout 1 --max-time 1 "$@"
}
serve_dir() {
  local directory=$1 port=$2 label=$3 deadline=$((SECONDS + 5))
  if [[ -s "$directory/SHA256SUMS" ]] && cmp -s "$directory/SHA256SUMS" <(fixture_curl -fsS "http://127.0.0.1:$port/SHA256SUMS" 2>/dev/null); then return 0; fi
  python3 -m http.server --bind 127.0.0.1 --directory "$directory" "$port" >"$STATE/http-$label.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/http-$label.pid"
  while (( SECONDS < deadline )); do
    if fixture_curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  fail "HTTP fixture failed to start: $label"
}
start_source_fixture() {
  local deadline=$((SECONDS + 5))
  mkdir -p "$ROOT/fixtures"
  cat > "$ROOT/fixtures/feed.txt" <<EOF
198.51.100.44
2001:db8::44
EOF
  if cmp -s "$ROOT/fixtures/feed.txt" <(fixture_curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" 2>/dev/null); then return 0; fi
  stop_fixture "$STATE/http-source.pid" "$ROOT/traffic.py source $ROOT/fixtures/feed.txt $SOURCE_PORT"
  python3 "$ROOT/traffic.py" source "$ROOT/fixtures/feed.txt" "$SOURCE_PORT" >"$STATE/http-source.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/http-source.pid"
  while (( SECONDS < deadline )); do
    if fixture_curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  fail 'HTTP source fixture failed to start'
}
stop_fixture() {
  local pid_file=$1 expected=$2
  if [[ -s "$pid_file" ]]; then
    local pid
    pid=$(<"$pid_file")
    if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$expected"; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
    rm -f "$pid_file"
  fi
}
defer_timer_until_configuration_is_ready() {
  local dropin=/run/systemd/system/kidobo-sync.timer.d/e2e.conf
  [[ ! -e "$dropin" ]] || fail "refusing to replace existing timer drop-in $dropin"
  mkdir -p "${dropin%/*}"
  # Timer expressions accumulate across drop-ins unless the list is reset first.
  printf '[Timer]\nOnBootSec=\nOnActiveSec=1h\n' > "$dropin"
  systemctl daemon-reload
  if systemctl is-active --quiet kidobo-sync.timer; then
    systemctl restart kidobo-sync.timer
  fi
}
restore_boot_timer() {
  clear_timer_deferral
  systemctl restart kidobo-sync.timer
}
clear_timer_deferral() {
  local dropin=/run/systemd/system/kidobo-sync.timer.d/e2e.conf
  rm -f "$dropin"
  rmdir "${dropin%/*}" 2>/dev/null || true
  systemctl daemon-reload
}
wait_for_sync_service_idle() {
  for _ in {1..180}; do
    local active result status started
    active=$(systemctl show kidobo-sync.service --property=ActiveState --value 2>/dev/null || true)
    if [[ "$active" == inactive ]]; then
      started=$(systemctl show kidobo-sync.service --property=ExecMainStartTimestamp --value 2>/dev/null || true)
      if [[ -n "$started" && "$started" != n/a ]]; then
        result=$(systemctl show kidobo-sync.service --property=Result --value 2>/dev/null || true)
        status=$(systemctl show kidobo-sync.service --property=ExecMainStatus --value 2>/dev/null || true)
        [[ "$result" == success && "$status" == 0 ]] || fail "kidobo-sync.service did not complete successfully (result=$result status=$status)"
      fi
      return 0
    fi
    [[ "$active" == activating || "$active" == deactivating ]] || fail "unexpected kidobo-sync.service state before installer operation: $active"
    sleep 1
  done
  fail 'kidobo-sync.service remained active for 180 seconds'
}

ensure_clean_namespace() {
  ip netns del "$TEST_NS" >/dev/null 2>&1 || true
  ip link del "$HOST_IF" >/dev/null 2>&1 || true
}
cleanup_namespace() { ensure_clean_namespace; }
capture_namespace_and_cleanup() {
  local exit_status=$?
  trap - EXIT
  e2e_report_exit "$exit_status"
  {
    printf 'phase=%s\n' "$phase"
    printf '%s\n' '=== host links and addresses ==='
    ip -details address show || true
    printf '%s\n' '=== host routes ==='
    ip route show table all || true
    ip -6 route show table all || true
    printf '%s\n' '=== host neighbors ==='
    ip neigh show || true
    ip -6 neigh show || true
    if command -v nmcli >/dev/null 2>&1; then
      printf '%s\n' '=== guest NetworkManager fixture interface ==='
      nmcli device show "$HOST_IF" || true
      journalctl -u NetworkManager -n 80 --no-pager || true
    fi
    printf '%s\n' '=== namespace links and addresses ==='
    ip netns exec "$TEST_NS" ip -details address show || true
    printf '%s\n' '=== namespace routes ==='
    ip netns exec "$TEST_NS" ip route show table all || true
    ip netns exec "$TEST_NS" ip -6 route show table all || true
    printf '%s\n' '=== namespace neighbors ==='
    ip netns exec "$TEST_NS" ip neigh show || true
    ip netns exec "$TEST_NS" ip -6 neigh show || true
  } > "$STATE/network-$phase.txt" 2>&1 || true
  cleanup_namespace
  exit "$exit_status"
}
setup_namespace() {
  ensure_clean_namespace
  ip netns add "$TEST_NS"
  ip link add "$HOST_IF" type veth peer name "$PEER_IF"
  ip link set "$PEER_IF" netns "$TEST_NS"
  if command -v nmcli >/dev/null 2>&1 && [[ "$(nmcli -g RUNNING general)" == running ]]; then
    local nm_ready=0
    for _ in {1..100}; do
      if nmcli -g GENERAL.DEVICE device show "$HOST_IF" >/dev/null 2>&1; then nm_ready=1; break; fi
      sleep 0.05
    done
    [[ "$nm_ready" == 1 ]] || fail 'NetworkManager did not discover the fixture veth within five seconds'
    nmcli -w 10 device set "$HOST_IF" managed no
    [[ "$(LC_ALL=C nmcli -g GENERAL.STATE device show "$HOST_IF")" == "10 "* ]] || fail 'NetworkManager still manages the fixture veth'
  fi
  ip addr add "$V4_HOST/29" dev "$HOST_IF"
  ip -6 addr add "$V6_HOST/64" dev "$HOST_IF" nodad
  ip link set "$HOST_IF" up
  ip netns exec "$TEST_NS" ip addr add "$V4_PEER/29" dev "$PEER_IF"
  ip netns exec "$TEST_NS" ip -6 addr add "$V6_PEER/64" dev "$PEER_IF" nodad
  ip netns exec "$TEST_NS" ip addr add "$V4_CONTROL/29" dev "$PEER_IF"
  ip netns exec "$TEST_NS" ip -6 addr add "$V6_CONTROL/64" dev "$PEER_IF" nodad
  ip netns exec "$TEST_NS" ip link set lo up
  ip netns exec "$TEST_NS" ip link set "$PEER_IF" up
  ip netns exec "$TEST_NS" ip route add default via "$V4_HOST"
  ip netns exec "$TEST_NS" ip -6 route add default via "$V6_HOST"
}
start_traffic_servers() {
  local address label pid_file ready_file log_file pid proc_state rc
  for address in "$V4_HOST" "$V6_HOST"; do
    if [[ "$address" == *:* ]]; then label=v6; else label=v4; fi
    pid_file="$STATE/server-$label.pid"
    ready_file="$STATE/server-$label.ready"
    log_file="$STATE/server-$label.log"
    stop_fixture "$pid_file" "$ROOT/traffic.py serve $address $TRAFFIC_PORT"
    rm -f "$ready_file"
    python3 "$ROOT/traffic.py" serve "$address" "$TRAFFIC_PORT" "$ready_file" >"$log_file" 2>&1 9>&- &
    pid=$!
    printf '%s\n' "$pid" > "$pid_file"
    for _ in {1..200}; do
      if [[ -s "$ready_file" ]]; then
        if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$ROOT/traffic.py serve $address $TRAFFIC_PORT"; then
          break
        fi
        fail "traffic fixture $label published readiness without a live matching process; log: $log_file"
      fi
      if [[ -r "/proc/$pid/stat" ]]; then
        proc_state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || proc_state=''
        if [[ "$proc_state" == Z || -z "$proc_state" ]]; then
          rc=0
          wait "$pid" || rc=$?
          fail "traffic fixture $label exited before readiness (status=$rc); log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
        fi
      else
        rc=0
        wait "$pid" || rc=$?
        fail "traffic fixture $label exited before readiness (status=$rc); log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
      fi
      sleep 0.05
    done
    [[ -s "$ready_file" ]] || fail "traffic fixture $label did not become ready within 10 seconds; log: $log_file; $(tail -n 20 "$log_file" 2>/dev/null || true)"
  done
}
managed_drop_packets() {
  local binary=$1 set_name=$2
  "$binary" -w 5 -L kidobo-input -n -v -x | awk -v set_name="$set_name" '
    $3 == "DROP" && index($0, "match-set " set_name " src") { count++; packets=$1 }
    END { if (count != 1 || packets !~ /^[0-9]+$/) exit 1; print packets }'
}
probe_raw() {
  local address=$1 source=$2 output=$3 status=0
  ip netns exec "$TEST_NS" python3 "$ROOT/traffic.py" probe "$address" "$TRAFFIC_PORT" "$source" > "$output" || status=$?
  printf '%s\n' "$status" > "$output.status"
}
probe_observation() {
  local family=$1 address=$2 source=$3 expectation=$4 output=$5 before=${6:-0} after=${7:-0}
  local status outcome
  e2e_check_start "$family traffic to $address" "connectivity=$expectation; namespace=$TEST_NS; source=$source; port=$TRAFFIC_PORT"
  status=$(<"$output.status")
  outcome=$(python3 - "$output" "$address" "$source" <<'PYPROBE'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
if value["address"] != sys.argv[2] or value["source"] != sys.argv[3]:
    raise SystemExit("probe identity mismatch")
print(value["outcome"])
PYPROBE
  ) || fail "$family probe did not return a valid structured observation"
  if [[ "$expectation" == allowed ]]; then
    [[ "$status" == 0 && "$outcome" == allowed ]] || fail "$family fixture/control failed; status=$status outcome=$outcome"
  else
    [[ "$status" == 10 && "$outcome" == connect-timeout ]] || fail "$family blocking requires connect timeout, got status=$status outcome=$outcome"
    [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ && "$after" -gt "$before" ]] || fail "$family intended DROP counter did not increase ($before -> $after)"
  fi
  e2e_check_pass "status=$status outcome=$outcome; intended DROP packets=$before->$after; source=$source"
}
probe_pair() {
  local expectation=$1 before4=0 before6=0 after4=0 after6=0 pid4 pid6
  local prefix="$STATE/probe-$phase"
  if [[ "$expectation" == blocked ]]; then
    before4=$(managed_drop_packets iptables "$SET4") || fail 'cannot read intended IPv4 DROP counter'
    before6=$(managed_drop_packets ip6tables "$SET6") || fail 'cannot read intended IPv6 DROP counter'
  fi
  (
    probe_raw "$V4_HOST" "$V4_CONTROL" "$prefix-v4-control.json"
    probe_raw "$V4_HOST" "$V4_PEER" "$prefix-v4.json"
  ) 9>&- & pid4=$!
  (
    probe_raw "$V6_HOST" "$V6_CONTROL" "$prefix-v6-control.json"
    probe_raw "$V6_HOST" "$V6_PEER" "$prefix-v6.json"
  ) 9>&- & pid6=$!
  wait "$pid4" || fail 'IPv4 probe worker failed'
  wait "$pid6" || fail 'IPv6 probe worker failed'
  if [[ "$expectation" == blocked ]]; then
    after4=$(managed_drop_packets iptables "$SET4") || fail 'cannot read intended IPv4 DROP counter after probe'
    after6=$(managed_drop_packets ip6tables "$SET6") || fail 'cannot read intended IPv6 DROP counter after probe'
  fi
  probe_observation 'IPv4 control' "$V4_HOST" "$V4_CONTROL" allowed "$prefix-v4-control.json"
  probe_observation 'IPv6 control' "$V6_HOST" "$V6_CONTROL" allowed "$prefix-v6-control.json"
  probe_observation IPv4 "$V4_HOST" "$V4_PEER" "$expectation" "$prefix-v4.json" "$before4" "$after4"
  probe_observation IPv6 "$V6_HOST" "$V6_PEER" "$expectation" "$prefix-v6.json" "$before6" "$after6"
}
# Kept as a narrow helper for local assertion regressions and single-family diagnostics.
probe() {
  local family=$1 address=$2 expectation=$3 output="$STATE/probe-single.json" before=0 after=0
  local source=$V4_PEER binary=iptables set_name=$SET4
  if [[ "$family" == IPv6 ]]; then source=$V6_PEER; binary=ip6tables; set_name=$SET6; fi
  if [[ "$expectation" == blocked ]]; then before=$(managed_drop_packets "$binary" "$set_name"); fi
  probe_raw "$address" "$source" "$output"
  if [[ "$expectation" == blocked ]]; then after=$(managed_drop_packets "$binary" "$set_name"); fi
  probe_observation "$family" "$address" "$source" "$expectation" "$output" "$before" "$after"
}

start_irr_fixture() {
  local deadline=$((SECONDS + 5)) real_bgpq4
  real_bgpq4=$(command -v bgpq4) || fail 'packaged bgpq4 is unavailable'
  "$real_bgpq4" -v > "$STATE/bgpq4-version.txt" 2>&1
  mkdir -p "$ROOT/asn-bin"
  printf '#!/usr/bin/env bash\nexec %q -h 127.0.0.1:%q "$@"\n' "$real_bgpq4" "$IRR_PORT" > "$ROOT/asn-bin/bgpq4"
  chmod 0755 "$ROOT/asn-bin/bgpq4"
  stop_fixture "$STATE/irr.pid" "$ROOT/traffic.py irr $IRR_PORT"
  rm -f "$STATE/irr.ready" "$STATE/irr.error"
  : > "$STATE/irr-protocol.log"
  python3 "$ROOT/traffic.py" irr "$IRR_PORT" "$STATE/irr.ready" "$STATE/irr-protocol.log" "$STATE/irr.error" > "$STATE/irr.log" 2>&1 9>&- &
  printf '%s\n' "$!" > "$STATE/irr.pid"
  while (( SECONDS < deadline )); do
    [[ ! -s "$STATE/irr.error" ]] || fail 'IRR fixture rejected an unexpected request'
    [[ ! -s "$STATE/irr.ready" ]] || return 0
    sleep 0.05
  done
  fail 'IRR fixture did not become ready'
}
test_asn_resolver() {
  e2e_check_start 'packaged ASN resolver and sync boundaries' 'actual bgpq4 resolves both families through local IRRd; ban/unban change enforcement only at sync; lookup works offline'
  start_irr_fixture
  local resolver_path="$ROOT/asn-bin:$PATH"
  PATH="$resolver_path" kidobo ban --asn AS13335
  grep -Fq 13335 "$CONFIG" || fail 'ASN ban did not update config'
  if ipset test "$SET4" 203.0.113.80 >/dev/null 2>&1 || ipset test "$SET6" 2001:db8::80 >/dev/null 2>&1; then fail 'ASN ban changed enforcement before sync'; fi
  PATH="$resolver_path" kidobo sync
  assert_live_rules
  ipset test "$SET4" 203.0.113.80 || fail 'ASN IPv4 prefix was not enforced'
  ipset test "$SET6" 2001:db8::80 || fail 'ASN IPv6 prefix was not enforced'
  grep -Eiq '^!gas13335$' "$STATE/irr-protocol.log" || fail 'packaged resolver did not request IPv4 prefixes'
  grep -Eiq '^!6as13335$' "$STATE/irr-protocol.log" || fail 'packaged resolver did not request IPv6 prefixes'
  [[ ! -s "$STATE/irr.error" ]] || fail 'packaged resolver used an unsupported IRRd request'
  stop_fixture "$STATE/irr.pid" "$ROOT/traffic.py irr $IRR_PORT"
  PATH="$resolver_path" kidobo lookup 203.0.113.80 --format tsv > "$STATE/asn-lookup-v4.tsv"
  PATH="$resolver_path" kidobo lookup 2001:db8::80 --format tsv > "$STATE/asn-lookup-v6.tsv"
  grep -Fxq "$(printf '203.0.113.80\tasn:AS13335\t203.0.113.80/32')" "$STATE/asn-lookup-v4.tsv" || fail 'offline ASN IPv4 lookup was incorrect'
  grep -Fxq "$(printf '2001:db8::80\tasn:AS13335\t2001:db8::80/128')" "$STATE/asn-lookup-v6.tsv" || fail 'offline ASN IPv6 lookup was incorrect'
  PATH="$resolver_path" kidobo unban --asn AS13335 --yes
  ipset test "$SET4" 203.0.113.80 || fail 'ASN unban changed IPv4 enforcement before sync'
  ipset test "$SET6" 2001:db8::80 || fail 'ASN unban changed IPv6 enforcement before sync'
  sync_and_assert
  if ipset test "$SET4" 203.0.113.80 >/dev/null 2>&1 || ipset test "$SET6" 2001:db8::80 >/dev/null 2>&1; then fail 'ASN prefixes remain after unban and sync'; fi
  e2e_check_pass 'real packaged resolver queried both families; exact offline results match; ASN membership changed only after sync'
}

write_config() {
  local safe4=${1:-} safe6=${2:-} maxelem=${3:-500000}
  local safe_items=() safe_list
  [[ -z "$safe4" ]] || safe_items+=("\"$safe4\"")
  [[ -z "$safe6" ]] || safe_items+=("\"$safe6\"")
  safe_list=$(IFS=,; printf '%s' "${safe_items[*]}")
  cat > "$CONFIG" <<EOF
[ipset]
set_name = "$SET4"
set_name_v6 = "$SET6"
enable_ipv6 = true
chain_action = "DROP"
maxelem = $maxelem

[safe]
ips = [$safe_list]
include_github_meta = false

[remote]
urls = ["http://127.0.0.1:$SOURCE_PORT/feed.txt"]

[asn]
banned = []
EOF
}
assert_target_version() {
  [[ "$(kidobo --version)" == "kidobo ${tag#v}" ]] || fail "installed version mismatch (wanted ${tag#v})"
}
assert_installed_binary() {
  local label=$1 owner permissions hash
  owner=$(stat -c '%U' /usr/local/bin/kidobo)
  permissions=$(stat -c '%a' /usr/local/bin/kidobo)
  [[ "$owner" == root ]] || fail "installed binary is owned by $owner, expected root"
  [[ "$permissions" == 755 ]] || fail "installed binary mode is $permissions, expected 755"
  hash=$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')
  printf '%s  /usr/local/bin/kidobo\n' "$hash" > "$STATE/binary-$label.sha256"
  if [[ "$mode" == candidate && "$label" != baseline ]]; then
    local archive="$RELEASE/kidobo-${tag}-linux-x86_64.tar.gz" archive_root="kidobo-${tag}-linux-x86_64" member_hash
    [[ -s "$archive" ]] || fail "candidate archive missing: $archive"
    tar -tzf "$archive" | grep -Fxq "$archive_root/kidobo" || fail 'candidate archive does not contain the expected kidobo member'
    member_hash=$(tar -xzOf "$archive" "$archive_root/kidobo" | sha256sum | awk '{print $1}')
    [[ "$hash" == "$member_hash" ]] || fail 'installed candidate binary does not match the release archive member'
    printf '%s  archive:kidobo\n' "$member_hash" > "$STATE/archive-binary-candidate.sha256"
  fi
}
assert_systemd_units() {
  [[ -s /etc/systemd/system/kidobo-sync.service ]] || fail 'kidobo init did not create the systemd service unit'
  [[ -s /etc/systemd/system/kidobo-sync.timer ]] || fail 'kidobo init did not create the systemd timer unit'
  grep -Eq '^ExecStart="/usr/local/bin/kidobo" sync$' /etc/systemd/system/kidobo-sync.service || fail 'generated service unit has an unexpected ExecStart'
  grep -Eq '^OnBootSec=2min$' /etc/systemd/system/kidobo-sync.timer || fail 'generated timer unit is missing its two-minute boot delay'
  grep -Eq '^OnUnitActiveSec=1h$' /etc/systemd/system/kidobo-sync.timer || fail 'generated timer unit is missing its hourly cadence'
}
assert_init_artifacts() {
  assert_systemd_units
  [[ -s "$CONFIG" ]] || fail 'kidobo init did not create a nonempty default config'
  [[ -f "$BLOCKLIST" ]] || fail 'kidobo init did not create the blocklist file'
  grep -Eq '^\[ipset\]$' "$CONFIG" || fail 'default config is missing the [ipset] table'
  grep -Eq '^set_name = "kidobo"$' "$CONFIG" || fail 'default config has an unexpected set_name'
  grep -Eq '^chain_action = "DROP"$' "$CONFIG" || fail 'default config has an unexpected chain action'
  grep -Eq '^\[safe\]$' "$CONFIG" || fail 'default config is missing the [safe] table'
  grep -Eq '^include_github_meta = true$' "$CONFIG" || fail 'default config has an unexpected GitHub metadata default'
  grep -Eq '^github_meta_url = "https://api.github.com/meta"$' "$CONFIG" || fail 'default config has an unexpected GitHub metadata URL'
  grep -Eq '^\[remote\]$' "$CONFIG" || fail 'default config is missing the [remote] table'
  grep -Eq '^urls = \[\]$' "$CONFIG" || fail 'default config has an unexpected remote URL default'
  grep -Eq '^timeout_secs = 30$' "$CONFIG" || fail 'default config has an unexpected remote timeout default'
  grep -Eq '^\[asn\]$' "$CONFIG" || fail 'default config is missing the [asn] table'
  grep -Eq '^banned = \[\]$' "$CONFIG" || fail 'default config has an unexpected ASN default'
  grep -Eq '^cache_stale_after_secs = 86400$' "$CONFIG" || fail 'default config has an unexpected ASN cache default'
  grep -Fq '# Add one IP or CIDR entry per line.' "$BLOCKLIST" || fail 'default blocklist header is missing'
}
sets_snapshot() {
  {
    ipset save
    iptables-save | sed -E -e 's/\[[0-9]+:[0-9]+\]//g' -e '/^#/d'
    ip6tables-save | sed -E -e 's/\[[0-9]+:[0-9]+\]//g' -e '/^#/d'
  } > "$STATE/firewall.snapshot"
  sha256sum "$STATE/firewall.snapshot" | awk '{print $1}'
}
ensure_unrelated_sentinels() {
  ipset create E2E-UNRELATED hash:ip -exist
  ipset add E2E-UNRELATED 192.0.2.239 -exist
  iptables -N E2E-UNRELATED-SENTINEL 2>/dev/null || true
  iptables -C INPUT -j E2E-UNRELATED-SENTINEL 2>/dev/null || iptables -I INPUT 1 -j E2E-UNRELATED-SENTINEL
  ip6tables -N E2E-UNRELATED-SENTINEL 2>/dev/null || true
  ip6tables -C INPUT -j E2E-UNRELATED-SENTINEL 2>/dev/null || ip6tables -I INPUT 1 -j E2E-UNRELATED-SENTINEL
}
assert_one_managed_rule() {
  local binary=$1 set_name=$2 chain_rules first_input jump_rule
  chain_rules=$("$binary" -S kidobo-input | sed -n '/^-A kidobo-input /p')
  [[ "$(printf '%s\n' "$chain_rules" | sed '/^$/d' | wc -l)" -eq 1 ]] || fail "$binary managed chain must contain exactly one rule"
  [[ "$chain_rules" == "-A kidobo-input -m set --match-set $set_name src -j DROP" ]] || fail "$binary managed chain does not have the expected set-match DROP rule"
  jump_rule=$("$binary" -S INPUT | grep -Fxc -- '-A INPUT -j kidobo-input' || true)
  [[ "$jump_rule" == 1 ]] || fail "$binary INPUT must contain exactly one managed jump"
  first_input=$("$binary" -S INPUT | sed -n '/^-A INPUT /{p;q;}')
  [[ "$first_input" == '-A INPUT -j kidobo-input' ]] || fail "$binary managed jump is not first in INPUT"
  if "$binary" -S kidobo-input-stage >/dev/null 2>&1; then fail "$binary staging chain remains after successful sync"; fi
}
assert_live_rules() {
  assert_one_managed_rule iptables "$SET4"
  assert_one_managed_rule ip6tables "$SET6"
  assert_unrelated_sentinels
}
sync_and_assert() {
  kidobo sync
  assert_live_rules
}
readonly_state_snapshot() {
  {
    sha256sum "$CONFIG" "$BLOCKLIST" /var/lib/kidobo/temporary-bans.toml
    find /var/cache/kidobo -type f -print0 | sort -z | xargs -0 -r sha256sum
    ipset save
    iptables-save | sed -E -e 's/\[[0-9]+:[0-9]+\]//g' -e '/^#/d'
    ip6tables-save | sed -E -e 's/\[[0-9]+:[0-9]+\]//g' -e '/^#/d'
  } > "$1"
}

test_init_idempotent() {
  local profile=${1:-default}
  e2e_check_start "initialization preserves $profile files" 'repeat init leaves config and source hashes unchanged'
  local files=("$CONFIG" "$BLOCKLIST")
  [[ -f "$CONFIG" && -f "$BLOCKLIST" ]] || fail 'kidobo init did not create required config and blocklist files'
  if [[ -f /var/lib/kidobo/temporary-bans.toml ]]; then
    files+=(/var/lib/kidobo/temporary-bans.toml)
  elif [[ "$mode" == candidate ]]; then
    fail 'candidate kidobo init did not create temporary-bans.toml'
  fi
  sha256sum "${files[@]}" > "$STATE/init-before"
  kidobo init
  sha256sum -c "$STATE/init-before" || fail 'kidobo init changed existing configuration or source files'
  e2e_check_pass "sha256sum verified all files listed in $STATE/init-before"
}
test_bad_checksum() {
  [[ "$mode" == candidate ]] || { printf 'bad checksum test skipped for published-only mode\n'; return; }
  e2e_check_start 'bad checksum rejected' 'installer fails; installed version, binary hash and mode remain unchanged'
  local archive="kidobo-${tag}-linux-x86_64.tar.gz" bad="$ROOT/bad-release"
  [[ -s "$RELEASE/$archive" && -s "$RELEASE/SHA256SUMS" ]] || fail 'candidate archive/checksums missing for checksum test'
  mkdir -p "$bad"
  cp "$RELEASE/$archive" "$bad/$archive"
  printf '%064d  %s\n' 0 "$archive" > "$bad/SHA256SUMS"
  serve_dir "$bad" "$BAD_HTTP_PORT" bad
  local before before_hash before_mode
  before=$(kidobo --version)
  before_hash=$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')
  before_mode=$(stat -c '%a' /usr/local/bin/kidobo)
  printf 'EXPECTED FAILURE: installer with corrupt SHA256SUMS\n' >&9
  if KIDOBO_RELEASE_BASE_URL="http://127.0.0.1:$BAD_HTTP_PORT" "$installer" --version "$tag" > "$STATE/bad-checksum.stdout" 2> "$STATE/bad-checksum.stderr"; then
    fail 'installer accepted a bad candidate checksum'
  else
    printf 'EXPECTED FAILURE observed: corrupt-checksum installer exit status=%s\n' "$?" >&9
  fi
  grep -Eiq "checksum|FAILED|did not match" "$STATE/bad-checksum.stdout" "$STATE/bad-checksum.stderr" || fail 'checksum failure did not identify a checksum rejection'
  [[ "$(kidobo --version)" == "$before" ]] || fail 'bad-checksum install changed the installed binary'
  [[ "$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')" == "$before_hash" ]] || fail 'bad-checksum install changed binary bytes'
  [[ "$(stat -c '%a' /usr/local/bin/kidobo)" == "$before_mode" ]] || fail 'bad-checksum install changed binary mode'
  e2e_check_pass "installer rejected checksum; version=$before sha256=$before_hash mode=$before_mode preserved"
}

start_phase() {
  [[ -s "$STATE/provision.txt" ]] || fail 'start requires a completed provisioning phase'
  start_source_fixture
  if [[ "$mode" == candidate ]]; then serve_dir "$RELEASE" "$HTTP_PORT" release; fi
  defer_timer_until_configuration_is_ready
  e2e_check_start 'installation and initialization' "install $tag; binary owner=root mode=755; default config, source files and systemd units match assertions"
  install_target --init
  assert_installed_binary initial
  assert_init_artifacts
  e2e_check_pass "binary ownership/mode/archive hash and default config/systemd assertions passed; installed $tag"
  test_init_idempotent default
  write_config
  printf '%s\n' "$V4_PEER" "$V6_PEER" > "$BLOCKLIST"
  if [[ "$mode" == candidate ]]; then
    test_init_idempotent custom
  fi
  assert_target_version
  test_bad_checksum
  setup_namespace
  trap capture_namespace_and_cleanup EXIT
  start_traffic_servers
  probe_pair allowed

  # Runtime sync fetches a real local HTTP source and blocks both address families.
  ensure_unrelated_sentinels
  e2e_check_start 'HTTP sync and repeated firewall activation' 'both families blocked; HTTP source members enforced; exact managed wiring and unrelated sentinels preserved'
  sync_and_assert
  # Repeated synchronization must preserve the exact managed wiring and unrelated rules.
  sync_and_assert
  probe_pair blocked
  ipset list "$SET4" | grep -Fq 198.51.100.44 || fail 'HTTP IPv4 source was not enforced'
  ipset list "$SET6" | grep -Fq 2001:db8::44 || fail 'HTTP IPv6 source was not enforced'
  e2e_check_pass 'two syncs preserved exact wiring; IPv4/IPv6 probes blocked; source members 198.51.100.44 and 2001:db8::44 present'

  if [[ "$mode" == published ]]; then
    printf 'COVERAGE OMITTED (published smoke lane): bad checksum, candidate invalid-config/capacity/safelist/source-edit/read-only preservation scenarios; older releases lack candidate contracts\n' >&9
    e2e_check_start 'published doctor and offline lookup' 'doctor succeeds; lookup includes blocked IPv4 peer'
    # The published smoke checks only stable behavior available to older
    # releases: installation/init, HTTP-backed sync, firewall wiring, doctor,
    # and offline lookup. Candidate-only CLI and capacity cases run below.
    kidobo doctor > "$STATE/doctor-published-smoke.json"
    kidobo lookup "$V4_PEER" --format tsv > "$STATE/lookup-published-smoke.tsv"
    grep -Fq "$V4_PEER" "$STATE/lookup-published-smoke.tsv" || fail 'published smoke lookup missed the blocked peer'
    e2e_check_pass "doctor exited 0; lookup-published-smoke.tsv contains $V4_PEER"
    restore_boot_timer
    printf 'started_tag=%s\nmode=%s\n' "$tag" "$mode" > "$STATE/current-release"
    printf 'published smoke passed: %s (HTTP sync and live enforcement verified)\n' "$tag"
    return 0
  fi

  # A parse/preflight failure must preserve the current two-family enforcement.
  e2e_check_start 'invalid configuration preserves enforcement' 'sync fails; IPv4 and IPv6 remain blocked'
  cp -p "$CONFIG" "$STATE/config.good.toml"
  printf '\nunknown_key = true\n' >> "$CONFIG"
  printf 'EXPECTED FAILURE: sync with unknown configuration key\n' >&9
  if kidobo sync > "$STATE/invalid-config.stdout" 2> "$STATE/invalid-config.stderr"; then fail 'invalid configuration unexpectedly synchronized'; else printf 'EXPECTED FAILURE observed: invalid-config sync exit status=%s\n' "$?" >&9; fi
  grep -Fq unknown_key "$STATE/invalid-config.stderr" || fail 'invalid config failed without identifying unknown_key'
  cp -p "$STATE/config.good.toml" "$CONFIG"
  probe_pair blocked
  e2e_check_pass 'invalid-config sync rejected; restored config; both traffic probes remain blocked'

  # Exact safelist entries release only the test traffic source; removing them reapplies it.
  e2e_check_start 'safelist add and removal' 'both families become allowed with safelists and blocked after removal'
  write_config "$V4_PEER" "$V6_PEER"
  sync_and_assert
  probe_pair allowed
  write_config
  sync_and_assert
  probe_pair blocked
  e2e_check_pass 'IPv4/IPv6 probes allowed with safelists, blocked after safelist removal and sync'

  # Exercise a temporary source edit, offline lookup, sync boundary, and removal.
  e2e_check_start 'temporary ban and unban sync boundary' 'source and offline lookup update immediately; enforcement changes only on sync'
  kidobo ban 203.0.113.77 --for 1d
  grep -Fq '203.0.113.77/32' /var/lib/kidobo/temporary-bans.toml || fail 'temporary ban was not persisted'
  kidobo lookup 203.0.113.77 --format tsv > "$STATE/temporary-lookup.tsv"
  grep -Fq 203.0.113.77 "$STATE/temporary-lookup.tsv" || fail 'offline lookup missed the temporary ban'
  if ipset list "$SET4" | grep -Fq 203.0.113.77; then fail 'temporary ban changed enforcement before sync'; fi
  sync_and_assert
  ipset list "$SET4" | grep -Fq 203.0.113.77 || fail 'sync did not enforce the temporary ban'
  kidobo unban 203.0.113.77 --yes
  if grep -Fq 203.0.113.77 /var/lib/kidobo/temporary-bans.toml; then fail 'unban retained the temporary ban'; fi
  ipset list "$SET4" | grep -Fq 203.0.113.77 || fail 'unban changed enforcement before sync'
  sync_and_assert
  if ipset list "$SET4" | grep -Fq 203.0.113.77; then fail 'sync retained the removed temporary ban'; fi
  e2e_check_pass '203.0.113.77 persisted and found offline; live membership changed only after each sync'

  e2e_check_start 'permanent ban and unban sync boundary' 'blocklist updates immediately; enforcement changes only on sync'
  kidobo ban 203.0.113.78
  grep -Fq '203.0.113.78' "$BLOCKLIST" || fail 'permanent ban was not persisted'
  if ipset list "$SET4" | grep -Fq 203.0.113.78; then fail 'permanent ban changed enforcement before sync'; fi
  sync_and_assert
  ipset list "$SET4" | grep -Fq 203.0.113.78 || fail 'sync did not enforce the permanent ban'
  kidobo unban 203.0.113.78 --yes
  if grep -Fq '203.0.113.78' "$BLOCKLIST"; then fail 'unban retained the permanent ban'; fi
  ipset list "$SET4" | grep -Fq 203.0.113.78 || fail 'unban changed enforcement before sync'
  sync_and_assert
  if ipset list "$SET4" | grep -Fq 203.0.113.78; then fail 'sync retained the removed permanent ban'; fi
  e2e_check_pass '203.0.113.78 added/removed in blocklist; live membership changed only after each sync'

  test_asn_resolver

  # Read-only doctor and lookup must leave source files, sets, and firewall rules unchanged.
  e2e_check_start 'offline doctor and lookup preserve runtime' 'readonly-before and readonly-after snapshots match with HTTP source stopped'
  stop_fixture "$STATE/http-source.pid" "$ROOT/traffic.py source $ROOT/fixtures/feed.txt $SOURCE_PORT"
  readonly_state_snapshot "$STATE/readonly-before"
  kidobo doctor > "$STATE/doctor.json"
  kidobo lookup "$V4_PEER" --format tsv > "$STATE/lookup.tsv"
  readonly_state_snapshot "$STATE/readonly-after"
  cmp -s "$STATE/readonly-before" "$STATE/readonly-after" || fail 'doctor or lookup changed runtime state'
  e2e_check_pass "cmp $STATE/readonly-before $STATE/readonly-after exited 0; source, cache and firewall state match"
  start_source_fixture

  # IPv4 is under capacity but differs from the live set; IPv6 alone overflows.
  # This catches an implementation that replaces IPv4 before checking IPv6.
  e2e_check_start 'IPv6 capacity failure preserves both families' 'sync fails; before/after firewall snapshot hashes match'
  cat > "$ROOT/fixtures/feed.txt" <<'EOF'
2001:db8::44
2001:db8::46
EOF
  write_config '' '' 2
  local before after
  before=$(sets_snapshot)
  printf 'EXPECTED FAILURE: IPv6-only capacity overflow during sync\n' >&9
  if kidobo sync > "$STATE/capacity.stdout" 2> "$STATE/capacity.stderr"; then fail 'capacity-limited sync unexpectedly succeeded'; else printf 'EXPECTED FAILURE observed: capacity-limited sync exit status=%s\n' "$?" >&9; fi
  grep -Eiq "IPv6.*(capacity|maxelem)|capacity.*IPv6|maxelem" "$STATE/capacity.stderr" || fail 'capacity rejection did not identify capacity/maxelem'
  after=$(sets_snapshot)
  [[ "$before" == "$after" ]] || fail 'IPv6 capacity failure changed IPv4 or IPv6 sets/firewall rules'
  e2e_check_pass "firewall snapshot hashes match: before=$before after=$after; IPv6 capacity failure rejected"
  cat > "$ROOT/fixtures/feed.txt" <<'EOF'
198.51.100.44
2001:db8::44
EOF
  write_config
  sync_and_assert
  restore_boot_timer

  e2e_check_start 'boot timer enabled and active' 'kidobo-sync.timer enabled and active'
  systemctl is-enabled --quiet kidobo-sync.timer || fail 'kidobo timer is not enabled'
  systemctl is-active --quiet kidobo-sync.timer || fail 'kidobo timer is not active'
  e2e_check_pass 'systemctl is-enabled and is-active both exited 0'
  printf 'started_tag=%s\nmode=%s\n' "$tag" "$mode" > "$STATE/current-release"
  printf 'start phase passed: %s (%s)\n' "$tag" "$mode"
}

wait_for_timer_run() {
  for _ in {1..180}; do
    local started active result status
    started=$(systemctl show kidobo-sync.service --property=ExecMainStartTimestamp --value 2>/dev/null || true)
    active=$(systemctl show kidobo-sync.service --property=ActiveState --value 2>/dev/null || true)
    if [[ "$active" == failed ]]; then fail 'kidobo-sync.service failed after reboot'; fi
    if [[ -n "$started" && "$started" != n/a && "$active" == inactive ]]; then
      result=$(systemctl show kidobo-sync.service --property=Result --value)
      status=$(systemctl show kidobo-sync.service --property=ExecMainStatus --value)
      [[ "$result" == success && "$status" == 0 ]] || fail "timer service failed (result=$result status=$status)"
      return 0
    fi
    sleep 1
  done
  fail 'kidobo-sync.timer did not start its service within 180 seconds after reboot'
}
assert_reboot_preparation() {
  [[ -s "$ROOT/prepared/expected-kernel" && "$(uname -r)" == "$(<"$ROOT/prepared/expected-kernel")" ]] || fail 'application reboot did not retain the intended prepared kernel'
  [[ -s "$ROOT/prepared/selinux-requested" ]] || fail 'application reboot lacks security preparation provenance'
  if [[ "$(<"$ROOT/prepared/selinux-requested")" == enforcing ]]; then
    [[ "$(getenforce)" == Enforcing && ! -e /.autorelabel ]] || fail 'application reboot lost completed enforcing SELinux state'
  fi
}
after_reboot_phase() {
  e2e_check_start 'reboot restores timer enforcement' 'version retained; timer enabled/active; sync service succeeds; both traffic families blocked'
  assert_target_version
  assert_reboot_preparation
  systemctl is-enabled --quiet kidobo-sync.timer || fail 'timer lost enabled state across reboot'
  systemctl is-active --quiet kidobo-sync.timer || fail 'timer is not active after reboot'
  wait_for_timer_run
  ipset test "$SET4" 198.51.100.44 || fail 'boot sync lost cached remote IPv4 entry'
  ipset test "$SET6" 2001:db8::44 || fail 'boot sync lost cached remote IPv6 entry'
  kidobo lookup 198.51.100.44 --format tsv > "$STATE/reboot-remote-lookup.tsv"
  grep -Fxq "$(printf '198.51.100.44\thttp://127.0.0.1:%s/feed.txt\t198.51.100.44/32' "$SOURCE_PORT")" "$STATE/reboot-remote-lookup.tsv" || fail 'boot offline lookup lost remote cache'
  kidobo doctor > "$STATE/doctor-after-reboot.json"
  start_source_fixture
  if [[ "$mode" == candidate ]]; then serve_dir "$RELEASE" "$HTTP_PORT" release-after-reboot; fi
  setup_namespace
  trap capture_namespace_and_cleanup EXIT
  start_traffic_servers
  probe_pair blocked
  # Firewall rules and ipsets are volatile across reboot; recreate only the
  # test-owned sentinels before asserting post-reboot sync preservation.
  ensure_unrelated_sentinels
  sync_and_assert
  probe_pair blocked
  printf 'after-reboot phase passed: %s (timer fired)\n' "$tag"
  e2e_check_pass "version=$tag; timer fired successfully; repeated sync preserved wiring; IPv4/IPv6 probes blocked"
}

configure_baseline_sources() {
  python3 - "$CONFIG" "$SET4" "$SET6" "$SOURCE_PORT" <<'PYCONFIG'
import re
import sys
from pathlib import Path
path = Path(sys.argv[1])
updates = {
    "ipset": {"set_name": f'"{sys.argv[2]}"', "set_name_v6": f'"{sys.argv[3]}"', "enable_ipv6": "true", "chain_action": '"DROP"'},
    "safe": {"ips": "[]", "include_github_meta": "false"},
    "remote": {"urls": f'["http://127.0.0.1:{sys.argv[4]}/feed.txt"]'},
    "asn": {"banned": "[]"},
}
section = ""
seen = set()
sections = set()
lines = []
def complete_section():
    for name, value in updates.get(section, {}).items():
        if (section, name) not in seen:
            lines.append(f"{name} = {value}")
            seen.add((section, name))
for line in path.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"\s*\[([^]]+)\]\s*", line)
    if match:
        complete_section()
        section = match.group(1)
        sections.add(section)
    key = re.match(r"\s*([a-z0-9_]+)\s*=", line)
    if key and key.group(1) in updates.get(section, {}):
        name = key.group(1)
        line = f"{name} = {updates[section][name]}"
        seen.add((section, name))
    lines.append(line)
complete_section()
if not set(updates).issubset(sections):
    raise SystemExit(f"baseline config lacks expected stable tables: {set(updates) - sections}")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PYCONFIG
}
assert_remote_lookup() {
  local label=$1 address=$2 cidr=$3
  kidobo lookup "$address" --format tsv > "$STATE/$label.tsv"
  grep -Fxq "$(printf '%s\thttp://127.0.0.1:%s/feed.txt\t%s' "$address" "$SOURCE_PORT" "$cidr")" "$STATE/$label.tsv" || fail "exact cached remote lookup failed: $label"
}
install_frozen_baseline() {
  local baseline_tag=$1 directory="$ROOT/baseline-bin"
  mkdir -p "$directory"
  printf '#!/usr/bin/env bash\nexec python3 %q baseline-download %q %q "$@"\n' "$ROOT/traffic.py" "$BASELINE" "$baseline_tag" > "$directory/curl"
  chmod 0755 "$directory/curl"
  env -u KIDOBO_RELEASE_BASE_URL PATH="$directory:$PATH" "$BASELINE/installer.sh" --version "$baseline_tag" --init
}
create_recovered_baseline_cache() {
  local isolated="$ROOT/baseline-cache-root" fake="$ROOT/baseline-cache-bin" name
  mkdir -p "$isolated/config" "$isolated/data" "$fake"
  cp -p "$CONFIG" "$isolated/config/config.toml"
  cp -p "$BLOCKLIST" "$isolated/data/blocklist.txt"
  for name in ipset iptables ip6tables; do
    printf '#!/usr/bin/env bash\nexec python3 %q baseline-firewall %q "${0##*/}" "$@"\n' "$ROOT/traffic.py" "$isolated" > "$fake/$name"
    chmod 0755 "$fake/$name"
  done
  # Only the old binary's cache writer uses these fakes, inside a separate root.
  # The candidate and the guest's live firewall never see this PATH.
  KIDOBO_ROOT="$isolated" PATH="$fake:$PATH" /usr/local/bin/kidobo sync > "$STATE/baseline-cache-generation.stdout" 2> "$STATE/baseline-cache-generation.stderr"
  [[ -n "$(find "$isolated/cache/remote" -type f -print -quit)" ]] || fail 'recovered baseline did not generate a cache'
  rm -rf /var/cache/kidobo/remote
  cp -a "$isolated/cache/remote" /var/cache/kidobo/remote
  printf 'generator=%s\nroot=%s\nfirewall=isolated-fakes-only\n' "$(kidobo --version)" "$isolated" > "$STATE/baseline-cache-provenance.txt"
  find "$isolated/cache/remote" -type f -print0 | sort -z | xargs -0 -r sha256sum >> "$STATE/baseline-cache-provenance.txt"
}
test_candidate_temporary_reinstall() {
  e2e_check_start 'candidate reinstall preserves temporary bans' 'nonempty temporary state and exact offline lookup survive binary reinstall and remain enforceable'
  local target=203.0.113.79 preserved="$STATE/reinstall-temporary-bans.toml"
  kidobo ban "$target" --for 1d
  cp -p /var/lib/kidobo/temporary-bans.toml "$preserved"
  install_target
  assert_target_version
  assert_installed_binary reinstalled
  cmp -s "$preserved" /var/lib/kidobo/temporary-bans.toml || fail 'candidate reinstall changed nonempty temporary state'
  kidobo lookup "$target" --format tsv > "$STATE/reinstall-temporary-lookup.tsv"
  grep -Fxq "$(printf '%s\ttemporary:blocklist\t%s/32' "$target" "$target")" "$STATE/reinstall-temporary-lookup.tsv" || fail 'candidate reinstall lost the active temporary lookup'
  sync_and_assert
  ipset test "$SET4" "$target" || fail 'reinstalled candidate did not enforce temporary ban'
  e2e_check_pass 'nonempty temporary file preserved byte-for-byte; exact offline lookup and enforcement passed'
}
upgrade_phase() {
  e2e_check_start 'baseline to target upgrade preserves data' 'old binary generates config, permanent bans and cache; binary upgrade preserves them and works offline before refresh'
  start_source_fixture
  if [[ "$mode" == candidate ]]; then serve_dir "$RELEASE" "$HTTP_PORT" release-upgrade; fi
  [[ -s "$ROOT/baseline-tag" ]] || fail 'runner must capture baseline-tag'
  local baseline_tag baseline_archive baseline_hash installed_hash
  baseline_tag=$(<"$ROOT/baseline-tag")
  [[ "$baseline_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ && "$baseline_tag" != "$tag" ]] || fail 'invalid or equal baseline tag'
  baseline_archive="$BASELINE/kidobo-${baseline_tag}-linux-x86_64.tar.gz"
  [[ -s "$baseline_archive" && -s "$BASELINE/SHA256SUMS" && -x "$BASELINE/installer.sh" ]] || fail 'captured baseline assets are incomplete'
  (cd "$BASELINE"; awk -v archive="${baseline_archive##*/}" '$2 == archive { print }' SHA256SUMS | sha256sum -c -) || fail 'captured baseline checksum mismatch'
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  "$installer" --uninstall
  # Uninstall removes the deferral directory, so establish it again before old init.
  clear_timer_deferral
  defer_timer_until_configuration_is_ready
  install_frozen_baseline "$baseline_tag"
  [[ "$(kidobo --version)" == "kidobo ${baseline_tag#v}" ]] || fail 'captured baseline version did not install'
  assert_installed_binary baseline
  baseline_hash=$(tar -xzOf "$baseline_archive" "kidobo-${baseline_tag}-linux-x86_64/kidobo" | sha256sum | awk '{print $1}')
  installed_hash=$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')
  [[ "$baseline_hash" == "$installed_hash" ]] || fail 'installed baseline differs from frozen archive member'
  printf '%s  baseline-binary\n' "$baseline_hash" > "$STATE/baseline-binary.sha256"
  assert_systemd_units
  configure_baseline_sources
  kidobo ban "$V4_PEER"
  kidobo ban "$V6_PEER"
  kidobo ban --help > "$STATE/baseline-ban-help.txt"
  local preserved_config="$STATE/upgrade-config.toml" preserved_blocklist="$STATE/upgrade-blocklist.txt"
  local preserved_temporary=- temporary_supported=false
  if grep -Eq -- '(^|[[:space:]])--for([[:space:]]|$)' "$STATE/baseline-ban-help.txt"; then
    temporary_supported=true
    kidobo ban 203.0.113.79 --for 1d
    preserved_temporary="$STATE/upgrade-temporary-bans.toml"
    cp -p /var/lib/kidobo/temporary-bans.toml "$preserved_temporary"
  else
    [[ ! -e /var/lib/kidobo/temporary-bans.toml ]] || fail 'legacy baseline unexpectedly created temporary state'
  fi
  printf '{"tag":"%s","temporary_bans":%s}\n' "$baseline_tag" "$temporary_supported" > "$STATE/baseline-capabilities.json"
  cp -p "$CONFIG" "$preserved_config"
  cp -p "$BLOCKLIST" "$preserved_blocklist"
  setup_namespace
  trap capture_namespace_and_cleanup EXIT
  start_traffic_servers
  run_baseline_enforcement_check "$baseline_tag" "$preserved_config" "$preserved_blocklist" "$preserved_temporary" /var/lib/kidobo/temporary-bans.toml
  if [[ -s "$STATE/upgrade-recovery.txt" ]]; then create_recovered_baseline_cache; fi
  assert_remote_lookup baseline-remote-v4 198.51.100.44 198.51.100.44/32
  assert_remote_lookup baseline-remote-v6 2001:db8::44 2001:db8::44/128
  find /var/cache/kidobo/remote -type f -print0 | sort -z | xargs -0 -r sha256sum > "$STATE/upgrade-cache-before.sha256"
  stop_fixture "$STATE/http-source.pid" "$ROOT/traffic.py source $ROOT/fixtures/feed.txt $SOURCE_PORT"
  install_target
  assert_target_version
  assert_installed_binary upgraded
  cmp -s "$preserved_config" "$CONFIG" || fail 'binary upgrade changed baseline-generated config'
  cmp -s "$preserved_blocklist" "$BLOCKLIST" || fail 'binary upgrade changed baseline-generated blocklist'
  sha256sum -c "$STATE/upgrade-cache-before.sha256" || fail 'binary upgrade changed old remote-cache bytes'
  if [[ "$preserved_temporary" != - ]]; then
    cmp -s "$preserved_temporary" /var/lib/kidobo/temporary-bans.toml || fail 'binary upgrade changed baseline temporary data'
    kidobo lookup 203.0.113.79 --format tsv > "$STATE/upgrade-temporary-lookup.tsv"
    grep -Fxq "$(printf '203.0.113.79\ttemporary:blocklist\t203.0.113.79/32')" "$STATE/upgrade-temporary-lookup.tsv" || fail 'binary upgrade lost baseline temporary lookup'
  else
    [[ ! -e /var/lib/kidobo/temporary-bans.toml ]] || fail 'binary-only legacy upgrade unexpectedly created temporary state'
  fi
  assert_remote_lookup upgraded-remote-v4 198.51.100.44 198.51.100.44/32
  assert_remote_lookup upgraded-remote-v6 2001:db8::44 2001:db8::44/128
  sync_and_assert
  ipset test "$SET4" 198.51.100.44 || fail 'offline upgraded sync lost old remote IPv4 cache'
  ipset test "$SET6" 2001:db8::44 || fail 'offline upgraded sync lost old remote IPv6 cache'
  if [[ "$preserved_temporary" != - ]]; then
    ipset test "$SET4" 203.0.113.79 || fail 'offline upgraded sync lost the baseline-generated temporary ban'
  fi
  probe_pair blocked
  start_source_fixture
  # Initialize only after proving binary-only upgrade compatibility, including missing temporary state.
  kidobo init
  test_candidate_temporary_reinstall
  restore_boot_timer
  kidobo doctor > "$STATE/doctor-after-upgrade.json"
  printf 'upgrade phase passed: baseline %s -> target %s with baseline-generated files and cache retained\n' "$baseline_tag" "$tag"
  e2e_check_pass "baseline=$baseline_tag target=$tag; old files/cache preserved; exact IPv4/IPv6 lookup and enforcement succeeded with source stopped"
}

assert_enforcement_absent() {
  if ipset list "$SET4" >/dev/null 2>&1 || ipset list "$SET6" >/dev/null 2>&1; then fail 'managed ipset remains after cleanup'; fi
  if ipset save | grep -Eq '^create kidobo-e2e(-v6)?-[[:xdigit:]]{8} '; then fail 'temporary managed ipset remains after cleanup'; fi
  if iptables -C INPUT -j kidobo-input >/dev/null 2>&1 || ip6tables -C INPUT -j kidobo-input >/dev/null 2>&1; then fail 'managed firewall jump remains after cleanup'; fi
  if iptables -S kidobo-input >/dev/null 2>&1 || ip6tables -S kidobo-input >/dev/null 2>&1 || \
     iptables -S kidobo-input-stage >/dev/null 2>&1 || ip6tables -S kidobo-input-stage >/dev/null 2>&1; then
    fail 'managed firewall chain remains after cleanup'
  fi
}
assert_no_managed_runtime() {
  assert_enforcement_absent
  [[ ! -e /etc/systemd/system/kidobo-sync.timer && ! -e /etc/systemd/system/kidobo-sync.service ]] || fail 'managed systemd units remain after uninstall'
  [[ ! -e "$CONFIG" && ! -e "$BLOCKLIST" && ! -e /var/lib/kidobo/temporary-bans.toml ]] || fail 'managed runtime files remain after uninstall'
  [[ ! -e /etc/kidobo && ! -e /var/lib/kidobo ]] || fail 'managed config or data directory remains after uninstall'
  [[ ! -e /var/cache/kidobo ]] || fail 'managed cache directory remains after uninstall'
  [[ ! -e /usr/local/bin/kidobo ]] || fail 'kidobo binary remains after uninstall'
  if systemctl is-enabled --quiet kidobo-sync.timer || systemctl is-active --quiet kidobo-sync.timer; then
    fail 'managed timer remains enabled or active after uninstall'
  fi
}
assert_unrelated_sentinels() {
  ipset list E2E-UNRELATED | grep -Fq 192.0.2.239 || fail 'cleanup removed/changed unrelated ipset'
  iptables -C INPUT -j E2E-UNRELATED-SENTINEL || fail 'cleanup removed unrelated IPv4 firewall wiring'
  ip6tables -C INPUT -j E2E-UNRELATED-SENTINEL || fail 'cleanup removed unrelated IPv6 firewall wiring'
}
debian12_baseline_recovery_allowed() {
  local baseline_tag=$1 os_release_file=${2:-/etc/os-release}
  local iptables_version=${3:-$(iptables --version)}
  local ip6tables_version=${4:-$(ip6tables --version)}
  [[ "$baseline_tag" == v0.14.2 || "$baseline_tag" == v0.14.3 ]] || return 1
  [[ -r "$os_release_file" ]] || return 1
  local ID= VERSION_ID=
  # shellcheck disable=SC1090
  . "$os_release_file"
  [[ "$ID" == debian && "$VERSION_ID" == 12 ]] || return 1
  [[ "$iptables_version" == 'iptables v1.8.9 (nf_tables)' ]] || return 1
  [[ "$ip6tables_version" == 'ip6tables v1.8.9 (nf_tables)' ]]
}
baseline_missing_chain_diagnostic_matches() {
  local status=$1 stderr_file=$2
  [[ "$status" == 1 && -r "$stderr_file" ]] || return 1
  local expected="firewall operation failed: firewall command failed \`iptables -w 5 -S kidobo-input\` with status Exited(1): iptables v1.8.9 (nf_tables): chain \`kidobo-input' in table \`filter' is incompatible, use 'nft' tool."
  grep -Fxq -- "$expected" "$stderr_file"
}
capture_upgrade_firewall_evidence() {
  local output=$1
  printf '%s\n' '=== ipset save ===' > "$output" || fail "could not write firewall evidence: $output"
  ipset save >> "$output" 2>&1 || fail "ipset save failed while capturing firewall evidence: $output"
  printf '%s\n' '=== iptables-save ===' >> "$output" || fail "could not write firewall evidence: $output"
  iptables-save >> "$output" 2>&1 || fail "iptables-save failed while capturing firewall evidence: $output"
  printf '%s\n' '=== ip6tables-save ===' >> "$output" || fail "could not write firewall evidence: $output"
  ip6tables-save >> "$output" 2>&1 || fail "ip6tables-save failed while capturing firewall evidence: $output"
}
assert_no_managed_firewall_jumps() {
  local binary output
  for binary in iptables-save ip6tables-save; do
    output=$("$binary") || fail "$binary failed while checking baseline enforcement state"
    if grep -Eq '^-A INPUT (.* )?-j kidobo-input(-stage)?([[:space:]]|$)' <<< "$output"; then
      fail "$binary shows active Kidobo enforcement after the known baseline failure"
    fi
  done
}
run_baseline_enforcement_check() {
  local baseline_tag=$1 preserved_config=$2 preserved_blocklist=$3 preserved_temporary=$4 temporary_bans=$5
  local baseline_sync_status=0
  e2e_check_start 'published baseline enforcement' 'dual-stack enforcement succeeds, or exact documented Debian 12 baseline recovery preserves state'
  ensure_unrelated_sentinels
  capture_upgrade_firewall_evidence "$STATE/baseline-firewall-before.txt"
  kidobo sync > "$STATE/baseline-sync.stdout" 2> "$STATE/baseline-sync.stderr" || baseline_sync_status=$?
  printf '%s\n' "$baseline_sync_status" > "$STATE/baseline-sync.status"
  printf 'BASELINE SYNC: observed exit status=%s; stdout follows\n' "$baseline_sync_status" >&9
  printf '{"profile":"%s","status":%s}\n' "$([[ "$baseline_sync_status" == 0 ]] && printf live || printf recovery-candidate)" "$baseline_sync_status" > "$STATE/baseline-enforcement-profile.json"
  cat "$STATE/baseline-sync.stdout" >&9
  printf '\nBASELINE SYNC: stderr follows\n' >&9
  cat "$STATE/baseline-sync.stderr" >&9
  if [[ "$baseline_sync_status" == 0 ]]; then
    assert_live_rules
    probe_pair blocked
    e2e_check_pass 'baseline sync exited 0; exact managed rules verified; IPv4/IPv6 probes blocked'
    return 0
  fi
  if ! debian12_baseline_recovery_allowed "$baseline_tag" || \
     ! baseline_missing_chain_diagnostic_matches "$baseline_sync_status" "$STATE/baseline-sync.stderr"; then
    fail "published baseline sync failed unexpectedly (status=$baseline_sync_status); see $STATE/baseline-sync.stderr"
  fi
  printf '{"profile":"known-debian12-recovery","status":%s}\n' "$baseline_sync_status" > "$STATE/baseline-enforcement-profile.json"
  capture_upgrade_firewall_evidence "$STATE/baseline-firewall-after.txt"
  cmp -s "$preserved_config" "$CONFIG" || fail 'known baseline sync failure changed configuration'
  cmp -s "$preserved_blocklist" "$BLOCKLIST" || fail 'known baseline sync failure changed blocklist data'
  if [[ "$preserved_temporary" != - ]]; then cmp -s "$preserved_temporary" "$temporary_bans" || fail 'known baseline sync failure changed temporary-ban data'; fi
  assert_unrelated_sentinels
  assert_no_managed_firewall_jumps
  probe_pair allowed
  printf '%s\n' \
    "baseline recovery: $baseline_tag sync failed with the known Debian 12 iptables 1.8.9 nftables missing-chain diagnostic; evidence saved under $STATE; candidate enforcement is required next" \
    | tee "$STATE/upgrade-recovery.txt"
  e2e_check_pass "KNOWN BASELINE RECOVERY: $baseline_tag sync status=$baseline_sync_status matched exact Debian 12 diagnostic; config/blocklist and applicable temporary state match; unrelated sentinels intact; no managed jumps; candidate enforcement required next"
}
test_uninstall_failure_preserves_runtime() {
  e2e_check_start 'failed uninstall preserves runtime' 'invalid-config uninstall fails; timer, binary hash, runtime files and exact dual-stack enforcement retained before repair'
  local before_hash before_firewall
  cp -p "$CONFIG" "$STATE/finish-config.good.toml"
  before_hash=$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  before_firewall=$(sets_snapshot)
  printf '\nunknown_key = true\n' >> "$CONFIG"
  printf 'EXPECTED FAILURE: uninstall with invalid runtime configuration\n' >&9
  if "$installer" --uninstall > "$STATE/failed-uninstall.stdout" 2> "$STATE/failed-uninstall.stderr"; then fail 'uninstall unexpectedly succeeded with invalid runtime configuration'; else printf 'EXPECTED FAILURE observed: invalid-config uninstall exit status=%s\n' "$?" >&9; fi
  grep -Fq unknown_key "$STATE/failed-uninstall.stdout" "$STATE/failed-uninstall.stderr" || fail 'failed uninstall did not identify invalid configuration'
  systemctl is-active --quiet kidobo-sync.timer || fail 'failed uninstall did not restore the active timer'
  [[ -x /usr/local/bin/kidobo && -s "$CONFIG" && -s "$BLOCKLIST" ]] || fail 'failed uninstall removed runtime files or binary'
  [[ "$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')" == "$before_hash" ]] || fail 'failed uninstall changed binary bytes'
  ipset list "$SET4" >/dev/null && ipset list "$SET6" >/dev/null || fail 'failed uninstall removed managed ipsets'
  [[ "$(sets_snapshot)" == "$before_firewall" ]] || fail 'failed uninstall changed live firewall enforcement'
  probe_pair blocked
  cp -p "$STATE/finish-config.good.toml" "$CONFIG"
  sync_and_assert
  restore_boot_timer
  e2e_check_pass "uninstall rejected; timer active, binary sha256=$before_hash retained; firewall snapshot unchanged and both probes blocked before repair; config restored"
}
finish_phase() {
  stop_fixture "$STATE/http-release.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-release-upgrade.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-release-after-reboot.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-bad.pid" "$ROOT/bad-release $BAD_HTTP_PORT"
  start_source_fixture
  ensure_unrelated_sentinels
  setup_namespace
  trap capture_namespace_and_cleanup EXIT
  start_traffic_servers

  test_uninstall_failure_preserves_runtime
  e2e_check_start 'cache-only flush preserves enforcement' 'cache files removed; remote directory and sync lock inode retained; IPv4/IPv6 still blocked'
  local sync_lock_inode
  sync_lock_inode=$(stat -c '%i' /var/cache/kidobo/sync.lock)
  kidobo flush --cache-only
  probe_pair blocked
  [[ -d /var/cache/kidobo/remote ]] || fail 'cache-only flush removed the remote cache directory'
  [[ -z "$(find /var/cache/kidobo/remote -type f -print -quit)" ]] || fail 'cache-only flush retained remote cache files'
  [[ "$(stat -c '%i' /var/cache/kidobo/sync.lock)" == "$sync_lock_inode" ]] || fail 'cache-only flush replaced the sync lock file'
  e2e_check_pass "remote cache empty; directory retained; sync lock inode=$sync_lock_inode unchanged; both probes blocked"
  e2e_check_start 'flush removes only managed enforcement' 'managed sets/chains absent; both families allowed; unrelated sentinels retained'
  kidobo flush
  probe_pair allowed
  assert_enforcement_absent
  assert_unrelated_sentinels
  e2e_check_pass 'managed sets/chains absent; both probes allowed; unrelated IPv4/IPv6 sentinels present'

  # Reapply enforcement before the successful installer uninstall path.
  e2e_check_start 'successful uninstall removes managed runtime' 'reapplied enforcement verified; uninstall removes binary, data, cache, units and wiring; unrelated sentinels retained'
  sync_and_assert
  ipset list "$SET4" >/dev/null || fail 'sync did not restore managed IPv4 set'
  ipset list "$SET6" >/dev/null || fail 'sync did not restore managed IPv6 set'
  probe_pair blocked
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  "$installer" --uninstall
  clear_timer_deferral
  probe_pair allowed
  assert_no_managed_runtime
  assert_unrelated_sentinels
  e2e_check_pass 'binary/data/cache/units/sets/chains absent; timer inactive; IPv4/IPv6 allowed; unrelated sentinels retained'
  stop_fixture "$STATE/http-source.pid" "$ROOT/traffic.py source $ROOT/fixtures/feed.txt $SOURCE_PORT"
  printf 'finished tag=%s\n' "$tag" > "$STATE/finished"
  printf 'finish phase passed; failed uninstall preserved runtime and cleanup retained unrelated sentinels\n'
}

case "$phase" in
  start) start_phase ;;
  after-reboot) after_reboot_phase ;;
  upgrade) upgrade_phase ;;
  finish) finish_phase ;;
  *) fail "unknown phase: $phase" ;;
esac
