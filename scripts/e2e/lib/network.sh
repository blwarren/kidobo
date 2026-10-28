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

probe() {
  local family=$1 address=$2 expectation=$3 output="$STATE/probe-single.json" before=0 after=0
  local source=$V4_PEER binary=iptables set_name=$SET4
  if [[ "$family" == IPv6 ]]; then source=$V6_PEER; binary=ip6tables; set_name=$SET6; fi
  if [[ "$expectation" == blocked ]]; then before=$(managed_drop_packets "$binary" "$set_name"); fi
  probe_raw "$address" "$source" "$output"
  if [[ "$expectation" == blocked ]]; then after=$(managed_drop_packets "$binary" "$set_name"); fi
  probe_observation "$family" "$address" "$source" "$expectation" "$output" "$before" "$after"
}
