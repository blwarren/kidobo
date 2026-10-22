#!/usr/bin/env bash
set -euo pipefail

readonly ROOT=/opt/kidobo-e2e MARKER=/etc/kidobo-e2e-owned
readonly MARKER_CONTENT=kidobo-e2e-v1
readonly RELEASE="$ROOT/release" BASELINE="$ROOT/baseline" STATE="$ROOT/state"
readonly TEST_NS=kidobo-e2e HOST_IF=ke2eh0 PEER_IF=ke2ep0
readonly V4_HOST=198.18.77.1 V4_PEER=198.18.77.2
readonly V6_HOST=fd42:6b69:646f:626f::1 V6_PEER=fd42:6b69:646f:626f::2
readonly TRAFFIC_PORT=39471 HTTP_PORT=39472 BAD_HTTP_PORT=39473 SOURCE_PORT=39474
readonly CONFIG=/etc/kidobo/config.toml BLOCKLIST=/var/lib/kidobo/blocklist.txt
readonly SET4=kidobo-e2e SET6=kidobo-e2e-v6

fail() { printf 'e2e lifecycle: %s\n' "$*" >&2; exit 1; }
[[ -f "$MARKER" ]] || fail "missing guest ownership marker $MARKER"
cmp -s "$MARKER" <(printf '%s\n' "$MARKER_CONTENT") || fail "invalid guest ownership marker content in $MARKER"
[[ ! -e /run/systemd/container ]] || fail 'refusing to run inside a container; E2E requires a VM'
[[ $# -eq 3 ]] || fail 'usage: lifecycle.sh PHASE TAG MODE(candidate|published)'
phase=$1 tag=$2 mode=$3
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || fail "invalid release tag: $tag"
[[ "$mode" == candidate || "$mode" == published ]] || fail "invalid mode: $mode"
installer="$RELEASE/installer.sh"
[[ -x "$installer" ]] || fail "missing executable installer $installer"
install_target() {
  if [[ "$mode" == candidate ]]; then
    KIDOBO_RELEASE_BASE_URL="http://127.0.0.1:$HTTP_PORT" "$installer" --version "$tag" "$@"
  else
    env -u KIDOBO_RELEASE_BASE_URL "$installer" --version "$tag" "$@"
  fi
}

serve_dir() {
  local directory=$1 port=$2 label=$3
  if [[ -s "$directory/SHA256SUMS" ]] && cmp -s "$directory/SHA256SUMS" <(curl -fsS "http://127.0.0.1:$port/SHA256SUMS" 2>/dev/null); then return 0; fi
  python3 -m http.server --bind 127.0.0.1 --directory "$directory" "$port" >"$STATE/http-$label.log" 2>&1 &
  printf '%s\n' "$!" > "$STATE/http-$label.pid"
  for _ in {1..50}; do
    if curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  fail "HTTP fixture failed to start: $label"
}
start_source_fixture() {
  mkdir -p "$ROOT/fixtures"
  cat > "$ROOT/fixtures/feed.txt" <<EOF
198.51.100.44
2001:db8::44
EOF
  if cmp -s "$ROOT/fixtures/feed.txt" <(curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" 2>/dev/null); then return 0; fi
  stop_fixture "$STATE/http-source.pid" "$ROOT/fixtures $SOURCE_PORT"
  python3 -m http.server --bind 127.0.0.1 --directory "$ROOT/fixtures" "$SOURCE_PORT" >"$STATE/http-source.log" 2>&1 &
  printf '%s\n' "$!" > "$STATE/http-source.pid"
  for _ in {1..50}; do
    if curl -fsS "http://127.0.0.1:$SOURCE_PORT/feed.txt" >/dev/null 2>&1; then return 0; fi
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
  printf '[Timer]\nOnBootSec=1h\n' > "$dropin"
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
setup_namespace() {
  ensure_clean_namespace
  ip netns add "$TEST_NS"
  ip link add "$HOST_IF" type veth peer name "$PEER_IF"
  ip link set "$PEER_IF" netns "$TEST_NS"
  ip addr add "$V4_HOST/30" dev "$HOST_IF"
  ip -6 addr add "$V6_HOST/64" dev "$HOST_IF" nodad
  ip link set "$HOST_IF" up
  ip netns exec "$TEST_NS" ip addr add "$V4_PEER/30" dev "$PEER_IF"
  ip netns exec "$TEST_NS" ip -6 addr add "$V6_PEER/64" dev "$PEER_IF" nodad
  ip netns exec "$TEST_NS" ip link set lo up
  ip netns exec "$TEST_NS" ip link set "$PEER_IF" up
  ip netns exec "$TEST_NS" ip route add default via "$V4_HOST"
  ip netns exec "$TEST_NS" ip -6 route add default via "$V6_HOST"
}
start_traffic_servers() {
  stop_fixture "$STATE/server-v4.pid" "$ROOT/traffic.py serve $V4_HOST $TRAFFIC_PORT"
  stop_fixture "$STATE/server-v6.pid" "$ROOT/traffic.py serve $V6_HOST $TRAFFIC_PORT"
  python3 "$ROOT/traffic.py" serve "$V4_HOST" "$TRAFFIC_PORT" >"$STATE/server-v4.log" 2>&1 &
  printf '%s\n' "$!" > "$STATE/server-v4.pid"
  python3 "$ROOT/traffic.py" serve "$V6_HOST" "$TRAFFIC_PORT" >"$STATE/server-v6.log" 2>&1 &
  printf '%s\n' "$!" > "$STATE/server-v6.pid"
  sleep 1
}
probe() {
  local family=$1 address=$2 expectation=$3
  if ip netns exec "$TEST_NS" python3 "$ROOT/traffic.py" probe "$address" "$TRAFFIC_PORT"; then
    [[ "$expectation" == allowed ]] || fail "$family traffic unexpectedly passed; expected blocked"
  else
    [[ "$expectation" == blocked ]] || fail "$family traffic failed; expected allowed"
  fi
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
}
test_bad_checksum() {
  [[ "$mode" == candidate ]] || { printf 'bad checksum test skipped for published-only mode\n'; return; }
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
  if KIDOBO_RELEASE_BASE_URL="http://127.0.0.1:$BAD_HTTP_PORT" "$installer" --version "$tag"; then
    fail 'installer accepted a bad candidate checksum'
  fi
  [[ "$(kidobo --version)" == "$before" ]] || fail 'bad-checksum install changed the installed binary'
  [[ "$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')" == "$before_hash" ]] || fail 'bad-checksum install changed binary bytes'
  [[ "$(stat -c '%a' /usr/local/bin/kidobo)" == "$before_mode" ]] || fail 'bad-checksum install changed binary mode'
}

os_upgrade_phase() {
  [[ -s "$STATE/provision.txt" ]] || fail 'OS upgrade requires provisioning metadata'
  local family
  family=$(sed -n 's/^family=//p' "$STATE/provision.txt")
  # Several package managers use 102/103 to report a completed transaction
  # that requires reboot. Record and accept those statuses; the host runner
  # reboots before running the post-upgrade kernel checks.
  run_upgrade() {
    local rc=0
    "$@" || rc=$?
    case "$rc" in
      0) ;;
      102|103) printf 'package_manager_reboot_status=%s\n' "$rc" >> "$STATE/provision.txt" ;;
      *) return "$rc" ;;
    esac
  }
  case "$family" in
    apt) export DEBIAN_FRONTEND=noninteractive; apt-get -o APT::Update::Error-Mode=any update; run_upgrade apt-get -y full-upgrade ;;
    dnf|dnf-epel) run_upgrade dnf -y --refresh upgrade ;;
    zypper) zypper --non-interactive refresh; run_upgrade zypper --non-interactive update ;;
    *) fail "unknown recorded package family: $family" ;;
  esac
  case "$family" in
    apt) dpkg-query -W -f='${binary:Package}=${Version}\n' | sort > "$STATE/packages.txt" ;;
    *) rpm -qa --qf '%{NAME}=%{EVR}\n' | sort > "$STATE/packages.txt" ;;
  esac
  printf 'os_upgrade_completed_utc=%s\n' "$(date -u +%FT%TZ)" >> "$STATE/provision.txt"
  printf 'OS update completed for %s; runner must reboot then invoke bash /opt/kidobo-e2e/provision.sh --check-kernel\n' "$family"
}

start_phase() {
  [[ -s "$STATE/provision.txt" ]] || fail 'start requires a completed provisioning phase'
  start_source_fixture
  if [[ "$mode" == candidate ]]; then serve_dir "$RELEASE" "$HTTP_PORT" release; fi
  defer_timer_until_configuration_is_ready
  install_target --init
  assert_installed_binary initial
  assert_init_artifacts
  test_init_idempotent
  write_config
  printf '%s\n' "$V4_PEER" "$V6_PEER" > "$BLOCKLIST"
  assert_target_version
  test_bad_checksum
  setup_namespace
  trap cleanup_namespace EXIT
  start_traffic_servers
  probe IPv4 "$V4_HOST" allowed
  probe IPv6 "$V6_HOST" allowed

  # Runtime sync fetches a real local HTTP source and blocks both address families.
  ensure_unrelated_sentinels
  sync_and_assert
  # Repeated synchronization must preserve the exact managed wiring and unrelated rules.
  sync_and_assert
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  ipset list "$SET4" | grep -Fq 198.51.100.44 || fail 'HTTP IPv4 source was not enforced'
  ipset list "$SET6" | grep -Fq 2001:db8::44 || fail 'HTTP IPv6 source was not enforced'

  if [[ "$mode" == published ]]; then
    # The published smoke checks only stable behavior available to older
    # releases: installation/init, HTTP-backed sync, firewall wiring, doctor,
    # and offline lookup. Candidate-only CLI and capacity cases run below.
    kidobo doctor > "$STATE/doctor-published-smoke.json"
    kidobo lookup "$V4_PEER" --format tsv > "$STATE/lookup-published-smoke.tsv"
    grep -Fq "$V4_PEER" "$STATE/lookup-published-smoke.tsv" || fail 'published smoke lookup missed the blocked peer'
    restore_boot_timer
    printf 'started_tag=%s\nmode=%s\n' "$tag" "$mode" > "$STATE/current-release"
    printf 'published smoke passed: %s (HTTP sync and live enforcement verified)\n' "$tag"
    return 0
  fi

  # A parse/preflight failure must preserve the current two-family enforcement.
  cp -p "$CONFIG" "$STATE/config.good.toml"
  printf '\nunknown_key = true\n' >> "$CONFIG"
  if kidobo sync; then fail 'invalid configuration unexpectedly synchronized'; fi
  cp -p "$STATE/config.good.toml" "$CONFIG"
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked

  # Exact safelist entries release only the test traffic source; removing them reapplies it.
  write_config "$V4_PEER" "$V6_PEER"
  sync_and_assert
  probe IPv4 "$V4_HOST" allowed
  probe IPv6 "$V6_HOST" allowed
  write_config
  sync_and_assert
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked

  # Exercise a temporary source edit, offline lookup, sync boundary, and removal.
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

  # Read-only doctor and lookup must leave source files, sets, and firewall rules unchanged.
  stop_fixture "$STATE/http-source.pid" "$ROOT/fixtures $SOURCE_PORT"
  readonly_state_snapshot "$STATE/readonly-before"
  kidobo doctor > "$STATE/doctor.json"
  kidobo lookup "$V4_PEER" --format tsv > "$STATE/lookup.tsv"
  readonly_state_snapshot "$STATE/readonly-after"
  cmp -s "$STATE/readonly-before" "$STATE/readonly-after" || fail 'doctor or lookup changed runtime state'
  start_source_fixture

  # IPv4 is under capacity but differs from the live set; IPv6 alone overflows.
  # This catches an implementation that replaces IPv4 before checking IPv6.
  cat > "$ROOT/fixtures/feed.txt" <<'EOF'
2001:db8::44
2001:db8::46
EOF
  sleep 2
  write_config '' '' 2
  local before after
  before=$(sets_snapshot)
  if kidobo sync; then fail 'capacity-limited sync unexpectedly succeeded'; fi
  after=$(sets_snapshot)
  [[ "$before" == "$after" ]] || fail 'IPv6 capacity failure changed IPv4 or IPv6 sets/firewall rules'
  cat > "$ROOT/fixtures/feed.txt" <<'EOF'
198.51.100.44
2001:db8::44
EOF
  sleep 2
  write_config
  sync_and_assert
  restore_boot_timer

  systemctl is-enabled --quiet kidobo-sync.timer || fail 'kidobo timer is not enabled'
  systemctl is-active --quiet kidobo-sync.timer || fail 'kidobo timer is not active'
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
after_reboot_phase() {
  assert_target_version
  systemctl is-enabled --quiet kidobo-sync.timer || fail 'timer lost enabled state across reboot'
  systemctl is-active --quiet kidobo-sync.timer || fail 'timer is not active after reboot'
  wait_for_timer_run
  kidobo doctor > "$STATE/doctor-after-reboot.json"
  start_source_fixture
  if [[ "$mode" == candidate ]]; then serve_dir "$RELEASE" "$HTTP_PORT" release-after-reboot; fi
  setup_namespace
  trap cleanup_namespace EXIT
  start_traffic_servers
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  # Firewall rules and ipsets are volatile across reboot; recreate only the
  # test-owned sentinels before asserting post-reboot sync preservation.
  ensure_unrelated_sentinels
  sync_and_assert
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  printf 'after-reboot phase passed: %s (timer fired)\n' "$tag"
}

upgrade_phase() {
  start_source_fixture
  if [[ "$mode" == candidate ]] && ! curl -fsS "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1; then
    serve_dir "$RELEASE" "$HTTP_PORT" release-upgrade
  fi
  [[ -s "$ROOT/baseline-tag" ]] || fail 'runner must write /opt/kidobo-e2e/baseline-tag'
  local baseline_tag baseline_installer="$BASELINE/installer.sh"
  baseline_tag=$(<"$ROOT/baseline-tag")
  [[ "$baseline_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] || fail 'invalid baseline-tag'
  [[ "$baseline_tag" != "$tag" ]] || fail 'baseline-tag must differ from target tag'
  [[ -x "$baseline_installer" ]] || fail "missing baseline installer $baseline_installer"
  [[ -s "$BASELINE/SHA256SUMS" ]] || fail 'baseline release checksums missing'
  local preserved_config="$STATE/upgrade-config.toml" preserved_blocklist="$STATE/upgrade-blocklist.txt"
  local preserved_temporary="$STATE/upgrade-temporary-bans.toml"
  cp -p "$CONFIG" "$preserved_config"
  cp -p "$BLOCKLIST" "$preserved_blocklist"
  cp -p /var/lib/kidobo/temporary-bans.toml "$preserved_temporary"

  # The installer uninstall path is verified separately in finish; this phase
  # performs a baseline install followed by an in-place target binary upgrade.
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  "$installer" --uninstall
  # Use the release installer recovery path for the known systemd
  # reset-failed response seen on a cleanly uninstalled guest.
  env -u KIDOBO_RELEASE_BASE_URL "$baseline_installer" --version "$baseline_tag" --init
  assert_installed_binary baseline
  assert_systemd_units
  cp -p "$preserved_config" "$CONFIG"
  cp -p "$preserved_blocklist" "$BLOCKLIST"
  cp -p "$preserved_temporary" /var/lib/kidobo/temporary-bans.toml
  local baseline_version
  baseline_version=$(kidobo --version)
  [[ "$baseline_version" == "kidobo ${baseline_tag#v}" ]] || fail 'baseline version did not install from published release'

  # Exercise the baseline release against real dual-stack traffic before
  # replacing it with the candidate binary.
  setup_namespace
  trap cleanup_namespace EXIT
  start_traffic_servers
  ensure_unrelated_sentinels
  kidobo sync
  assert_live_rules
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked

  install_target
  assert_target_version
  assert_installed_binary upgraded
  cmp -s "$preserved_config" "$CONFIG" || fail 'binary upgrade changed configuration'
  cmp -s "$preserved_blocklist" "$BLOCKLIST" || fail 'binary upgrade changed blocklist data'
  cmp -s "$preserved_temporary" /var/lib/kidobo/temporary-bans.toml || fail 'binary upgrade changed temporary-ban data'
  restore_boot_timer
  kidobo doctor > "$STATE/doctor-after-upgrade.json"
  sync_and_assert
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  printf 'upgrade phase passed: baseline %s -> target %s with config/data retained\n' "$baseline_tag" "$tag"
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
test_uninstall_failure_preserves_runtime() {
  local before_hash
  cp -p "$CONFIG" "$STATE/finish-config.good.toml"
  before_hash=$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')
  printf '\nunknown_key = true\n' >> "$CONFIG"
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  if "$installer" --uninstall; then fail 'uninstall unexpectedly succeeded with invalid runtime configuration'; fi
  systemctl is-active --quiet kidobo-sync.timer || fail 'failed uninstall did not restore the active timer'
  [[ -x /usr/local/bin/kidobo && -s "$CONFIG" && -s "$BLOCKLIST" ]] || fail 'failed uninstall removed runtime files or binary'
  [[ "$(sha256sum /usr/local/bin/kidobo | awk '{print $1}')" == "$before_hash" ]] || fail 'failed uninstall changed binary bytes'
  ipset list "$SET4" >/dev/null && ipset list "$SET6" >/dev/null || fail 'failed uninstall removed managed ipsets'
  cp -p "$STATE/finish-config.good.toml" "$CONFIG"
  sync_and_assert
  restore_boot_timer
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
}
finish_phase() {
  stop_fixture "$STATE/http-release.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-release-upgrade.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-release-after-reboot.pid" "$RELEASE $HTTP_PORT"
  stop_fixture "$STATE/http-bad.pid" "$ROOT/bad-release $BAD_HTTP_PORT"
  start_source_fixture
  ensure_unrelated_sentinels
  setup_namespace
  trap cleanup_namespace EXIT
  start_traffic_servers

  test_uninstall_failure_preserves_runtime
  local sync_lock_inode
  sync_lock_inode=$(stat -c '%i' /var/cache/kidobo/sync.lock)
  kidobo flush --cache-only
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  [[ -d /var/cache/kidobo/remote ]] || fail 'cache-only flush removed the remote cache directory'
  [[ -z "$(find /var/cache/kidobo/remote -type f -print -quit)" ]] || fail 'cache-only flush retained remote cache files'
  [[ "$(stat -c '%i' /var/cache/kidobo/sync.lock)" == "$sync_lock_inode" ]] || fail 'cache-only flush replaced the sync lock file'
  kidobo flush
  probe IPv4 "$V4_HOST" allowed
  probe IPv6 "$V6_HOST" allowed
  assert_enforcement_absent
  assert_unrelated_sentinels

  # Reapply enforcement before the successful installer uninstall path.
  sync_and_assert
  ipset list "$SET4" >/dev/null || fail 'sync did not restore managed IPv4 set'
  ipset list "$SET6" >/dev/null || fail 'sync did not restore managed IPv6 set'
  probe IPv4 "$V4_HOST" blocked
  probe IPv6 "$V6_HOST" blocked
  defer_timer_until_configuration_is_ready
  wait_for_sync_service_idle
  "$installer" --uninstall
  clear_timer_deferral
  probe IPv4 "$V4_HOST" allowed
  probe IPv6 "$V6_HOST" allowed
  assert_no_managed_runtime
  assert_unrelated_sentinels
  stop_fixture "$STATE/http-source.pid" "$ROOT/fixtures $SOURCE_PORT"
  printf 'finished tag=%s\n' "$tag" > "$STATE/finished"
  printf 'finish phase passed; failed uninstall preserved runtime and cleanup retained unrelated sentinels\n'
}

case "$phase" in
  os-upgrade) os_upgrade_phase ;;
  start) start_phase ;;
  after-reboot) after_reboot_phase ;;
  upgrade) upgrade_phase ;;
  finish) finish_phase ;;
  *) fail "unknown phase: $phase" ;;
esac
