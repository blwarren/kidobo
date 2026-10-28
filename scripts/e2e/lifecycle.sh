#!/usr/bin/env bash
set -euo pipefail

# Keep tracing and check evidence out of stdout and redirected command diagnostics.
exec 9>&2
BASH_XTRACEFD=9
PS4='+ TRACE ${BASH_SOURCE:-main}:${LINENO}:${FUNCNAME[0]:-main}: '
set -x

e2e_checks=()
e2e_failure_reason='command failed or guest interrupted before assertion completion'
readonly ROOT=/opt/kidobo-e2e MARKER=/etc/kidobo-e2e-owned
readonly MARKER_CONTENT=kidobo-e2e-v1
readonly RELEASE="$ROOT/release" BASELINE="$ROOT/baseline" STATE="$ROOT/state"
readonly TEST_NS=kidobo-e2e HOST_IF=ke2eh0 PEER_IF=ke2ep0
readonly V4_HOST=198.18.77.1 V4_PEER=198.18.77.2 V4_CONTROL=198.18.77.3
readonly V6_HOST=fd42:6b69:646f:626f::1 V6_PEER=fd42:6b69:646f:626f::2 V6_CONTROL=fd42:6b69:646f:626f::3
readonly TRAFFIC_PORT=39471 HTTP_PORT=39472 BAD_HTTP_PORT=39473 SOURCE_PORT=39474 IRR_PORT=39475
readonly CONFIG=/etc/kidobo/config.toml BLOCKLIST=/var/lib/kidobo/blocklist.txt
readonly SET4=kidobo-e2e SET6=kidobo-e2e-v6

source "$ROOT/lib/reporting.sh"
trap 'e2e_report_exit "$?"' EXIT
source "$ROOT/lib/fixtures.sh"
source "$ROOT/lib/network.sh"
source "$ROOT/lib/runtime.sh"
source "$ROOT/lib/upgrade.sh"
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

# Keep host-dispatched phase boundaries here; the phase-specific ordered checks live with their helpers.
after_reboot_phase() {
  run_after_reboot_phase
}

upgrade_phase() {
  run_upgrade_phase
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
