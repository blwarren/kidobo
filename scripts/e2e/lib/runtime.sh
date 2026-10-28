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
  [[ -s "$ROOT/prepared/selinux-requested" ]] || fail 'application reboot lacks security preparation provenance'
  if [[ "$(<"$ROOT/prepared/selinux-requested")" == enforcing ]]; then
    [[ "$(getenforce)" == Enforcing && ! -e /.autorelabel ]] || fail 'application reboot lost completed enforcing SELinux state'
  fi
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

run_after_reboot_phase() {
  e2e_check_start 'reboot restores timer enforcement' 'version retained; timer enabled/active; sync service succeeds; both traffic families blocked'
  local kernel
  kernel=$(uname -r)
  printf 'post_application_reboot_kernel=%s\n' "$kernel" >> "$STATE/provision.txt"
  printf 'post_application_reboot_kernel=%s\n' "$kernel"
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
