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
  # The baseline invokes sudo even as root; its secure_path would escape the fakes.
  {
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    printf '[[ $# -ge 2 && "$1" == -n ]] || exit 90\nshift\n'
    printf 'case "$1" in ipset|iptables|ip6tables) ;; *) exit 91 ;; esac\n'
    printf 'program=$1\nshift\nexec %q/"$program" "$@"\n' "$fake"
  } > "$fake/sudo"
  chmod 0755 "$fake/sudo"
  # Only the old binary's cache writer uses these fakes, inside a separate root.
  # The candidate and the guest's live firewall never see this PATH.
  if ! KIDOBO_ROOT="$isolated" PATH="$fake:$PATH" /usr/local/bin/kidobo sync > "$STATE/baseline-cache-generation.stdout" 2> "$STATE/baseline-cache-generation.stderr"; then
    cat "$STATE/baseline-cache-generation.stdout" "$STATE/baseline-cache-generation.stderr" >&9
    fail 'isolated baseline cache generation failed; see baseline-cache-generation.stderr'
  fi
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

run_upgrade_phase() {
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
  local preserved_config="$STATE/baseline-before-sync-config.toml" preserved_blocklist="$STATE/baseline-before-sync-blocklist.txt"
  local preserved_temporary=- temporary_supported=false
  if grep -Eq -- '(^|[[:space:]])--for([[:space:]]|$)' "$STATE/baseline-ban-help.txt"; then
    temporary_supported=true
    kidobo ban 203.0.113.79 --for 1d
    preserved_temporary="$STATE/baseline-before-sync-temporary-bans.toml"
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
  # Baseline sync may canonicalize source files; measure only the installer's changes.
  preserved_config="$STATE/upgrade-config.toml"
  preserved_blocklist="$STATE/upgrade-blocklist.txt"
  cp -p "$CONFIG" "$preserved_config"
  cp -p "$BLOCKLIST" "$preserved_blocklist"
  if [[ "$temporary_supported" == true ]]; then
    preserved_temporary="$STATE/upgrade-temporary-bans.toml"
    cp -p /var/lib/kidobo/temporary-bans.toml "$preserved_temporary"
  fi
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
