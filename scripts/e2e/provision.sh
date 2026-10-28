#!/usr/bin/env bash
set -euo pipefail

readonly BASE=/opt/kidobo-e2e PREPARED=/opt/kidobo-e2e/prepared
readonly MARKER=/etc/kidobo-e2e-owned MARKER_CONTENT=kidobo-e2e-v1
e2e_active_check=
e2e_failure_reason='command failed or guest interrupted before assertion completion'
e2e_check_start() {
  e2e_active_check=$1
  printf 'E2E_CHECK\t%s\tSTART\t%s\n' "$1" "$2" >&9
}
e2e_check_pass() {
  printf 'E2E_CHECK\t%s\tPASS\t%s\n' "$e2e_active_check" "$1" >&9
  e2e_active_check=
}
e2e_report_exit() {
  local status=$1
  if [[ -n "$e2e_active_check" ]]; then
    printf 'E2E_CHECK\t%s\tFAIL\t%s; guest exit status=%s\n' "$e2e_active_check" "$e2e_failure_reason" "$status" >&9
  fi
}
fail() { e2e_failure_reason=$*; printf 'e2e provision: %s\n' "$*" >&2; exit 1; }

require_guest() {
  [[ -f "$MARKER" ]] || fail "missing guest ownership marker $MARKER"
  cmp -s "$MARKER" <(printf '%s\n' "$MARKER_CONTENT") || fail "invalid guest ownership marker content in $MARKER"
  [[ ! -e /run/systemd/container ]] || fail 'refusing to run inside a container; E2E requires a VM'
}

wait_for_network() {
  local family=$1 repo_host deadline=$((SECONDS + 60))
  case "$family" in
    apt)
      local ID=
      # shellcheck disable=SC1091
      . /etc/os-release
      if [[ "$ID" == ubuntu ]]; then repo_host=archive.ubuntu.com; else repo_host=deb.debian.org; fi
      ;;
    dnf) repo_host=mirrors.fedoraproject.org ;;
    dnf-epel) repo_host=mirrors.almalinux.org ;;
    zypper) repo_host=download.opensuse.org ;;
    *) fail "unsupported package family: $family" ;;
  esac
  until ip -4 route show default | grep -q . && getent ahostsv4 "$repo_host" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || fail "IPv4 default route/DNS not ready for $repo_host within 60 seconds"
    sleep 2
  done
}

record_packages() {
  local family=$1 output=$2
  case "$family" in
    apt) dpkg-query -W -f='${binary:Package}=${Version}\n' | sort > "$output" ;;
    *) rpm -qa --qf '%{NAME}=%{EVR}\n' | sort > "$output" ;;
  esac
}

install_dependencies() {
  local family=$1 selinux=$2
  shift 2
  local packages=("$@")
  case "$family" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get -o APT::Update::Error-Mode=any update
      apt-get install -y --no-install-recommends "${packages[@]}"
      ;;
    dnf|dnf-epel)
      if [[ "$selinux" == enforcing ]]; then packages+=(grubby selinux-policy-targeted libselinux-utils policycoreutils); fi
      if [[ "$family" == dnf-epel ]]; then
        dnf -y --refresh install epel-release dnf-plugins-core
        if command -v crb >/dev/null 2>&1; then
          crb enable
        elif dnf repolist all | grep -Eq '(^|[[:space:]])crb([[:space:]]|$)'; then
          dnf config-manager --set-enabled crb
        fi
      fi
      dnf -y --refresh install "${packages[@]}"
      ;;
    zypper)
      [[ "$selinux" == image-default ]] || fail 'SELinux enforcing preparation is supported only for Fedora and AlmaLinux'
      zypper --non-interactive refresh
      zypper --non-interactive install --no-recommends "${packages[@]}"
      ;;
    *) fail "unsupported package family: $family" ;;
  esac
  for command in bash curl tar sha256sum sudo ip python3 ipset iptables ip6tables bgpq4 systemctl modprobe; do
    command -v "$command" >/dev/null 2>&1 || fail "required command unavailable after package install: $command"
  done
}

run_upgrade() {
  local family=$1 rc=0
  shift
  "$@" || rc=$?
  case "$rc" in
    0) ;;
    102|103)
      [[ "$family" == zypper ]] || return "$rc"
      printf 'package_manager_reboot_status=%s\n' "$rc" >> "$PREPARED/provision.txt"
      printf 'EXPECTED STATUS: package manager requested reboot (status=%s)\n' "$rc" >&9
      ;;
    *) return "$rc" ;;
  esac
}

upgrade_operating_system() {
  local family=$1
  # Dependency installation refreshed this guest's package metadata immediately above.
  case "$family" in
    apt) export DEBIAN_FRONTEND=noninteractive; run_upgrade "$family" apt-get -y full-upgrade ;;
    dnf|dnf-epel) run_upgrade "$family" dnf -y upgrade ;;
    zypper) run_upgrade "$family" zypper --no-refresh --non-interactive update ;;
    *) fail "unsupported package family: $family" ;;
  esac
  record_packages "$family" "$PREPARED/packages.txt"
  printf 'os_upgrade_completed_utc=%s\n' "$(date -u +%FT%TZ)" >> "$PREPARED/provision.txt"
}

prepare_agent_selinux() {
  local command
  command=$(systemctl show incus-agent.service --property=ExecStart --value)
  [[ "$command" == *'path=/run/incus_agent/incus-agent ;'* ]] || fail 'unsupported Incus agent executable; expected /run/incus_agent/incus-agent'
  command -v chcon >/dev/null || fail 'chcon is required for the Incus agent executable label'
  install -d -m 0755 /etc/systemd/system/incus-agent.service.d
  # The upstream setup recreates this tmpfs executable on every start. Append
  # after its ExecStartPre so the upstream bin_t label survives every boot.
  cat > /etc/systemd/system/incus-agent.service.d/kidobo-e2e-selinux.conf <<'UNIT'
[Service]
ExecStartPre=/usr/bin/chcon -t bin_t /run/incus_agent/incus-agent
UNIT
  systemctl daemon-reload
  {
    systemctl cat incus-agent.service
    ls -lZ /run/incus_agent/incus-agent
    ps -eZ
  } > "$PREPARED/agent-before-enforcement.txt"
}

prepare_selinux() {
  local family=$1 requested=$2 actual
  printf '%s\n' "$requested" > "$PREPARED/selinux-requested"
  printf '0\n' > "$PREPARED/relabel-scheduled"
  [[ "$requested" == enforcing ]] || return 0
  [[ "$family" == dnf || "$family" == dnf-epel ]] || fail 'SELinux enforcing preparation is supported only for Fedora and AlmaLinux'
  prepare_agent_selinux
  actual=$(getenforce)
  grubby --update-kernel ALL --remove-args 'selinux=0 enforcing=0'
  case "$actual" in
    Enforcing) sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config ;;
    Disabled|Permissive)
      # The post-reboot check enables enforcement only after relabeling completes.
      sed -i -E 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
      grubby --update-kernel ALL --args 'selinux=1 enforcing=0'
      install -d -m 0755 /etc/systemd/system/selinux-autorelabel.service.d
      cat > /etc/systemd/system/selinux-autorelabel.service.d/kidobo-e2e.conf <<'UNIT'
[Service]
ExecStartPre=/bin/sh -c 'cat /proc/sys/kernel/random/boot_id > /opt/kidobo-e2e/prepared/relabel-boot-id'
UNIT
      systemctl daemon-reload
      fixfiles -F onboot
      printf '1\n' > "$PREPARED/relabel-scheduled"
      ;;
    *) fail "unrecognized SELinux state: $actual" ;;
  esac
}

verify_running_kernel() {
  local actual module
  actual=$(uname -r)
  printf 'running_kernel=%s\n' "$actual"
  for module in ip_set xt_set ip_set_hash_net; do
    modprobe "$module" || fail "required module $module cannot be loaded for running kernel $actual"
  done
  iptables -w 5 -S >/dev/null || fail 'default IPv4 iptables backend is unavailable'
  ip6tables -w 5 -S >/dev/null || fail 'default IPv6 iptables backend is unavailable'
}

finish_selinux() {
  local requested actual
  requested=$(<"$PREPARED/selinux-requested")
  [[ "$requested" == enforcing ]] || return 0
  [[ ! -e /.autorelabel ]] && ! systemctl is-active --quiet selinux-autorelabel.service || fail 'SELinux relabeling has not completed'
  actual=$(getenforce)
  [[ "$actual" == Enforcing ]] || fail "SELinux did not enter enforcing mode: $actual"
  [[ -s "$PREPARED/enforcement.status" && "$(<"$PREPARED/enforcement.status")" == 0 ]] || fail 'detached SELinux enforcement did not complete successfully'
}

enable_selinux() {
  [[ ! -e /.autorelabel ]] && ! systemctl is-active --quiet selinux-autorelabel.service || fail 'SELinux relabeling has not completed'
  local actual
  actual=$(getenforce)
  [[ "$actual" == Permissive || "$actual" == Enforcing ]] || fail "SELinux policy did not load after relabeling: $actual"
  # This runs in a systemd job, not in the agent session being restarted.
  systemctl restart incus-agent.service
  systemctl is-active --quiet incus-agent.service || fail 'Incus agent failed to restart before enforcing SELinux'
  ls -lZ /run/incus_agent/incus-agent
  [[ "$(stat -c %C /run/incus_agent/incus-agent | cut -d: -f3)" == bin_t ]] || fail 'Incus agent executable did not receive the bin_t label'
  if [[ "$actual" == Permissive ]]; then setenforce 1; fi
  [[ "$(getenforce)" == Enforcing ]] || fail 'SELinux did not enter enforcing mode'
  sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  grubby --update-kernel ALL --remove-args 'enforcing=0 selinux=0'
  grubby --update-kernel ALL --args 'selinux=1'
}

prepared_boot_status() {
  local boot relabel=not-recorded
  boot=$(</proc/sys/kernel/random/boot_id)
  if [[ -s "$PREPARED/relabel-boot-id" ]]; then relabel=$(<"$PREPARED/relabel-boot-id"); fi
  printf 'Preparation boot observation: current=%s relabel=%s\n' "$boot" "$relabel" >&2
  if [[ "$(<"$PREPARED/relabel-scheduled")" == 1 ]]; then
    [[ -s "$PREPARED/relabel-boot-id" ]] || return 75
    [[ "$boot" != "$relabel" && ! -e /.autorelabel ]] || return 75
    ! systemctl is-active --quiet selinux-autorelabel.service || return 75
  fi
  printf '%s\n' "$boot"
}

assert_pristine() {
  local path
  for path in /usr/local/bin/kidobo /usr/bin/kidobo /etc/kidobo /var/lib/kidobo /var/cache/kidobo \
    /etc/systemd/system/kidobo-sync.service /etc/systemd/system/kidobo-sync.timer; do
    [[ ! -e "$path" && ! -L "$path" ]] || fail "fresh guest contains Kidobo state: $path"
  done
}

write_environment() {
  python3 - "$PREPARED" <<'PYTHON'
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

prepared = Path(sys.argv[1])
values = dict(line.split('=', 1) for line in (prepared / 'provision.txt').read_text().splitlines() if '=' in line)
environment = {
    'family': values['family'],
    'architecture': os.uname().machine,
    'kernel': os.uname().release,
    'selinux': subprocess.check_output(['getenforce'], text=True).strip() if shutil.which('getenforce') else 'unavailable',
    'iptables_backend': subprocess.check_output(['iptables', '--version'], text=True).strip(),
    'ip6tables_backend': subprocess.check_output(['ip6tables', '--version'], text=True).strip(),
}
(prepared / 'environment.json').write_text(json.dumps(environment, indent=2) + '\n')
PYTHON
}

validate_environment() {
  assert_pristine
  verify_running_kernel
  finish_selinux
  local family
  family=$(sed -n 's/^family=//p' "$PREPARED/provision.txt")
  wait_for_network "$family"
  write_environment
}

provision_main() {
  exec 9>&2
  BASH_XTRACEFD=9
  PS4='+ TRACE ${BASH_SOURCE:-main}:${LINENO}:${FUNCNAME[0]:-main}: '
  set -x
  trap 'e2e_report_exit "$?"' EXIT
  require_guest
  local mode=${1:-} family selinux=image-default
  case "$mode" in
    --check-bootstrap)
      [[ $# == 1 ]] || fail '--check-bootstrap accepts no additional arguments'
      e2e_check_start 'vendor image agent bootstrap' 'cloud-init-installed agent completed successfully under enforcing SELinux'
      [[ -s /var/log/kidobo-image-bootstrap.status && "$(</var/log/kidobo-image-bootstrap.status)" == 0 ]] || fail 'vendor image bootstrap did not complete successfully'
      systemctl is-active --quiet incus-agent.service || fail 'bootstrapped Incus agent is not active'
      [[ "$(getenforce)" == Enforcing ]] || fail 'vendor image bootstrap lost enforcing SELinux'
      e2e_check_pass 'durable bootstrap success, active Incus agent and enforcing SELinux verified'
      ;;
    --boot-status)
      [[ $# == 1 ]] || fail '--boot-status accepts no additional arguments'
      prepared_boot_status
      e2e_check_start 'prepared boot status observed' 'guest reached a boot after relabeling'
      e2e_check_pass 'boot identity returned for host stability verification'
      ;;
    --start-enforcement)
      [[ $# == 1 ]] || fail '--start-enforcement accepts no additional arguments'
      [[ "$(<"$PREPARED/selinux-requested")" == enforcing ]] || fail 'enforcement job requires enforcing preparation'
      rm -f "$PREPARED/enforcement.status" "$PREPARED/enforcement.status.tmp"
      systemd-run --unit=kidobo-e2e-enforce --no-block --property=Type=oneshot \
        --property=TimeoutStartSec=120 \
        --property=StandardOutput=journal --property=StandardError=journal \
        /bin/bash "$BASE/provision.sh" --enforce-selinux
      e2e_check_start 'prepared enforcement job scheduled' 'systemd accepted the detached enforcement job'
      e2e_check_pass 'job accepted; durable completion is checked separately'
      ;;
    --enforce-selinux)
      [[ $# == 1 ]] || fail '--enforce-selinux accepts no additional arguments'
      trap 'status=$?; printf "%s\n" "$status" > "$PREPARED/enforcement.status.tmp"; mv "$PREPARED/enforcement.status.tmp" "$PREPARED/enforcement.status"' EXIT
      enable_selinux
      ;;
    --enforcement-status)
      [[ $# == 1 ]] || fail '--enforcement-status accepts no additional arguments'
      if [[ -s "$PREPARED/enforcement.status" ]]; then
        printf '%s %s\n' "$(<"$PREPARED/enforcement.status")" "$(getenforce)"
      else
        local active result exit_status
        active=$(systemctl show kidobo-e2e-enforce.service --property=ActiveState --value)
        case "$active" in
          activating|active|deactivating) printf 'pending\n' ;;
          *)
            result=$(systemctl show kidobo-e2e-enforce.service --property=Result --value)
            exit_status=$(systemctl show kidobo-e2e-enforce.service --property=ExecMainStatus --value)
            printf 'failed unit=%s result=%s status=%s; completion marker missing\n' "$active" "$result" "$exit_status"
            ;;
        esac
      fi
      e2e_check_start 'prepared enforcement status observed' 'detached job status inspected without assuming success'
      e2e_check_pass 'status returned for host enforcement admission'
      ;;
    --check-kernel)
      [[ $# == 1 ]] || fail '--check-kernel accepts no additional arguments'
      e2e_check_start 'running kernel capabilities and firewall backends' 'required modules load for the running kernel; both firewall backends work'
      verify_running_kernel
      family=$(sed -n 's/^family=//p' "$PREPARED/provision.txt")
      wait_for_network "$family"
      printf 'post_upgrade_kernel=%s\n' "$(uname -r)" >> "$PREPARED/provision.txt"
      e2e_check_pass "running kernel=$(uname -r); required modules loaded; both firewall backends and network available"
      e2e_check_start 'prepared SELinux enforcement' 'requested security mode verified after relabeling; persistent enforcement configured where required'
      finish_selinux
      rm -f /etc/systemd/system/selinux-autorelabel.service.d/kidobo-e2e.conf
      systemctl daemon-reload
      install -d -m 0755 "$BASE/state"
      cp "$PREPARED/provision.txt" "$BASE/state/provision.txt"
      cp "$PREPARED/packages.txt" "$BASE/state/packages.txt"
      e2e_check_pass "requested=$(<"$PREPARED/selinux-requested"); actual=$(getenforce 2>/dev/null || printf unavailable)"
      ;;
    --validate)
      [[ $# == 1 ]] || fail '--validate accepts no additional arguments'
      e2e_check_start 'fresh guest environment' 'no pre-existing Kidobo state; kernel, firewall backends, network and requested security state are usable'
      validate_environment
      e2e_check_pass 'fresh guest environment verified'
      ;;
    --prepare|apt|dnf|dnf-epel|zypper)
      if [[ "$mode" == --prepare ]]; then
        [[ $# -ge 4 ]] || fail 'usage: provision.sh --prepare FAMILY SELINUX PACKAGE [PACKAGE...]'
        family=$2 selinux=$3
        shift 3
      else
        [[ $# -ge 2 ]] || fail 'usage: provision.sh FAMILY PACKAGE [PACKAGE...]'
        family=$1
        shift
      fi
      [[ "$selinux" == enforcing || "$selinux" == image-default ]] || fail "unsupported SELinux requirement: $selinux"
      install -d -m 0755 "$PREPARED"
      e2e_check_start 'guest route and DNS readiness' 'guest has an IPv4 default route and can resolve its distro repository host'
      wait_for_network "$family"
      e2e_check_pass 'guest IPv4 route and distro repository DNS ready'
      e2e_check_start 'guest dependency provisioning' 'packaged prerequisites installed; inventory and guest identity retained'
      install_dependencies "$family" "$selinux" "$@"
      {
        printf 'family=%s\n' "$family"
        printf 'release=%s\n' "$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
        printf 'kernel=%s\n' "$(uname -r)"
        printf 'architecture=%s\n' "$(uname -m)"
        printf 'provisioned_utc=%s\n' "$(date -u +%FT%TZ)"
      } > "$PREPARED/provision.txt"
      record_packages "$family" "$PREPARED/packages.txt"
      e2e_check_pass "required commands available; $family package inventory recorded"
      if [[ "$mode" == --prepare ]]; then
        e2e_check_start 'operating system upgrade' 'upgrade reuses fresh provisioning metadata; package transaction and inventory succeed'
        upgrade_operating_system "$family"
        e2e_check_pass "OS upgrade completed for $family; refreshed inventory recorded"
        e2e_check_start 'guest security preparation' 'requested security transition prepared for reboot'
        prepare_selinux "$family" "$selinux"
        e2e_check_pass "requested_selinux=$selinux; relabel_scheduled=$(<"$PREPARED/relabel-scheduled")"
      fi
      install -d -m 0755 "$BASE/state"
      cp "$PREPARED/provision.txt" "$BASE/state/provision.txt"
      cp "$PREPARED/packages.txt" "$BASE/state/packages.txt"
      ;;
    *) fail 'usage: provision.sh --prepare FAMILY SELINUX PACKAGE... | --check-kernel | --validate' ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  provision_main "$@"
fi
