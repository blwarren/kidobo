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
      packages+=(kernel grubby)
      if [[ "$selinux" == enforcing ]]; then packages+=(selinux-policy-targeted libselinux-utils policycoreutils); fi
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
  for command in bash curl tar sha256sum sudo ip python3 ipset iptables ip6tables bgpq4 systemctl modinfo modprobe; do
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

installed_kernel() {
  local family=$1
  case "$family" in
    apt)
      dpkg-query -W -f='${db:Status-Status} ${Package}\n' 'linux-image-[0-9]*' |
        sed -n -E 's/^installed linux-image-([0-9].*)$/\1/p' | sort -V | tail -n 1
      ;;
    dnf|dnf-epel) rpm -q kernel-core --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort -V | tail -n 1 ;;
    zypper) find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' | sed 's/^vmlinuz-//' | sort -V | tail -n 1 ;;
    *) fail "unsupported package family: $family" ;;
  esac
}

verify_kernel_artifacts() {
  local kernel=$1 initramfs=$2 module location
  [[ "$kernel" =~ ^[0-9][0-9A-Za-z._+-]*$ ]] || fail "invalid intended kernel release: $kernel"
  [[ -s "/boot/vmlinuz-$kernel" ]] || fail "intended kernel image is missing: /boot/vmlinuz-$kernel"
  [[ -s "$initramfs" ]] || fail "intended kernel initramfs is missing: $initramfs"
  [[ -d "/lib/modules/$kernel" ]] || fail "intended kernel module directory is missing: $kernel"
  for module in ip_set xt_set ip_set_hash_net; do
    location=$(modinfo -k "$kernel" -n "$module") || fail "intended kernel $kernel lacks required module $module"
    [[ "$location" == '(builtin)' || -s "$location" ]] || fail "intended kernel module file is missing: $location"
  done
}

select_boot_kernel() {
  local family=$1 kernel=$2 initramfs first_linux
  case "$family" in
    apt)
      initramfs="/boot/initrd.img-$kernel"
      [[ -s "$initramfs" ]] || update-initramfs -c -k "$kernel"
      install -d -m 0755 /etc/default/grub.d
      printf 'GRUB_DEFAULT=0\nGRUB_SAVEDEFAULT=false\n' > /etc/default/grub.d/99-kidobo-e2e.cfg
      update-grub
      first_linux=$(sed -n -E '/^[[:space:]]*linux(efi)?[[:space:]]/{p;q;}' /boot/grub/grub.cfg)
      [[ "$first_linux" == *"/vmlinuz-$kernel "* ]] || fail "first GRUB kernel is not the intended $kernel: $first_linux"
      ;;
    dnf|dnf-epel)
      initramfs="/boot/initramfs-$kernel.img"
      [[ -s "$initramfs" ]] || dracut --force "$initramfs" "$kernel"
      grubby --set-default "/boot/vmlinuz-$kernel"
      [[ "$(grubby --default-kernel)" == "/boot/vmlinuz-$kernel" ]] || fail 'grubby did not select the intended kernel'
      ;;
    zypper)
      initramfs="/boot/initrd-$kernel"
      [[ -s "$initramfs" ]] || dracut --force "$initramfs" "$kernel"
      sed -i -E 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=0/' /etc/default/grub
      grub2-mkconfig -o /boot/grub2/grub.cfg
      first_linux=$(sed -n -E '/^[[:space:]]*linux(efi)?[[:space:]]/{p;q;}' /boot/grub2/grub.cfg)
      [[ "$first_linux" == *"/vmlinuz-$kernel "* ]] || fail "first GRUB kernel is not the intended $kernel: $first_linux"
      ;;
    *) fail "unsupported package family: $family" ;;
  esac
  verify_kernel_artifacts "$kernel" "$initramfs"
  printf '%s\n' "$kernel" > "$PREPARED/expected-kernel"
  printf '%s\n' "$initramfs" > "$PREPARED/expected-initramfs"
}

prepare_selinux() {
  local family=$1 requested=$2 actual
  printf '%s\n' "$requested" > "$PREPARED/selinux-requested"
  printf '0\n' > "$PREPARED/relabel-scheduled"
  [[ "$requested" == enforcing ]] || return 0
  [[ "$family" == dnf || "$family" == dnf-epel ]] || fail 'SELinux enforcing preparation is supported only for Fedora and AlmaLinux'
  actual=$(getenforce)
  grubby --update-kernel ALL --remove-args 'selinux=0 enforcing=0'
  case "$actual" in
    Enforcing) sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config ;;
    Disabled|Permissive)
      # The post-reboot check enables enforcement only after relabeling completes.
      sed -i -E 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
      grubby --update-kernel ALL --args 'selinux=1 enforcing=0'
      fixfiles -F onboot
      printf '1\n' > "$PREPARED/relabel-scheduled"
      ;;
    *) fail "unrecognized SELinux state: $actual" ;;
  esac
}

capture_boot_diagnostics() {
  {
    printf '%s\n' '=== observed kernel ==='; uname -a
    printf '%s\n' '=== kernel command line ==='; cat /proc/cmdline
    printf '%s\n' '=== expected kernel ==='; cat "$PREPARED/expected-kernel"
    printf '%s\n' '=== boot files ==='; find /boot -maxdepth 3 -type f -printf '%p %s bytes\n'
    if command -v grubby >/dev/null 2>&1; then grubby --default-kernel; grubby --info=ALL; fi
    if command -v grub2-editenv >/dev/null 2>&1; then grub2-editenv list; fi
    if command -v grub-editenv >/dev/null 2>&1; then grub-editenv list; fi
    printf '%s\n' '=== package inventory ==='; cat "$PREPARED/packages.txt"
    printf '%s\n' '=== current boot journal ==='; journalctl -b --no-pager
  } > "$PREPARED/boot-diagnostics.txt" 2>&1 || true
}

verify_running_kernel() {
  local expected actual module
  [[ -s "$PREPARED/expected-kernel" && -s "$PREPARED/expected-initramfs" ]] || fail 'kernel verification requires completed boot preparation'
  expected=$(<"$PREPARED/expected-kernel")
  actual=$(uname -r)
  if [[ "$actual" != "$expected" ]]; then
    capture_boot_diagnostics
    fail "running kernel $actual does not match intended kernel $expected; see prepared/boot-diagnostics.txt"
  fi
  verify_kernel_artifacts "$expected" "$(<"$PREPARED/expected-initramfs")"
  for module in ip_set xt_set ip_set_hash_net; do
    modprobe "$module" || fail "required running-kernel module cannot be loaded: $module"
  done
  iptables -w 5 -S >/dev/null || fail 'default IPv4 iptables backend is unavailable'
  ip6tables -w 5 -S >/dev/null || fail 'default IPv6 iptables backend is unavailable'
}

finish_selinux() {
  local requested actual deadline=$((SECONDS + 900))
  requested=$(<"$PREPARED/selinux-requested")
  [[ "$requested" == enforcing ]] || return 0
  while [[ -e /.autorelabel ]] || systemctl is-active --quiet selinux-autorelabel.service; do
    (( SECONDS < deadline )) || fail 'SELinux relabeling did not complete within 900 seconds'
    sleep 2
  done
  actual=$(getenforce)
  [[ "$actual" == Permissive || "$actual" == Enforcing ]] || fail "SELinux policy did not load after relabeling: $actual"
  if [[ "$actual" == Permissive ]]; then setenforce 1; fi
  [[ "$(getenforce)" == Enforcing ]] || fail 'SELinux did not enter enforcing mode'
  sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
  grubby --update-kernel ALL --remove-args 'enforcing=0 selinux=0'
  grubby --update-kernel ALL --args 'selinux=1'
}

assert_pristine() {
  local path
  for path in /usr/local/bin/kidobo /usr/bin/kidobo /etc/kidobo /var/lib/kidobo /var/cache/kidobo \
    /etc/systemd/system/kidobo-sync.service /etc/systemd/system/kidobo-sync.timer; do
    [[ ! -e "$path" && ! -L "$path" ]] || fail "prepared image contains Kidobo state: $path"
  done
}

write_manifest() {
  python3 - "$PREPARED" <<'PY'
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

prepared = Path(sys.argv[1])
values = dict(line.split('=', 1) for line in (prepared / 'provision.txt').read_text().splitlines() if '=' in line)
selinux = subprocess.check_output(['getenforce'], text=True).strip() if shutil.which('getenforce') else 'unavailable'
machine_id = Path('/etc/machine-id').read_text().strip()
if not re.fullmatch('[0-9a-f]{32}', machine_id):
    raise SystemExit('source VM has no valid machine ID before publishing')
manifest = {
    'format': 1,
    'prepared_at_unix': int(time.time()),
    'family': values['family'],
    'architecture': os.uname().machine,
    'expected_kernel': (prepared / 'expected-kernel').read_text().strip(),
    'selinux_requested': (prepared / 'selinux-requested').read_text().strip(),
    'selinux_actual': selinux,
    'packages_sha256': hashlib.sha256((prepared / 'packages.txt').read_bytes()).hexdigest(),
    'provision_sha256': hashlib.sha256(Path('/opt/kidobo-e2e/provision.sh').read_bytes()).hexdigest(),
    'source_machine_id': machine_id,
    'source_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'iptables_backend': subprocess.check_output(['iptables', '--version'], text=True).strip(),
    'ip6tables_backend': subprocess.check_output(['ip6tables', '--version'], text=True).strip(),
}
temporary = prepared / 'manifest.json.tmp'
temporary.write_text(json.dumps(manifest, indent=2) + '\n')
temporary.replace(prepared / 'manifest.json')
PY
}

sanitize_image() {
  [[ -s "$PREPARED/manifest.json" ]] || fail 'sanitizing requires successful post-reboot verification'
  assert_pristine
  if command -v cloud-init >/dev/null 2>&1; then cloud-init clean --logs; fi
  rm -f /etc/ssh/ssh_host_*
  rm -f /var/lib/dbus/machine-id
  : > /etc/machine-id
  find /var/lib/dhcp /var/lib/NetworkManager -maxdepth 1 -type f \( -name '*.lease' -o -name '*.leases' \) -delete 2>/dev/null || true
  find "$BASE" -mindepth 1 -maxdepth 1 ! -name prepared ! -name provision.sh -exec rm -rf -- {} +
}

admit_clone() {
  local fresh=${1:-false}
  [[ -s "$PREPARED/manifest.json" ]] || fail 'clone lacks preparation provenance'
  assert_pristine
  verify_running_kernel
  local family requested
  family=$(sed -n 's/^family=//p' "$PREPARED/provision.txt")
  wait_for_network "$family"
  requested=$(<"$PREPARED/selinux-requested")
  if [[ "$requested" == enforcing ]]; then
    [[ "$(getenforce)" == Enforcing ]] || fail 'prepared clone is not SELinux enforcing'
    [[ ! -e /.autorelabel ]] || fail 'prepared clone has incomplete SELinux relabeling'
  fi
  record_packages "$family" "$PREPARED/admission-packages.txt"
  python3 - "$PREPARED" "$fresh" <<'PY'
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

prepared = Path(sys.argv[1])
manifest = json.loads((prepared / 'manifest.json').read_text())
machine_id = Path('/etc/machine-id').read_text().strip()
if not re.fullmatch('[0-9a-f]{32}', machine_id) or (sys.argv[2] != 'true' and machine_id == manifest['source_machine_id']):
    raise SystemExit('prepared clone did not receive a new valid machine ID')
if hashlib.sha256((prepared / 'packages.txt').read_bytes()).hexdigest() != manifest['packages_sha256']:
    raise SystemExit('prepared package inventory does not match provenance')
if hashlib.sha256((prepared / 'admission-packages.txt').read_bytes()).hexdigest() != manifest['packages_sha256']:
    raise SystemExit('installed clone packages changed after preparation')
if hashlib.sha256(Path('/opt/kidobo-e2e/provision.sh').read_bytes()).hexdigest() != manifest['provision_sha256']:
    raise SystemExit('prepared provision script does not match provenance')
if os.uname().release != manifest['expected_kernel']:
    raise SystemExit('running kernel does not match preparation provenance')
iptables = subprocess.check_output(['iptables', '--version'], text=True).strip()
ip6tables = subprocess.check_output(['ip6tables', '--version'], text=True).strip()
if iptables != manifest['iptables_backend'] or ip6tables != manifest['ip6tables_backend']:
    raise SystemExit('clone firewall backends changed after preparation')
selinux = subprocess.check_output(['getenforce'], text=True).strip() if shutil.which('getenforce') else 'unavailable'
if selinux != manifest['selinux_actual']:
    raise SystemExit('clone SELinux state changed after preparation')
admission = {
    'format': 1,
    'admitted_at_unix': int(time.time()),
    'machine_id': machine_id,
    'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'manifest_sha256': hashlib.sha256((prepared / 'manifest.json').read_bytes()).hexdigest(),
    'kernel': os.uname().release,
    'selinux': selinux,
    'iptables_backend': iptables,
    'ip6tables_backend': ip6tables,
    'fresh_same_instance': sys.argv[2] == 'true',
}
(prepared / 'admission.json').write_text(json.dumps(admission, indent=2) + '\n')
PY
  install -d -m 0755 "$BASE/state"
  cp "$PREPARED/provision.txt" "$BASE/state/provision.txt"
  cp "$PREPARED/packages.txt" "$BASE/state/packages.txt"
}

provision_main() {
  exec 9>&2
  BASH_XTRACEFD=9
  PS4='+ TRACE ${BASH_SOURCE:-main}:${LINENO}:${FUNCNAME[0]:-main}: '
  set -x
  trap 'e2e_report_exit "$?"' EXIT
  require_guest
  local mode=${1:-} family selinux=image-default kernel
  case "$mode" in
    --check-kernel)
      [[ $# == 1 ]] || fail '--check-kernel accepts no additional arguments'
      e2e_check_start 'post-upgrade kernel and firewall backends' 'running kernel equals intended kernel; required modules load; both firewall backends work'
      verify_running_kernel
      family=$(sed -n 's/^family=//p' "$PREPARED/provision.txt")
      wait_for_network "$family"
      printf 'post_upgrade_kernel=%s\n' "$(uname -r)" >> "$PREPARED/provision.txt"
      e2e_check_pass "intended kernel=$(uname -r); required modules loaded; both firewall backends and network available"
      e2e_check_start 'prepared SELinux enforcement' 'requested security mode verified after relabeling; persistent enforcement configured where required'
      finish_selinux
      write_manifest
      install -d -m 0755 "$BASE/state"
      cp "$PREPARED/provision.txt" "$BASE/state/provision.txt"
      cp "$PREPARED/packages.txt" "$BASE/state/packages.txt"
      e2e_check_pass "requested=$(<"$PREPARED/selinux-requested"); actual=$(getenforce 2>/dev/null || printf unavailable); preparation manifest recorded"
      ;;
    --sanitize)
      [[ $# == 1 ]] || fail '--sanitize accepts no additional arguments'
      e2e_check_start 'prepared image is pristine and sanitized' 'no Kidobo installation/state; instance IDs, SSH host keys and cloud-init instance state removed'
      sanitize_image
      e2e_check_pass 'pristine preparation retained; instance identities removed before publishing'
      ;;
    --admit)
      [[ $# == 1 || ( $# == 2 && $2 == --fresh ) ]] || fail 'usage: provision.sh --admit [--fresh]'
      e2e_check_start 'prepared clone admission' 'pristine clone has new identity, intended kernel/modules/backends, networking and requested security state'
      if [[ ${2:-} == --fresh ]]; then admit_clone true; else admit_clone false; fi
      e2e_check_pass 'new clone identity and preparation hashes verified; kernel, modules, network and security checks passed'
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
        e2e_check_start 'intended boot kernel and security preparation' 'installed target kernel, initramfs and module files exist; bootloader selects target; security transition prepared'
        kernel=$(installed_kernel "$family")
        [[ -n "$kernel" ]] || fail 'no installed kernel package was found'
        select_boot_kernel "$family" "$kernel"
        prepare_selinux "$family" "$selinux"
        e2e_check_pass "intended_kernel=$kernel; requested_selinux=$selinux; relabel_scheduled=$(<"$PREPARED/relabel-scheduled")"
      fi
      install -d -m 0755 "$BASE/state"
      cp "$PREPARED/provision.txt" "$BASE/state/provision.txt"
      cp "$PREPARED/packages.txt" "$BASE/state/packages.txt"
      ;;
    *) fail 'usage: provision.sh --prepare FAMILY SELINUX PACKAGE... | --check-kernel | --sanitize | --admit' ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  provision_main "$@"
fi
