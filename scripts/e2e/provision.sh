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

capture_boot_configuration() {
  local label=$1 file
  {
    printf '%s\n' '=== mounted filesystems ==='; findmnt -o TARGET,SOURCE,FSTYPE,UUID
    printf '%s\n' '=== boot identities ==='
    grub2-probe --target=fs_uuid /boot/grub2
    grub2-mkrelpath /boot/grub2
    for file in /proc/cmdline /etc/kernel/cmdline /etc/default/grub \
        /etc/grub2.cfg /etc/grub2-efi.cfg /boot/grub2/grub.cfg /boot/loader/entries/*.conf; do
      printf '\n=== %s ===\n' "$file"
      ls -ld "$file"
      [[ ! -L "$file" ]] || readlink -f "$file"
      head -c 1048576 "$file"
    done
    while IFS= read -r file; do
      printf '\n=== %s ===\n' "$file"
      case "$file" in
        */grubenv) grub2-editenv "$file" list ;;
        *) head -c 1048576 "$file" ;;
      esac
    done < <(find /boot/grub2 /boot/efi/EFI -maxdepth 4 -type f \( -name grub.cfg -o -name grubenv \))
  } > "$PREPARED/boot-config-$label.txt" 2>&1 || true
}

fedora_boot_configuration() {
  python3 - "$@" <<'PY'
import re
import shlex
import sys
from pathlib import Path

mode, root_uuid, boot_uuid, grub_path, kernel_path, initramfs_path, prepared = sys.argv[1:]
prepared = Path(prepared)
efi = Path('/boot/efi/EFI/fedora/grub.cfg')
canonical = Path('/boot/grub2/grub.cfg')
root_arg = 'root=UUID=' + root_uuid

def require(condition, message):
    if not condition:
        raise SystemExit('e2e Fedora boot: ' + message)

def root_options(text, add_root=True):
    # Keep other arguments, including quoted values, byte-for-byte. Only root and
    # the running kernel's informational BOOT_IMAGE token need replacement.
    shlex.split(text)  # Reject unbalanced quoting before writing boot files.
    tokens = re.findall(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''', text)
    roots = [token for token in tokens if token.startswith('root=')]
    require(all('"' not in value and "'" not in value for value in roots),
            'unrecognized quoted root argument')
    if not roots and not add_root:
        return text
    return ' '.join([token for token in tokens if not token.startswith(('root=', 'BOOT_IMAGE='))]
                    + [root_arg])

def default_arguments(match):
    prefix, value = match[0].split('=', 1)
    if value.startswith(('"', "'")):
        quoted = re.fullmatch(r'''(["'])(.*)\1([ \t]*(?:#.*)?)''', value)
        require(quoted is not None, 'unrecognized quoted GRUB command line')
        quote, arguments, comment = quoted.groups()
        return prefix + '=' + quote + root_options(arguments, add_root=False) + quote + comment
    require(not re.search(r'\s', value), 'unrecognized unquoted GRUB command line')
    return prefix + '=' + root_options(value, add_root=False)

def entries():
    paths = sorted(Path('/boot/loader/entries').glob('*.conf'))
    require(bool(paths), 'no BLS entries')
    return paths

def selected_entry() -> Path:
    matches = []
    observed = []
    for path in entries():
        text = path.read_text()
        linux = re.findall(r'^\s*linux[ \t]+([^\n]*)$', text, re.M)
        observed.append(path.name + ': ' + repr(linux))
        require(len(linux) == 1 and len(linux[0].split()) == 1,
                'BLS entry must have exactly one kernel path: ' + str(path))
        if linux[0].strip() == kernel_path:
            initrds = re.findall(r'^\s*initrd[ \t]+([^\n]*)$', text, re.M)
            require(sum(line.split().count(initramfs_path) for line in initrds) == 1,
                    'BLS entry does not reference intended initramfs ' + initramfs_path + ': ' + str(path))
            matches.append(path)
    require(len(matches) == 1,
            'intended kernel ' + kernel_path + ' must have exactly one BLS entry; matched '
            + str(len(matches)) + '; entries: ' + '; '.join(observed))
    return matches[0]

stub = ('search --no-floppy --fs-uuid --set=dev ' + boot_uuid + '\n'
        'set prefix=($dev)' + grub_path + '\n'
        'export prefix\nconfigfile $prefix/grub.cfg\n')

def valid_stub(text):
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    # Fedora's packaged stub exports $prefix; our generated stub exports its name.
    expected = stub.splitlines()
    return lines == expected or lines == [*expected[:2], 'export $prefix', expected[3]]

def recognized_layout():
    require(efi.is_file() and not efi.is_symlink(), 'missing or indirect Fedora EFI configuration')
    configs = sorted(Path('/boot/efi/EFI').rglob('grub.cfg'))
    require(configs == [efi], 'ambiguous EFI configuration layout')
    text = efi.read_text()
    if valid_stub(text):
        return
    require('grub2-mkconfig' in text or 'grub-mkconfig' in text,
            'unrecognized EFI forwarding configuration')
    require(re.search(r'^\s*(blscfg|menuentry\s)', text, re.M),
            'unrecognized full EFI configuration')

def grub_tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=False, punctuation_chars=';')
    lexer.whitespace_split = True
    return list(lexer)

def grub_section(text: str, name: str) -> str:
    sections = re.findall(r'^### BEGIN /etc/grub.d/' + re.escape(name)
                          + r' ###\n(.*?)^### END /etc/grub.d/' + re.escape(name)
                          + r' ###$', text, re.M | re.S)
    require(len(sections) == 1,
            'canonical configuration lacks environment-based BLS selection: expected one ' + name)
    return sections[0]

def consume_grub(text: str, fragment: str, reason: str) -> str:
    # Match known generated control flow, ignoring only comments and whitespace.
    expected = ' ' + ' '.join(grub_tokens(fragment)) + ' '
    require(text.count(expected) == 1, reason)
    return text.replace(expected, ' ', 1)

def verify_canonical() -> None:
    text = canonical.read_text()
    header = ' ' + ' '.join(grub_tokens(grub_section(text, '00_header'))) + ' '
    selection = '''
if [ "${next_entry}" ] ; then
  set default="${next_entry}"
  set next_entry=
  if [ "${env_block}" ] ; then
    save_env -f "${env_block}" next_entry
  else
    save_env next_entry
  fi
  set boot_once=true
else
  set default="${saved_entry}"
fi
'''
    environment = '''
if [ -f ${config_directory}/grubenv ]; then
  load_env -f ${config_directory}/grubenv
elif [ -s $prefix/grubenv ]; then
  load_env
fi
'''
    alternate_environment = '''
if [ "${env_block}" ] ; then
  if [ "${dev}" ]; then
    set env_block="(${dev})${env_block}"
  else
    set env_block="(${root})${env_block}"
  fi
  export env_block
  load_env -f "${env_block}"
fi
'''
    reason = 'canonical configuration lacks environment-based BLS selection'
    consume_grub(header, environment, reason)
    consume_grub(header, selection, reason)
    remaining = ' ' + ' '.join(grub_tokens(text)) + ' '
    for block in (environment, alternate_environment, selection):
        remaining = consume_grub(remaining, block, reason)
    fallback = grub_section(text, '08_fallback_counting')
    expected_fallback = '''
insmod increment
if [ -n "${boot_counter}" -a "${boot_success}" = "0" ]; then
  if [ "${boot_counter}" = "0" -o "${boot_counter}" = "-1" ]; then
    set default=1
    set boot_counter=-1
  else
    decrement boot_counter
  fi
  if [ "${env_block}" ]; then
    save_env -f "${env_block}" boot_counter
  else
    save_env boot_counter
  fi
fi
'''
    require(grub_tokens(fallback) == grub_tokens(expected_fallback),
            'canonical configuration has an unrecognized fallback guard')
    remaining = consume_grub(remaining, fallback, 'ambiguous fallback configuration')
    tokens = grub_tokens(remaining)
    require('blscfg' in tokens, reason)
    for index, token in enumerate(tokens):
        require(token not in ('load_env', 'configfile'),
                'canonical configuration redirects boot selection')
        if token == 'set' and index + 1 < len(tokens):
            name = tokens[index + 1].split('=', 1)[0]
            require(name not in ('default', 'prefix', 'boot_counter'),
                    'canonical configuration has an unexpected boot override: ' + name)

require(re.fullmatch(r'[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)*', root_uuid or ''), 'missing or ambiguous root UUID')
require(re.fullmatch(r'[0-9A-Fa-f]+(?:-[0-9A-Fa-f]+)*', boot_uuid or ''), 'missing or ambiguous boot UUID')
require(grub_path in ('/boot/grub2', '/grub2'), 'unrecognized GRUB filesystem path')
for artifact in (kernel_path, initramfs_path):
    require(artifact.startswith('/') and not re.search(r'\s', artifact)
            and not any(part in ('.', '..') for part in artifact.split('/')),
            'unrecognized boot artifact path: ' + artifact)

if mode == 'prepare':
    recognized_layout()
    selected = selected_entry()
    running = root_options(Path('/proc/cmdline').read_text().strip())
    cmdline = Path('/etc/kernel/cmdline')
    persistent = root_options(cmdline.read_text().strip() if cmdline.exists() else running)
    rewritten = []
    for path in entries():
        text = path.read_text()
        options = re.findall(r'^options[ \t]+(.*)$', text, re.M)
        require(len(options) == 1, 'BLS entry must have exactly one options line: ' + str(path))
        resolved = options[0].replace('${kernelopts}', running).replace('$kernelopts', running)
        resolved = root_options(resolved)
        rewritten.append((path, re.sub(r'^options[ \t]+.*$', lambda _: 'options ' + resolved,
                                       text, flags=re.M)))
    defaults = Path('/etc/default/grub')
    text = defaults.read_text()
    # Repair explicit roots inside quoted GRUB_CMDLINE_LINUX assignments as well.
    text = re.sub(r'^(GRUB_CMDLINE_LINUX(?:_DEFAULT)?=.*)$', default_arguments, text, flags=re.M)
    for key, value in [('GRUB_DEFAULT', 'saved'), ('GRUB_SAVEDEFAULT', 'false'),
                       ('GRUB_ENABLE_BLSCFG', 'true')]:
        text = re.sub(r'^' + key + r'=.*\n?', '', text, flags=re.M)
        text = text.rstrip() + '\n' + key + '=' + value + '\n'
    cmdline.parent.mkdir(parents=True, exist_ok=True)
    cmdline.write_text(persistent + '\n')
    for path, content in rewritten:
        path.write_text(content)
    defaults.write_text(text)
    (prepared / 'selected-bls-entry').write_text(selected.stem + '\n')
elif mode == 'forward':
    verify_canonical()
    if not valid_stub(efi.read_text()):
        efi.write_text(stub)
elif mode == 'verify':
    verify_canonical()
    require(valid_stub(efi.read_text()), 'EFI does not forward to the measured GRUB filesystem')
    selected = selected_entry()
    environment = (prepared / 'canonical-grubenv.txt').read_text().splitlines()
    require(environment.count('saved_entry=' + selected.stem) == 1,
            'canonical GRUB environment does not select the intended BLS entry')
    require(not any(line.startswith(('next_entry=', 'prev_saved_entry=', 'boot_counter=', 'env_block='))
                    for line in environment),
            'canonical GRUB environment still overrides the next boot')
    for path in entries():
        options = re.findall(r'^options[ \t]+(.*)$', path.read_text(), re.M)
        require(len(options) == 1 and re.findall(r'(?<!\S)root=\S+', options[0]) == [root_arg]
                and '$kernelopts' not in options[0] and '${kernelopts}' not in options[0],
                'BLS root identity is not explicit and correct: ' + str(path))
else:
    raise SystemExit('unknown Fedora boot configuration operation')
PY
}

fedora_boot_identity() {
  local kernel=$1 artifact
  root_uuid=$(findmnt --noheadings --output UUID --target /)
  boot_uuid=$(grub2-probe --target=fs_uuid /boot/grub2)
  grub_path=$(grub2-mkrelpath /boot/grub2)
  kernel_path=$(grub2-mkrelpath "/boot/vmlinuz-$kernel")
  initramfs_path=$(grub2-mkrelpath "/boot/initramfs-$kernel.img")
  for artifact in "/boot/vmlinuz-$kernel" "/boot/initramfs-$kernel.img"; do
    [[ "$(grub2-probe --target=fs_uuid "$artifact")" == "$boot_uuid" ]] || fail "boot artifact is on a different GRUB filesystem: $artifact"
  done
}

verify_fedora_boot() (
  local kernel=$1 root_uuid boot_uuid grub_path kernel_path initramfs_path
  trap 'capture_boot_configuration final' EXIT
  fedora_boot_identity "$kernel"
  grub2-editenv /boot/grub2/grubenv list > "$PREPARED/canonical-grubenv.txt"
  fedora_boot_configuration verify "$root_uuid" "$boot_uuid" "$grub_path" "$kernel_path" "$initramfs_path" "$PREPARED"
)

prepare_fedora_boot() (
  local kernel=$1 root_uuid boot_uuid grub_path kernel_path initramfs_path
  capture_boot_configuration before
  trap 'capture_boot_configuration after' EXIT
  fedora_boot_identity "$kernel"
  fedora_boot_configuration prepare "$root_uuid" "$boot_uuid" "$grub_path" "$kernel_path" "$initramfs_path" "$PREPARED"
  grub2-mkconfig -o /boot/grub2/grub.cfg
  fedora_boot_configuration forward "$root_uuid" "$boot_uuid" "$grub_path" "$kernel_path" "$initramfs_path" "$PREPARED"
  grubby --set-default "/boot/vmlinuz-$kernel"
  [[ "$(grubby --default-kernel)" == "/boot/vmlinuz-$kernel" ]] || fail 'grubby did not select the intended kernel'
  grub2-editenv /boot/grub2/grubenv set "saved_entry=$(<"$PREPARED/selected-bls-entry")"
  grub2-editenv /boot/grub2/grubenv unset next_entry prev_saved_entry boot_counter
  verify_fedora_boot "$kernel"
)

select_boot_kernel() {
  local family=$1 kernel=$2 initramfs first_linux ID=
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
      # shellcheck disable=SC1091
      . /etc/os-release
      if [[ "$ID" == fedora ]]; then
        prepare_fedora_boot "$kernel"
      else
        grubby --set-default "/boot/vmlinuz-$kernel"
        [[ "$(grubby --default-kernel)" == "/boot/vmlinuz-$kernel" ]] || fail 'grubby did not select the intended kernel'
      fi
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

capture_boot_diagnostics() {
  capture_boot_configuration current
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
  local mode=${1:-} family selinux=image-default kernel ID=
  case "$mode" in
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
        --property=RuntimeMaxSec=120 --property=TimeoutStartSec=120 \
        --property="StandardOutput=append:$PREPARED/enforcement.log" \
        --property="StandardError=append:$PREPARED/enforcement.log" \
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
        printf 'pending\n'
      fi
      e2e_check_start 'prepared enforcement status observed' 'detached job status inspected without assuming success'
      e2e_check_pass 'status returned for host enforcement admission'
      ;;
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
      rm -f /etc/systemd/system/selinux-autorelabel.service.d/kidobo-e2e.conf
      systemctl daemon-reload
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
        # SELinux preparation edits the selected entries through grubby.
        # shellcheck disable=SC1091
        . /etc/os-release
        if [[ "$ID" == fedora ]]; then verify_fedora_boot "$kernel"; fi
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
