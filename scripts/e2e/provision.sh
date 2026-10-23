#!/usr/bin/env bash
set -euo pipefail

exec 9>&2
BASH_XTRACEFD=9
PS4='+ TRACE ${BASH_SOURCE:-main}:${LINENO}:${FUNCNAME[0]:-main}: '
set -x
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
trap 'e2e_report_exit "$?"' EXIT

if [[ ${1:-} == --check-kernel ]]; then
  printf 'E2E_CHECK\tpost-upgrade kernel and firewall backends\tPLAN\tscenario scheduled; expectation follows at START\n' >&9
else
  printf 'E2E_CHECK\tguest route and DNS readiness\tPLAN\tscenario scheduled; expectation follows at START\n' >&9
  printf 'E2E_CHECK\tguest dependency provisioning\tPLAN\tscenario scheduled; expectation follows at START\n' >&9
fi

readonly BASE=/opt/kidobo-e2e
readonly MARKER=/etc/kidobo-e2e-owned
readonly MARKER_CONTENT=kidobo-e2e-v1

fail() { e2e_failure_reason=$*; printf 'e2e provision: %s\n' "$*" >&2; exit 1; }
[[ -f "$MARKER" ]] || fail "missing guest ownership marker $MARKER"
cmp -s "$MARKER" <(printf '%s\n' "$MARKER_CONTENT") || fail "invalid guest ownership marker content in $MARKER"
[[ ! -e /run/systemd/container ]] || fail 'refusing to run inside a container; E2E requires a VM'
if [[ $# == 1 && $1 == --check-kernel ]]; then
  e2e_check_start 'post-upgrade kernel and firewall backends' 'required modules load; default IPv4/IPv6 iptables backends available'
  [[ -s "$BASE/state/provision.txt" ]] || fail 'kernel check requires completed provisioning metadata'
  for module in ip_set xt_set ip_set_hash_net; do
    modprobe "$module" || fail "required kernel module cannot be loaded: $module"
  done
  iptables -w 5 -S >/dev/null || fail 'default IPv4 iptables backend is unavailable'
  ip6tables -w 5 -S >/dev/null || fail 'default IPv6 iptables backend is unavailable'
  {
    printf 'post_upgrade_kernel=%s\n' "$(uname -r)"
    iptables --version
    ip6tables --version
    for module in ip_set xt_set; do
      printf '%s_module=%s\n' "$module" "$(modinfo -n "$module")"
    done
  } >> "$BASE/state/provision.txt"
  printf 'kernel module checks passed for %s\n' "$(uname -r)"
  e2e_check_pass "ip_set, xt_set and ip_set_hash_net loaded; both firewall backends exited 0; kernel=$(uname -r)"
  exit 0
fi
[[ $# -ge 2 ]] || fail 'usage: provision.sh FAMILY PACKAGE [PACKAGE...] or provision.sh --check-kernel'
family=$1
shift
packages=("$@")

# Prevent a package operation against an unconfigured guest network. Give cloud-init
# and DHCP up to one minute, checking only route and DNS readiness.
case "$family" in
  apt|dnf|dnf-epel) repo_host=deb.debian.org ;;
  zypper) repo_host=download.opensuse.org ;;
  *) fail "unsupported package family: $family" ;;
esac
deadline=$((SECONDS + 60))
e2e_check_start 'guest route and DNS readiness' "IPv4 default route and DNS for $repo_host ready within 60 seconds; retries expected"
until ip -4 route show default | grep -q . && getent ahostsv4 "$repo_host" >/dev/null 2>&1; do
  (( SECONDS < deadline )) || fail "IPv4 default route/DNS not ready for $repo_host within 60 seconds"
  sleep 2
done
e2e_check_pass "IPv4 default route present; getent resolved $repo_host"

e2e_check_start 'guest dependency provisioning' "package transaction succeeds; required commands available; package inventory and guest identity recorded"
case "$family" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o APT::Update::Error-Mode=any update
    apt-get install -y --no-install-recommends "${packages[@]}"
    ;;
  dnf)
    dnf -y --refresh install "${packages[@]}"
    ;;
  dnf-epel)
    dnf -y --refresh install epel-release dnf-plugins-core
    if command -v crb >/dev/null 2>&1; then
      crb enable
    elif dnf repolist all | grep -Eq '(^|[[:space:]])crb([[:space:]]|$)'; then
      dnf config-manager --set-enabled crb
    fi
    dnf -y --refresh install "${packages[@]}"
    ;;
  zypper)
    zypper --non-interactive refresh
    zypper --non-interactive install --no-recommends "${packages[@]}"
    ;;
  *) fail "unsupported package family: $family" ;;
esac

for command in bash curl tar sha256sum sudo ip python3 ipset iptables ip6tables bgpq4 systemctl; do
  command -v "$command" >/dev/null 2>&1 || fail "required command unavailable after package install: $command"
done

install -d -m 0755 "$BASE/state"
{
  printf 'family=%s\n' "$family"
  printf 'release=%s\n' "$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
  printf 'kernel=%s\n' "$(uname -r)"
  printf 'architecture=%s\n' "$(uname -m)"
  printf 'provisioned_utc=%s\n' "$(date -u +%FT%TZ)"
  printf 'selinux=%s\n' "$(getenforce 2>/dev/null || printf unavailable)"
  printf 'ip_set_module=not_checked_until_post_upgrade_reboot\n'
  printf 'xt_set_module=not_checked_until_post_upgrade_reboot\n'
} > "$BASE/state/provision.txt"

case "$family" in
  apt) dpkg-query -W -f='${binary:Package}=${Version}\n' | sort > "$BASE/state/packages.txt" ;;
  *) rpm -qa --qf '%{NAME}=%{EVR}\n' | sort > "$BASE/state/packages.txt" ;;
esac

printf 'provisioned %s guest; metadata: %s/state/provision.txt; runner must OS-upgrade, reboot, then invoke provision.sh --check-kernel\n' "$family" "$BASE"
e2e_check_pass "packages installed for $family; all required commands available; provision.txt and packages.txt recorded"
