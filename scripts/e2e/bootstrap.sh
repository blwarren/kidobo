#!/usr/bin/env bash
set -euo pipefail

# Cloud-init runs this only in fresh vendor-image guests, before the agent exists.
exec > /var/log/kidobo-image-bootstrap.log 2>&1
mounted=0
finish() {
  local status=$?
  if [[ "$mounted" == 1 ]]; then
    umount /mnt/incus-agent || status=1
  fi
  printf '%s\n' "$status" > /var/log/kidobo-image-bootstrap.status.tmp
  mv /var/log/kidobo-image-bootstrap.status.tmp /var/log/kidobo-image-bootstrap.status
  exit "$status"
}
trap finish EXIT
systemd-detect-virt --vm >/dev/null
mkdir -p /mnt/incus-agent
mount -o ro /dev/disk/by-label/incus-agent /mnt/incus-agent
mounted=1
cd /mnt/incus-agent
sh install.sh
cd /
umount /mnt/incus-agent
mounted=0
command=$(systemctl show incus-agent.service --property=ExecStart --value)
[[ "$command" == *'path=/run/incus_agent/incus-agent ;'* ]]
install -d -m 0755 /etc/systemd/system/incus-agent.service.d
cat > /etc/systemd/system/incus-agent.service.d/kidobo-e2e-selinux.conf <<'UNIT'
[Service]
ExecStartPre=/usr/bin/chcon -t bin_t /run/incus_agent/incus-agent
UNIT
systemctl daemon-reload
systemctl start incus-agent.service
systemctl is-active --quiet incus-agent.service
[[ "$(getenforce)" == Enforcing ]]
