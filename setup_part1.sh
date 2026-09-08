#!/usr/bin/env bash
#basic setup script part 1/2
set -euo pipefail
if [[ "$EUID" != "0" ]]; then
  echo must be root to run setup_part1
  exit 1
fi
bootD="$(findmnt -no SOURCE /boot)"
luksUUID="$(cat /etc/crypttab | awk '{print $1}')"
systemdsvc="$(systemctl list-units | grep 'systemd-cryptsetup@luks' | grep -v '/run/credentials' | awk '{print $1}')"
systemdsvc="${systemdsvc//\\/\\\\}"
luksdev="/dev/$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")" || true
if ! cryptsetup isLuks "$luksdev"; then
  echo "faled to find correct luks2 disk"
  echo "$luksD is NOT a luks device change the luksD value on this script to your disk."
  exit 4
fi
if ! test -f SALT; then
  head -c 32 /dev/urandom >SALT
fi
#prevent cold build from always failing due to missing client binary
if ! test -f client/clientApp; then
  head -c 8 /dev/urandom >client/clientApp
fi
cd host/
bootdev="${bootD}" luksdev="${luksdev}" luksUUID="${luksUUID}" sudo -Eu $SUDO_USER cargo build --release
cp target/release/host ../dracut/host
strip ../dracut/host
cd ..
sed -i "3i \Before=${systemdsvc}" dracut/tkey-tpm-luks.service
test -d /lib/dracut/modules.d/90tkey-tpm-luks/ && rm -rf /lib/dracut/modules.d/90tkey-tpm-luks/ || true
mkdir -p /lib/dracut/modules.d/90tkey-tpm-luks/
mv dracut/ /lib/dracut/modules.d/90tkey-tpm-luks/ #makes module
dracut --force --verbose                          #rebuilds initramfs
echo "must reboot to make sure PCRs are updated (necessary since we rebuilt initramfs and tpm still has old PCR values) then run setup_part2.sh."
