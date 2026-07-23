#!/usr/bin/env bash
#basic setup script part 1/2
# note: doesn't work for qubes.
set -euo pipefail
if [[ "$EUID" != "0" ]]; then
  echo must be root to run setup_part1
  exit 1
fi
bootD="$(findmnt -no SOURCE /boot)"
luksUUID="$(cat /etc/crypttab | awk '{print $1}')"
systemdsvc="$(systemctl list-units | grep 'systemd-cryptsetup@luks' | grep -v '/run/credentials' | awk '{print $1}')"
luksD="$(findmnt -no /)" # might be wrong if using lvm
if ! cryptsetup isLuks "$luksD"; then
  echo "faled to find correct luks2 disk"
  echo "$luksD is NOT a luks device change the luksD value on this script to your disk."
  exit 4
fi
cd host/
sudo -u $SUDO_USER bootdev=\"${bootD}\" luksdev=\"${luksD}\" luksUUID=\"${luksUUID}\" cargo build --release
mv target/release/host ../dracut/host
cd ..
sed -i "3i \Before=${systemdsvc}" dracut/tkey-tpm-luks.service
mkdir -p /lib/dracut/modules.d/90tkey-tpm-luks/
mv dracut/ /lib/dracut/modules.d/90tkey-tpm-luks/ #makes module
dracut --force --verbose                          #rebuilds initramfs
echo "must reboot to make sure PCR are updated (necessary since we rebuilt initramfs and tpm still has old PCR values) then run setup_part2.sh."
