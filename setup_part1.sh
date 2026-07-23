#!/usr/bin/env bash
#basic setup script part 1/2
# note: doesn't work for qubes.
set -euo pipefail
if [[ "$EUID" != "0" ]]; then
  echo must be root to run setup_part1
  exit 1
fi
export systemdsvc=$(systemctl list-units | grep systemd-cryptsetup@luks | grep -v /run/credentials | awk '{print $1}')
cd host/
touch client/clientApp
sudo -u $SUDO_USER cargo build --release
mv target/release/host ../dracut/host
cd ..
sed -i "3i\Before=\${systemdsvc}" dracut/tkey-tpm-luks.service
mkdir -p /lib/dracut/modules.d/90tkey-tpm-luks/
mv dracut/ /lib/dracut/modules.d/90tkey-tpm-luks/ #makes module
dracut --force --verbose                          #rebuilds initramfs
echo "must reboot to make sure PCR are updated (necessary since we rebuilt initramfs and tpm still has old PCR values) then run setup_part2.sh."
