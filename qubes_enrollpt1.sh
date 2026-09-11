#!/bin/bash
set -euo pipefail

if [[ "$EUID" != "0" ]]; then
  echo must run as root
  exit 1
fi

builder="tkey-builder" #change this if your vm name is different..
bootD="$(findmnt -no SOURCE /boot)"
luksUUID="$(cat /etc/crypttab | awk '{print $1}')"
luksD="/dev/nvme0n1p3" #change here if you didn't use auto partitioning.
systemdsvc="$(systemctl list-units | grep 'systemd-cryptsetup@luks' | grep -v '/run/credentials' | awk '{print $1}')"
systemdsvc="${systemdsvc//\\/\\\\}"
mkdir -p ~/tkey-files && cd ~/tkey-files
if ! cryptsetup isLuks "$luksD"; then
  echo "$luksD is NOT a luks device change \$luksD on this script to your correct disk before proceeding."
  exit 1
fi
if ! qvm-run "$builder" 'test -d /home/user/tkey-tpm-luks '; then
  echo "ERR: dir /home/user/tkey-tpm-luks doesn't exist "
  echo "please make sure you've cloned the repo AND checked the code in $builder"
  exit 4
fi
if ! qvm-run "$builder" 'test -f /home/user/tkey-tpm-luks/SALT'; then
  if ! [[ -f "/boot/SALT" ]]; then
    head -c 32 /dev/urandom >/boot/SALT
  fi
  qvm-copy-to-vm "$builder" SALT
  qvm-run "$builder" 'mv /home/user/QubesIncoming/dom0/SALT /home/user/tkey-tpm-luks/SALT'
fi

#prevent cold build from always failing due to missing client binary
if ! qvm-run "$builder" 'test -f /home/user/tkey-tpm-luks/client/clientApp'; then
  qvm-run "$builder" 'head -c 8 /dev/urandom > /home/user/tkey-tpm-luks/client/clientApp'
fi

qvm-run -p "$builder" "cd /home/user/tkey-tpm-luks/host && bootdev=\"${bootD}\" luksdev=\"${luksD}\" luksUUID=\"${luksUUID}\" cargo build --release"
mkdir -p dracut/
#these are for later
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/host/target/release/verify >verify
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/host/target/release/Qubes_Kill_slot >Qubes_Kill_slot
chmod +x verify Qubes_Kill_slot
strip verify Qubes_Kill_slot
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/enroll.sh >enroll.sh
chmod +x enroll.sh
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/qubes_enrollpt2.sh >qubes_enrollpt2.sh
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/qubes_KillSlot.sh >qubes_KillSlot.sh
#get everything from builder
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/host/target/release/host >dracut/host
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/dracut/module-setup.sh >dracut/module-setup.sh
qvm-run -p "$builder" cat /home/user/tkey-tpm-luks/dracut/tkey-tpm-luks.service >dracut/tkey-tpm-luks.service
#makes sure the service starts right before systemd-cryptsetup which is how we can make it fallback
# in the case of testing so even if anything goes wrong you can still just type in your passphrase
sed -i "3i \Before=${systemdsvc}" dracut/tkey-tpm-luks.service
strip dracut/host || true
chmod +x dracut/host
test -d /lib/dracut/modules.d/90tkey && rm -rf /lib/dracut/modules.d/90tkey || true
mv dracut /lib/dracut/modules.d/90tkey
#allow dom0 to see tkey on initramfs, bailing if it already can (e.g already setup for usb keyboard)
if ! grep 'rd.qubes.dom0_usb' /etc/default/grub &>/dev/null; then
  usbController="$(lspci | grep -i 'usb controller' | awk '{print $1}' | tr '\n' ',')"
  sed -i '/rd\.qubes\.hide_all_usb/ s/"$/ rd\.qubes\.dom0_usb='"$usbController"'"/' /etc/default/grub
fi
# Backup first
test -f /boot/efi/EFI/BOOT/BOOTX64.EFI.bak || cp /boot/efi/EFI/BOOT/BOOTX64.EFI /boot/efi/EFI/BOOT/BOOTX64.EFI.bak
test -f /boot/efi/EFI/qubes/grubx64.efi.bak || cp /boot/efi/EFI/qubes/grubx64.efi /boot/efi/EFI/qubes/grubx64.efi.bak
#ensure deterministic PCR 8,9 generation (see issue below)
#https://github.com/fedora-silverblue/issue-tracker/issues/285
systemctl --global mask grub-boot-success.timer
systemctl --global mask grub-boot-success.service
systemctl --global mask grub-boot-indeterminate.service
chmod -x /etc/grub.d/10_reset_boot_success || true
chmod -x /etc/grub.d/08_fallback_counting || true
#modules from https://github.com/QubesOS/qubes-grub2/blob/00e34f13235d39f81fa0130500db43aa803c8a60/grub2.spec.in#L441 which are default.
# this is needed since by default qubes' grub doesnt have the tpm module so this is needed to make sure PCRs 8,9 arent 0s.
grub2-mkimage \
  -O x86_64-efi \
  -o /boot/efi/EFI/BOOT/BOOTX64.EFI \
  -p /EFI/qubes \
  -d /usr/lib/grub/x86_64-efi \
  all_video boot btrfs cat configfile cryptodisk echo efifwsetup efinet ext2 f2fs \
  fat font gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool \
  gfxmenu gfxterm gzio halt hfsplus http increment iso9660 jpeg \
  loadenv loopback linux lvm lsefi lsefimmap luks luks2 mdraid09 mdraid1x minicmd net \
  multiboot multiboot2 normal part_apple part_msdos part_gpt \
  password_pbkdf2 pgp png reboot regexp search search_fs_uuid search_fs_file \
  search_label serial sleep syslinuxcfg test tftp video xfs zstd \
  backtrace chain usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug \
  keylayouts at_keyboard \
  tpm_verifier || {
  echo "make sure you have grub2-efi-x64-modules installed."
  exit 9
}
grub2-mkimage \
  -O x86_64-efi \
  -o /boot/efi/EFI/qubes/grubx64.efi \
  -p /EFI/qubes \
  -d /usr/lib/grub/x86_64-efi \
  all_video boot btrfs cat configfile cryptodisk echo efifwsetup efinet ext2 f2fs \
  fat font gcry_rijndael gcry_rsa gcry_serpent gcry_sha256 gcry_twofish gcry_whirlpool \
  gfxmenu gfxterm gzio halt hfsplus http increment iso9660 jpeg \
  loadenv loopback linux lvm lsefi lsefimmap luks luks2 mdraid09 mdraid1x minicmd net \
  multiboot multiboot2 normal part_apple part_msdos part_gpt \
  password_pbkdf2 pgp png reboot regexp search search_fs_uuid search_fs_file \
  search_label serial sleep syslinuxcfg test tftp video xfs zstd \
  backtrace chain usb usbserial_common usbserial_pl2303 usbserial_ftdi usbserial_usbdebug \
  keylayouts at_keyboard \
  tpm_verifier || {
  echo "make sure you have grub2-efi-x64-modules installed."
  exit 9
}
dracut --force --verbose
#rebuild grub since we've editted /etc/default/grub to allow USB
grub2-mkconfig -o /boot/grub2/grub.cfg
#sets up qrexec svc for later. (just replaces itself  with verify bin which handles all of enrollment)
cat >/etc/qubes-rpc/qubes.TPMProxy <<EOF
#!/usr/bin/sudo bash

exec -c "$PWD/verify"
EOF

chmod +x /etc/qubes-rpc/qubes.TPMProxy

cat >/etc/qubes-rpc/qubes.LuksKillSlot <<EOF
#!/usr/bin/sudo bash

exec -c "$PWD/Qubes_Kill_slot"
EOF

chmod +x /etc/qubes-rpc/qubes.LuksKillSlot

echo "everything went well! you must now reboot so that new PCR values are enrolled correctly, then run qubes_enrollpt2.sh."
