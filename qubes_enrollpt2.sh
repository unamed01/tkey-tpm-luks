#!/bin/bash
set -euo pipefail

if [[ "$EUID" != "0" ]]; then
  echo must run as root
  exit 1
fi
disp_template=$(qubes-prefs default_dispvm)
disp_name="tkey-enroll"
builder="tkey-builder" #change this if your vm name is different..
bootD="$(findmnt -no SOURCE /boot)"
luksUUID="$(cat /etc/crypttab | awk '{print $1}')"
luksD="/dev/nvme0n1p3" #change here if you didn't use auto partitioning.
# if you change this make sure to also change last command to make sure it can execute the bin directly like xfce4-terminal can.
enroll_term="xfce4-terminal"
mkdir -p ~/tkey-files && cd ~/tkey-files #make sure were on the right dir

#cleanup policy on exit
trap 'rm -f /etc/qubes/policy.d/20-tkey-tpm-luks.policy' EXIT

if ! test -f enroll.sh; then
  echo ERROR: enroll.sh couldn\'t be found.
  echo make sure to also bring enroll.sh to dom0 to enroll PCRs onto tpm.
  echo this is most likely a bug since part1 should\'ve brought it to dom0 open a github issue if applicable.
  exit 3
fi

bash enroll.sh # actually enroll onto tpm with tpm2-tools.

if ! qvm-prefs "$disp_name"; then
  qvm-create --class DispVM --label red --property netvm='' -t "$disp_template" "$disp_name"
else
  qvm-kill "$disp_name" || true
  qvm-start "$disp_name" &
fi

qvm-run "$builder" "rm /home/user/QubesIncoming/dom0/tpm_pubkey_raw.bin" || true
qvm-copy-to-vm "$builder" "tpm_pubkey_raw.bin"
qvm-run "$builder" mv /home/user/QubesIncoming/dom0/tpm_pubkey_raw.bin /home/user/tkey-tpm-luks/tpm_pubkey_raw.bin
qvm-run -p "$builder" 'cd /home/user/tkey-tpm-luks/client/ && cargo build --release && llvm-objcopy --input-target=elf32-littleriscv --output-target=binary target/riscv32i-unknown-none-elf/release/client clientApp '
echo "type to to copy to $disp_name (copying qubes_enroll)"
notify-send "qubes_enrollpt2" "type to to copy to $disp_name (copying qubes_enroll)"
qvm-run -p "$builder" "cd /home/user/tkey-tpm-luks/host && bootdev=\"${bootD}\" luksdev=\"${luksD}\" luksUUID=\"${luksUUID}\" cargo build --release && qvm-copy target/release/qubes_enroll"
#allow disp to run verify bin with qrexec svc we setup in part1
cat >/etc/qubes/policy.d/20-tkey-tpm-luks.policy <<EOF
qubes.TPMProxy * $disp_name dom0 allow
EOF
if ! qvm-run "$disp_name" command -v "$enroll_term"; then
  echo "$disp_name" doesn\'t have "$enroll_term"
  echo must have "$enroll_term" to run
  exit 2
fi
usb="$(qvm-usb list | grep 'Tillitis' | awk '{print $1}')"
qvm-usb attach "$disp_name" "$usb"
qvm-run -u root "$disp_name" "$enroll_term" -x /home/user/QubesIncoming/$builder/qubes_enroll
