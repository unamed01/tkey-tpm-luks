#!/usr/bin/env bash
# basic wrapper around enroll bin part 2/2
# user just types passphrase in can be used after updates to re-enroll PCRs.
set -euo pipefail
if [[ "$EUID" != "0" ]]; then
  echo must be root to run setup_part2
  exit 1
fi
if [[ ! -c /dev/ttyACM0 ]]; then
  echo make sure tkey is plugged in before running setup_part2
  exit 2
fi
export bootdev="$(findmnt -n -o SOURCE /boot)"
export luksdev="$(findmnt -no SOURCE /)"
export luksUUID="$(cat /etc/crypttab | awk '{print $1}')"
if ! cryptsetup isLuks "$luksdev"; then
  echo "$luksD is NOT a luks device change \$luksD on this script to your correct disk before proceeding."
  exit 1
fi
bash enroll.sh
cd client/
sudo -u $SUDO_USER cargo build --release
sudo -u $SUDO_USER llvm-objcopy --input-target=elf32-littleriscv --output-target=binary target/riscv32i-unknown-none-elf/release/client clientApp
cp clientApp /boot/client
cd ../host
sudo -u $SUDO_USER cargo build --release #make sure its built with correct bin
target/release/enroll
