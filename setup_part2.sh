#!/usr/bin/env bash
# basic wrapper around enroll bin part 2/2
# user just types passphrase in can be used after updates to re-enroll PCRs.
# note: doesn't work for qubes.
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
export luksdev="$(cryptsetup status "$(findmnt -no SOURCE / | xargs basename)" | awk '{print $2}')"
export luksUUID="luks-$(cryptsetup luksUUID $cryptsetup)"
bash enroll.sh
cd client/
sudo -u $SUDO_USER cargo build --release
sudo -u $SUDO_USER llvm-objcopy --input-target=elf32-littleriscv --output-target=binary target/riscv32i-unknown-none-elf/release/client clientApp
cp clientApp /boot/client
cd ../host
sudo -u $SUDO_USER cargo build --release #make sure its built correctly.
target/release/enroll
