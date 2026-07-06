# tkey-tpm-luks2

luks2 + Tillitis Tkey, Full Disk Encryption and measured boot solution for Linux and [Qubes](https://qubes-os.org/)

## Why

Standard TPM-sealed LUKS unlock (PCR policy only) protects against offline disk theft but not against a persistent evil-maid attack that can extract or replay a TPM-only secret, since the TPM alone has no way to prove *freshness* or bind the unlock to a physical token which the owner carries. `tkey-tpm-luks2` adds a hardware root of trust — a [TKey](https://tillitis.se/) — as a second factor that must physically be given a signed nonce (from TRNG) from the TPM before the disk can unlock, and mixes a user passphrase with CDI (Compound Device Identifier) into the final keyfile so possession of the TKey alone and neither is passphrase possession alone sufficient must have passphrase AND Tkey for disk decryption.

## Threat model

- **In scope:** evil-maid attacks against a machine left unattended (firmware/bootloader tampering, PCR replay, disk exfiltration).
- **Assumption:** the TPM's PCR measurements are trustworthy up to the point the initramfs runs.
- **Out of scope:** attacks against the TKey's own supply chain and physical coercion.

## Architecture

```
 ┌─────────────┐      challenge-nonce     ┌─────────────┐
 │     TPM2    │ ◄─────────────────────── │    TKey     │
 │  (PCR-sealed│                          │   (verifed  │
 │  P-256 key) │ ───────────────────────► │   boot)     │
 └──────┬──────┘        signature         └─────────────┘
        │
        │ verifies TPM sig against
        │ baked-in pubkey 
        ▼
 ┌───────────────────────────────┐
 │  BLAKE2s(CDI || passphrase)   │
 │        → LUKS2 keyfile        │
 └───────────────────────────────┘
```

1. **PCR-sealed signing key.** A P-256 ECDSA key lives inside the TPM (and cannot be extracted out.), sealed to a PCR policy (PCR 0:firmware 4:bootloader 8:initramfs 9:grub settings/cmdline)so it will only ever unseals on an unmodified boot chain.
2. **TKey verification.** The TKey holds a baked-in TPM public key. During boot, the TPM signs a challenge and the TKey verifies that signature before deriving its own response — this is the physical-possession factor.
3. **Key derivation.** The final LUKS2 keyfile is `BLAKE2s(CDI || passphrase)`, where CDI (Compound Device Identifier) most importantly its generated deterministically from clientApp bytes so if clientApp is ever tampered with keyfile will be entirely different even with correct passphrase so luks cannot unlock.
4. **Boot integration.** A dracut module wires the unlock flow into the initramfs, "host" bin deals with all the backend complexity and gives user a very clear 0 or 1 of whether computer is trustworthy

## Components

| Component | Role |
|---|---|
| TKey app | Verifies TPM signature, derives CDI-based response |
| Host binary (Rust) | Talks to TKey over USB/UART, talks to TPM via `tss-esapi`, receives the LUKS keyfile |
| dracut module | Hooks the unlock binary into the initramfs boot path |
| Enrollment script | setup: seal the TPM key, register the TKey pubkey, write the LUKS keyslot |

## Update path

re-enrollment is necessary on every update which changes anything that's measured in relevant PCRs, note that for this exact reason if tpm refuses to unseal tkey will flash **YELLOW** if host sends error directly and **PURPLE** if Tkey got sent an invalid signature for current nonce from host note that under normal usage LED should never flash purple unless you've by accident enrolled new PCR values without recompilling client so its treated differently. You must physically touch Tkey sensor to proceed if you don't it will fail closed instead. then you can touch Tkey unlock disk as normal ignoring errors then you rerun enroll.sh recompile clientApp overwrite current one in /boot/client then run enroll binary again.

> [!WARNING]
> this software is still in alpha use at your own risk

## usage normal linux distros (must be dracut based and use systemd-boot)

#### **make sure you make a backup before proceeding.**

**firstly** you should make sure you're using a linux distro that uses dracut + systemd-boot which is what its been tested under, if you get it working under another linux distro please let me know so I can update tested list below. Feedback is really appreciated.

**has been tested on QubesOS 4.3.1 which is fedora 41 based with dracut 103-4.f41 which has the same underlying initramfs enviroment as any other fedora system**

**please open a github issue if any of this doesn't work!**

theres very easy to use setup scripts that will set everything for you

```bash
sudo ./setup_part1.sh
```

if everything went right reboot then run

```bash
sudo ./setup_part2.sh
```

after everything is enrolled just reboot type passphrase in and everything should just work, and in a case it does not it will fall trough to your normal unlock sequence.

## QubesOS usage (tested for Qubes 4.3.1)

(setup scripts coming to Qubes in a later update)

builder is the placeholder name of whatever qube which you'll be actually compiling the source code under change as needed

#### **make sure you make a backup before proceeding.**

**please open a github issue if any of this doesn't work!**

Firstly must compile host binary inside **builder**

```bash
cd host && cargo build --release
mv target/release/host dracut/host
```

Then from **dom0** run these commands to copy all needed files onto dom0 note that tkey-tpm-luks2.service will fail and let it

```bash
qvm-run -p builder cat /home/user/tkey-tpm-luks2/dracut/module-setup.sh > module-setup.sh
qvm-run -p builder cat /home/user/tkey-tpm-luks2/dracut/host > host 
qvm-run -p builder cat /home/user/tkey-tpm-luks2/dracut/tkey-tpm-luks2.service > tkey-tpm-luks2.service
qvm-run -p builder cat /home/user/tkey-tpm-luks2/enroll.sh > enroll.sh # going to be used later
qvm-run -p builder cat /home/user/tkey-tpm-luks2/host/target/release/verify > verify # going to be used later, note the path to it
sudo chown root:root host module-setup.sh tkey-tpm-luks2.service
sudo chmod +x host #make sure host is executable
sudo mkdir -p /lib/dracut/modules.d/90tkey/ && mv -t /lib/dracut/modules.d/90tkey/ host module-setup.sh tkey-tpm-luks2.service 
sudo dracut --force --verbose #rebuild initramfs
```

Before we reboot still in **dom0** we must whitelist the USB controller that your USB controller is whitelisted so initramfs can talk to tkey find the indetifier by running this command below note that if you use a USB keyboard this might already be setup for you but do double check regardless.

```bash
lspci | grep -i usb
```

I personally have "04:00.4 USB controller: Advanced Micro Devices, Inc. [AMD] USB 3.1 " so thats what i'll use.
now edit /etc/default/grub and at the end of GRUB_CMDLINE_LINUX="..." add note rd.qubes.hide_all_usb should already be there. your pcie device indetifier should look something like this: 04:00.4

```grub
GRUB_CMDLINE_LINUX="... rd.qubes.hide_all_usb rd.qubes.dom0_usb=04:00.4" # change with whatever identifier you got from lspci 
```

Rebuild grub with new config then reboot

```bash
grub2-mkconfig -o /boot/grub2/grub.cfg
systemctl reboot #reboot is necessary to make sure enrolled PCRs are correct.
```

After reboot now you must enroll current PCR values this is also from **dom0**

```bash
sudo ./enroll.sh #follow prompts and make sure all current PCRs are non zero
qvm-copy-to-vm builder tpm_pubkey_raw.bin
```

Now make your RPC service for the binary verifier binary put this in /etc/qubes-rpc/qubes.TPMProxy

```bash
#!/bin/bash

exec /home/user/verify #change if the path to verify bin imported from earlier
```

Then write this in /etc/qubes-rpc/policy/qubes.TPMProxy its recommended you use a dispvm for enrollment with no netvm change disp**** to match

```policy
disp**** dom0 allow #change to match whatever dispvm**** you'll be enrolling it in.
```

Then from builder compile client app from **builder**

```bash
mv QubesIncoming/dom0/tpm_pubkey_raw.bin tkey-tpm-luks2/ #or wherever you have this project's root at
cd tkey-tpm-luks2/client 
cargo build --release
llvm-objcopy --input-target=elf32-littleriscv --output-target=binary target/riscv32i-unknown-none-elf/release/client clientApp #gets in the right format for tkey
cd ../host
cargo build --release #MUST recompile to make sure ClientApp is there
```

Get clientApp in the right place now from dom0 take it from builder and place onto /boot

```bash
qvm-run -p builder cat /home/user/tkey-tpm-luks2/client/clientApp > client
sudo cp client /boot/client
```

Now it is recommended you use a airgapped dispVM for passphrase enrollment and this is what will be demonstrated this part is still from **builder**
start your dispVM then from builder run this and copy files to your new dispVM

```bash
qvm-copy target/release/qubes_enroll
```

Now plug in your tkey and attach it to your dispVM this can be done easily by the usb widget on the taskbar, then just run the binary

```bash
sudo QubesIncoming/builder/qubes_enroll #change if your builder vm is not named builder
```

Now from dom0 do this to take keyfile from disp and enroll

```bash
qvm-run -p disp**** cat /tmp/keyfile > /tmp/keyfile #takes keyfile from disp
sha256sum /tmp/keyfile # make sure they match whats on disp
```

After you made sure keyfile matches make SURE to shred keyfile on disp.

```bash
sha256sum /tmp/keyfile # make sure they match
sudo shred -uxz /tmp/keyfile
```

Now you can shutoff disp we'll be moving onto **dom0**

```bash
sudo cryptsetup luksAddKey  --new-key-slot 1 -y --keyfile-size 32 /dev/nvme0n1p3 /tmp/keyfile #change disk as needed and type in your current passphrase
sudo cryptsetup open --test-passphrase --key-file /tmp/keyfile --keyfile-size 32 /dev/nvme0n1p3 #also change disk as needed.
shred -uxz /tmp/keyfile #MAKE SURE you do this 
```

Now reboot and everything should just work!
