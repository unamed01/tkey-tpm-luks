# tkey-tpm-luks2

luks2 + Tillitis Tkey, Full Disk Encryption and measured boot solution for Linux and [Qubes](https://qubes-os.org/)

## Why

Standard TPM-sealed LUKS unlock (PCR policy only) protects against offline disk theft but not against a persistent evil-maid attack that can extract or replay a TPM-only secret, since the TPM alone has no way to prove *freshness* or bind the unlock to a physical token which the owner carries. `tkey-tpm-luks2` adds a hardware root of trust a [TKey](https://tillitis.se/) as a second factor that must physically be given a signed nonce (from TRNG) from the TPM before the disk can unlock, and mixes a user passphrase with CDI (Compound Device Identifier) into the final keyfile so possession of the TKey alone and neither is passphrase possession alone sufficient must have passphrase AND Tkey for disk decryption.

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

Theres very easy to use setup scripts that will set everything for you

```bash
sudo bash setup_part1.sh
```

If everything went right reboot then run

```bash
sudo bash setup_part2.sh
```

After everything is enrolled just reboot type passphrase in and everything should just work, and in a case it does not it will fall trough to your normal unlock sequence.

## QubesOS usage (tested for Qubes 4.3.1)

#### **make sure you make a backup before proceeding.**

**please open a github issue if any of this doesn't work!**

Firstly make a fully new builder Qube clone this repo and audit the code inside it. And install deps (deps are for debian-13-minimal)
```bash
sudo apt install llvm rustup libtss2-dev gcc libudev-dev
sudo apt install qubes-usb-proxy #if using minimal
rustup default stable 
rustup target add riscv32i-unknown-none-elf
git clone https://github.com/unamed01/tkey-tpm-luks.git
```

After you've looked at the code from dom0 take the qubes setup script and move into dom0
```bash
qvm-run -p builder cat /home/user/tkey-tpm-luks/qubes_enrollpt1.sh > qubes_enrollpt1.sh
sudo bash qubes_enrollpt1.sh #check the script before running it.
```
now you just reboot to update PCR values and run part2 which part1 has already moved onto dom0 for you into /root/tkey-files
```bash
sudo su #be root so you can actually see script
cd /root/tkey-files
```
make sure to plug Tkey in then run it (will walk you trough everything)
```bash
sudo bash qubes_enrollpt2.sh
```
