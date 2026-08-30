# tkey-tpm-luks

luks2 + Tillitis Tkey, hardware aware Full Disk Encryption and measured boot solution for Linux and [QubesOS](https://qubes-os.org/). Fully in Rust.

## Why?

**Secure boot's flaws:**

Secure boot lacks in compatibility (specially anything non windows), in security (rogue CA, downgrade attacks..etc) and microsoft helped make it. This solution tries to fix security problems for a subset of underserved systems (QubesOS/linux for now) uses a TPM 2.0 to implement measured boot + luks2 drive decryption built in, using [Tkey](https://www.tillitis.se/)  physical security key which measures the system's state alongside TPM and allowing for secure luks2 keyfile derivation for disk unlocking. A lot more secure since for each disk unlock the entire boot chain must match byte per byte what it was at enrollment which entirely fixes the possibility of a downgrade attack since there is no signature attached only a hash that gets checked by TPM if it doesn't match its instantly evident to the user which user can deal with accordingly.

**Why encrypt hash and keyfile?**

tkey-tpm-luks is hardware aware, whats the point in locking down boot process if all you need is to log the keyfile then encryption is meaningless. Side stepping measured boot and having a USB sniffer take keyfile/passphrase then decrypting disk later is just as good as having malware in the kernel/initramfs for this very reason we encrypt host-client communication so a sniffer would get nothing (also the reason to use randomly generated nonce). The rest (nonce, signature..etc) don't get encrypted since they're non sensitive which saves CPU precious time.

## Architecture
**numbers reflect the ones below**
```
  TKey              Host              TPM
    |                 |                 |
    | 1  move nonce |                 |
    |----------------------------------->
    |                 |                 |
    |                 |                 +-+ 2  checks PCRs,
    |                 |                 | |    signs nonce
    |                 |                 +-+
    | 1  X25519 key exchange            |
    |    (in parallel)|                 |
    <=================>                 |
    |                 | 2  signature    |
    |                 <-----------------|
    |                 |                 
    | 2  signature    |                 
    <-----------------|                 
    |                 |                 
    |                 |                 
    +-+ 3  verify sig |                 
    | |    (baked-in pubkey)            
    +----------------->                 
    |                 |                 
    |                 +-+ 3  hash passphrase
    |                 | |    (Argon2id) 
    |                 +-+               
    |                 |                 
    | 4  pass_hash*   |                 
    <-----------------|                 
    |                 |                 
    +-+ 4 decrypt hash, keyfile =      
    | |    blake2(CDI + hash)           
    +-+               |                 
    |                 |                 
    | 4 keyfile*     |                 
    |----------------->                 
                      |                 
                      +-+ 5 decrypt keyfile,
                      | |    cryptsetup unlock LUKS2
                      +-+               
```

**The * means ChaCha20-encrypted over the wire**

If step 3 fails -> TPM won't sign, Tkey will flash YELLOW, Touch to move past (only meant to be used for grub,kernel or xen updates)

TPM sealed keypair is created to PCR values that ensure every single byte of firmware, bootloader, initramfs, xen and kernel must be the same byte for byte, before TPM will sign anything.
1. Tkey generates nonce and sends to TPM if PCRs match TPM will sign nonce, while in parallel host and Tkey will do X25519 key exchange to encrypt sensitive traffic.
2. if PCRs match (nothing in the bootchain was tampered with) TPM will sign nonce, signature gets sent to Tkey where it will verify signature by using public key which was baked in at compile time (if publickey is changed/tampered with CDI will change so disk can't unlock)
CDI: (compound device Identifier) Tkey's, way to ensure currently loaded app hasn't been tampered with its blake2 out of unique device secret + blake(binary) if any byte in binary changes CDI also changes, this guarantees PublicKey is the same.
3. if signature matches or user bypassed verification by physically touching Tkey e.g for an update (tamper evident by showing green when everything checks out and yellow/purple if not), Tkey will move onto to receive passphrase. Host will take in passphrase then hash it using Argon2id encrypt hash using ChaCha20
4. Tkey will decrypt hash and do blake2(*CDI + decrypted_passphrase_hash) and that becomes the keyfile, which Tkey will encrypt and send to host
5. host will decrypt keyfile, then use cryptsetup to unlock disk if passphrase and CDI were correct disk unlocks!



## usage normal linux distros (must use dracut and use systemd)

> [!WARNING]
> this software is made to be the least intrusive as it can be, but do make a backup before proceeding (still in beta).

#### **make sure you make a backup before proceeding.**

**firstly** you should make sure you're using a linux distro that uses dracut + systemd (such as fedora) which is what its been tested under, if you get it working under another linux distro please let me know so I can update tested list below. Feedback is really appreciated.

**has been tested on QubesOS 4.3.1 which is fedora 41 based, with dracut (version 103-4.f41) which has the same underlying initramfs enviroment as other fedora systems**

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

#### updates

Simply run setup_part2.sh again, will make sure 

```bash
sudo bash setup_part2.sh
```


## QubesOS usage (tested for Qubes 4.3.1)

#### **make sure you make a backup before proceeding.**

**please open a github issue if any of this doesn't work!**

Firstly make a fully new builder Qube clone this repo and audit the code inside it. And install deps
```bash
sudo apt install llvm rustup libtss2-dev gcc libudev-dev
sudo apt install qubes-usb-proxy #if using minimal
rustup default stable 
rustup target add riscv32i-unknown-none-elf
git clone https://github.com/unamed01/tkey-tpm-luks.git
```

After you've looked at the code (don't skip this step) take the qubes setup script and move into dom0, installing the single dependency.
```bash
qvm-run -p builder cat /home/user/tkey-tpm-luks/qubes_enrollpt1.sh > qubes_enrollpt1.sh
sudo qubes-dom0-update grub2-efi-x64-modules #make sure you have qubes TPM module in dom0
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
#### updates 

Just run qubes_enrollpt2.sh again for re enrollment will walk trough the same process as the first time enrolling new PCR values.
```bash
sudo bash qubes_enrollpt2.sh
```
