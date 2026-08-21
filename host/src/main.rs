// this bin mounts /boot from it reads in client (intentionally outside of PCR checks check SECURITY.md for
// rationale behind this choice) takes nonce gives to tpm and if tpm ever refuses to sign host sends
// failure onto client then client requires user interaction before we can move onto passphrase
// another warning is shown at systemd-ask-password (even though we can guarantee it since we
// couldnt verify software running on host) this is vital to allow user to update kernel,xen or grub
// which is extremely important
use chacha20::cipher::stream::StreamCipher;
use host::{
    ClientError, ClientMessage, HostErr, HostMessage, Tkey, auth_with_tkey_and_tpm, check_status, 
};
use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::{
    error::Error,
    io::Read,
    process::{Command, Stdio},
};
use zeroize::Zeroize;

fn main() -> Result<ExitCode, Box<dyn Error>> {
    fs::create_dir_all("/mnt/boot")?;
    let mount_args = &[host::BOOTDEVICE, "/mnt/boot"];
    let mount = Command::new("/usr/bin/mount")
        .args(mount_args)
        .status()?
        .success();
    if !mount {
        Err("failed to mount, auto detection of boot device was wrong.")?;
    }

    let bin = fs::read("/mnt/boot/client")?;

    let (mut tkey, trustworthy,mut cipher) = auth_with_tkey_and_tpm(bin)?;

    //mirrors 3 tries client allows.
    for tries in 1..=3 {
        let status = check_status(&mut tkey);
        //first thing clientapp should do is signal its ready 4 passphrase if it does not print the error and exit
        if !matches!(status, Ok(ClientMessage::Ready4pass)) {
            eprintln!("expected Ready4pass, but instead received :");
            dbg!(&status);
            Err(ClientError::OutOfsync)?
        }

        if let Err(e) = ask_for_password(&mut tkey, trustworthy, &mut cipher) {
            if matches!(e, ClientError::PassLen | ClientError::Blake2) {
                let reason = if matches!(e, ClientError::PassLen) {
                    "password length error"
                } else {
                    "blake2 error"
                };
                println!("{reason}, try again. {}/3 tries", tries);
                continue;
            } else {
                Err(e)?
            }
        }
        match decrypt(&mut tkey, &mut cipher) {
            Ok(_) => return Ok(ExitCode::SUCCESS),
            Err(e @ (HostErr::CryptsetupKilled | HostErr::CryptsetupErr)) => {
                let reason = if matches!(e, HostErr::CryptsetupErr) {
                    "wrong password"
                } else {
                    "cryptsetup killed"
                };
                println!("{reason}, try again. {}/3 tries", tries);
                continue;
            }
            Err(e) => {
                println!("{e}");
                Err(e)?;
            }
        };
    }
    println!("couldn't decrypted system, 3/3 tries exhausted.");
    Ok(ExitCode::FAILURE)
}
fn ask_for_password(
    tkey: &mut Tkey,
    trustworthy: bool,
    cipher: &mut host::ChaCha20Cipher,
) -> Result<(), ClientError> {
    //can't control whether the warning will appear if system hasn't been verified but might as well
    //try to warn user twice (tkey already gates proceeding with touch)
    let prompt = if trustworthy {
        "input passphrase ALWAYS be sure tkey led is green before doing so."
    } else {
        "tpm REFUSED to unseal, system might be tampered with. Input password at your own risk."
    };
    let pass = Command::new("/usr/bin/systemd-ask-password")
        .arg(prompt)
        .output()?;

    let mut passphrase_bytes = pass.stdout;
    let mut passphrase = match String::try_from(passphrase_bytes.clone()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("passphrase to utf-8 parse error: {e}");
            String::from_utf8_lossy(&passphrase_bytes).to_string()
        }
    };
    passphrase_bytes.zeroize();
    let mut pass_len = passphrase.trim_end().len();
    if pass_len > u8::MAX as usize || pass_len < 8 {
        passphrase.zeroize();
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    //writting password length to client
    tkey.write_all(&[pass_len as u8])?;
    //sending actual password to client
    let mut passphrase_encrypted = vec![0u8; pass_len];
    cipher.apply_keystream_b2b(passphrase.trim_end().as_bytes(), &mut passphrase_encrypted);
    tkey.write_all(&passphrase_encrypted)?;

    passphrase.zeroize();
    pass_len.zeroize();
    match check_status(tkey) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync),
    }
}

fn decrypt(
    tkey: &mut Tkey,
    cipher: &mut host::ChaCha20Cipher,
) -> Result<(), HostErr> {
    let args = &[
        "open",
        "--key-file",
        "-",
        "--keyfile-size",
        "32",
        "--batch-mode",
        host::ENCRYPTEDDISK,
        host::LUKSUUID,
    ];
    let mut keyfile = [0u8; 32];
    tkey.read_exact(&mut keyfile)?;
    cipher.apply_keystream(&mut keyfile);
    let mut cryptsetup = Command::new("/usr/bin/cryptsetup")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()?;
    {
        let mut stdin = match cryptsetup.stdin.take() {
            Some(stdin) => stdin,
            None => {
                return Err(HostErr::PipeError);
            }
        };
        match stdin.write_all(&keyfile) {
            Ok(()) => keyfile.zeroize(),
            Err(e) => {
                keyfile.zeroize();
                tkey.write_all(&[HostErr::DecryptionError as u8])?;
                Err(e)?
            }
        }
    }

    //extract status code (.code() should only fail if process is killed which is very unlikely)
    let status_code = match cryptsetup.wait()?.code() {
        Some(s) => s,
        None => {
            tkey.write_all(&[HostErr::DecryptionError as u8])?;
            return Err(HostErr::CryptsetupKilled);
        }
    };
    if status_code == 0 {
        println!("successful decryption moving on..");
        let _ = tkey.write_all(&[HostMessage::DecryptionSuccess as u8]);
        Ok(())
    } else {
        eprintln!("cryptsetup exited with error code {}.", status_code);
        tkey.write_all(&[HostErr::DecryptionError as u8])?;
        Err(HostErr::CryptsetupErr)
    }
}
