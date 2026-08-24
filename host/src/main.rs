// this bin mounts /boot from it reads in client (intentionally outside of PCR checks check SECURITY.md for
// rationale behind this choice) takes nonce gives to tpm and if tpm ever refuses to sign host sends
// failure onto client then client requires user interaction before we can move onto passphrase
// another warning is shown at systemd-ask-password (even though we can guarantee it since we
// couldnt verify software running on host) this is vital to allow user to update kernel,xen or grub
// which is extremely important
use chacha20::cipher::stream::StreamCipher;
use host::{
    ClientError, ClientMessage, HostErr, HostMessage, Tkey, auth_with_tkey_and_tpm, check_status,
    get_argon2,
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

    let (mut tkey, trustworthy, mut cipher) = auth_with_tkey_and_tpm(bin)?;

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
    let mut pass_len = passphrase_bytes.len();
    if pass_len < 8 {
        passphrase_bytes.zeroize();
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    let argon2 = get_argon2();
    let mut hashed_pass = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(&passphrase_bytes, host::SALT, &mut hashed_pass) {
        eprintln!("ERR: failed to hash passphrase");
        eprintln!("this shouldn't happen, please report this issue.");
        eprintln!("{e}");
        return Err(ClientError::UnknownError);
    }
    let mut encrypted_hashed_pass = [0u8; 32];
    cipher.apply_keystream_b2b(&hashed_pass, &mut encrypted_hashed_pass);
    tkey.write_all(&encrypted_hashed_pass)?;
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

fn decrypt(tkey: &mut Tkey, cipher: &mut host::ChaCha20Cipher) -> Result<(), HostErr> {
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
        cipher.apply_keystream(&mut keyfile);
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
