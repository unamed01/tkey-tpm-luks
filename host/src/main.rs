// this bin mounts /boot from it reads in client (intentionally outside of PCR checks check SECURITY.md for
// rationale behind this choice) takes nonce gives to tpm and if tpm ever refuses to sign host sends
// failure onto client then client requires user interaction before we can move onto passphrase
// another warning is shown at systemd-ask-password (even though we can guarantee it since we
// couldnt verify software running on host) this is vital to allow user to update kernel,xen or grub
// which is extremely important
use host::{ClientError, ClientMessage, HostErr, HostMessage, check_status, verify};
use serialport::SerialPort;
use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;
use std::{
    error::Error,
    io::Read,
    process::{Command, Stdio},
};
use tkeyclient::TKey;
use zeroize::Zeroize;

fn main() -> Result<ExitCode, Box<dyn Error>> {
    fs::create_dir_all("/mnt/boot")?;
    let mount_args = &[host::BOOTDEVICE, "/mnt/boot"];
    let mount = Command::new("/usr/bin/mount")
        .args(mount_args)
        .status()?
        .success();
    if !mount {
        println!("failed to mount");
        return Ok(ExitCode::FAILURE);
    }
    let bin = fs::read("/mnt/boot/client")?;
    let mut tkey = TKey::connect(None)?;
    tkey.load_app(bin.as_slice(), None)?;
    drop(tkey);
    let mut tkey = serialport::new("/dev/ttyACM0", 62500)
        .timeout(Duration::from_secs(30))
        .open()?;
    let mut nonce = [0u8; 32];
    tkey.read_exact(&mut nonce)?;

    //if tpm hasn't signed
    let mut trustworthy: bool = match verify(&nonce) {
        Ok(sig) => {
            tkey.write_all(&[HostMessage::TpmSigned as u8])?;
            tkey.write_all(&sig)?;
            true
        }
        Err(e) => {
            eprintln!("{e}");
            eprintln!("tpm REFUSED, to sign nonce");
            tkey.write_all(&[HostErr::TpmRefusedToSign as u8])?;
            false
        }
    };
    match check_status(&mut *tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        Err(e @ (ClientError::InvalidSig | ClientError::MalformedSig | ClientError::BadPubkey)) => {
            eprintln!("{}", e);
            eprintln!("tkey FAILED to verify nonce signature system is untrustworthy.");
            trustworthy = false;
        }
        _ => return Err(ClientError::OutOfsync)?,
    }
    let trustworthy = trustworthy;
    let mut tries = 0;
    loop {
        if tries >= 3 {
            eprintln!("decryption failed too many attempts.");
            return Ok(ExitCode::FAILURE);
        }
        tries += 1;
        match check_status(&mut *tkey) {
            Ok(ClientMessage::Ready4pass) => {}
            Err(e) => return Err(e)?,
            _ => return Err(ClientError::OutOfsync)?,
        }
        if let Err(e) = ask_for_password(&mut tkey, trustworthy) {
            if matches!(e, ClientError::PassLen) {
                println!("password length error, try again.");
                continue;
            } else {
                Err(e)?
            }
        }
        match decrypt(&mut tkey) {
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
                return Err(e)?;
            }
        };
    }
}
fn ask_for_password(tkey: &mut Box<dyn SerialPort>, trustworthy: bool) -> Result<(), ClientError> {
    //we cant control this warning will actually appear since
    let prompt = if trustworthy {
        "input passphrase ALWAYS be sure tkey led is green before doing so."
    } else {
        "TPM REFUSED TO UNSEAL, system might be tampered with. Input password at your own risk."
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
        _ = check_status(tkey.as_mut());
        return Err(ClientError::PassLen);
    }
    //writting password length to client
    tkey.write_all(&[pass_len as u8])?;
    //sending actual password to client
    tkey.write_all(passphrase.trim_end().as_bytes())?;
    passphrase.zeroize();
    pass_len.zeroize();
    match check_status(tkey.as_mut()) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync),
    }
}

fn decrypt(tkey: &mut Box<dyn SerialPort>) -> Result<(), HostErr> {
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
        match stdin.write_all(&keyfile) {
            Ok(()) => keyfile.zeroize(),
            Err(e) => {
                keyfile.zeroize();
                Err(e)?
            }
        }
    }
    //extract status code (.code() should only fail if process is killed which is very unlikely)
    let status_code = match cryptsetup.wait()?.code() {
        Some(s) => s,
        None => {
            tkey.write_all(&[HostMessage::DecryptionError as u8])?;
            return Err(HostErr::CryptsetupKilled);
        }
    };
    if status_code == 0 {
        println!("successful decryption moving on..");
        let _ = tkey.write_all(&[HostMessage::DecryptionSuccess as u8]);
        Ok(())
    } else {
        eprintln!("cryptsetup exited with error code {}.", status_code);
        tkey.write_all(&[HostMessage::DecryptionError as u8])?;
        Err(HostErr::CryptsetupErr)
    }
}
