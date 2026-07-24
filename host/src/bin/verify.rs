//verify.rs
use host::{HostErr, HostMessage, verify};
use std::process::ExitCode;
use std::process::{Command, Stdio};
use std::{
    io,
    io::{Read, Write, stdin, stdout},
};
use zeroize::{Zeroize, Zeroizing};

//this is the code that actually gets run in dom0.
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 32];
    std::io::stdin().read_exact(&mut nonce)?;
    match verify(&nonce) {
        Ok(s) => {
            stdout().write_all(&[HostMessage::TpmSigned as u8])?;
            stdout().write_all(&s)?;
        }
        Err(e) => {
            eprintln!("tpm refused to unseal");
            eprintln!("{}", e);
            eprintln!("moving on this is only meant to happen if you're updating.");
            stdout().write_all(&[HostErr::TpmRefusedToSign as u8])?;
        }
    };
    enroll()?;
    eprintln!("success!");
    Ok(ExitCode::SUCCESS)
}

fn enroll() -> Result<(), HostErr> {
    //this below makes sure that we can realiably write the correct passphrase onto cryptsetup for
    //decryption using stdin only.
    let mut current_pass_bytes: Zeroizing<[u8; 256]> = [0u8; 256].into();
    let mut current_pass_bytes_len: Zeroizing<[u8; 1]> = [0u8; 1].into();
    stdin().read_exact(&mut *current_pass_bytes_len)?;
    stdin().read_exact(&mut current_pass_bytes[..current_pass_bytes_len[0] as usize])?;

    let current_pass: Zeroizing<String> = match String::from_utf8(
        current_pass_bytes[..current_pass_bytes_len[0] as usize].to_vec(),
    ) {
        Ok(k) => k,
        Err(_) => Err(HostErr::StringParseError)?,
    }
    .into();
    let current_pass_len: Zeroizing<String> = current_pass.len().to_string().into();

    let args = &[
        "luksAddKey",
        host::ENCRYPTEDDISK,
        "--batch-mode",
        "--key-file=-",
        "--keyfile-size",
        &current_pass_len,
        "--new-keyfile=-",
        "--new-keyfile-size=32",
    ];
    let mut cryptsetup = Command::new("/usr/sbin/cryptsetup")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()?;
    let mut stdin = match cryptsetup.stdin.take() {
        Some(stdin) => stdin,
        None => {
            return Err(HostErr::PipeError);
        }
    };
    //writes current passphrase
    stdin.write_all(current_pass.as_bytes())?;
    //takes keyfile from tkey from vm then sends over to cryptsetup
    {
        let mut keyfile: Zeroizing<[u8; 32]> = [0u8; 32].into();
        io::stdin().read_exact(&mut *keyfile)?;
        stdin.write_all(&*keyfile)?;
    }
    //extract status code (.code() should only fail if process is killed which is unlikely)
    let status_code = match cryptsetup.wait()?.code() {
        Some(s) => s,
        None => return Err(HostErr::CryptsetupKilled),
    };
    if status_code == 0 {
        eprintln!("successful luks enrollment moving on..");
        Ok(())
    } else {
        Err(HostErr::CryptsetupErr)
    }
}
