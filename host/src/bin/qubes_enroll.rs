// qubes_enroll.rs
//enrollment for qubesOS tested with qubes version 4.3.1
//check qubes_guide.md for setup help you should still audit the code before doing so though
//uses qrexec to talk to dom0 which owns tpm this will talk to verify bin enrollment should be done
//inside an airgapped dispVM.
use host::{ClientError, ClientMessage, HostErr, HostMessage, check_status};
use serialport::SerialPort;
use std::io::Write;
use std::process::ExitCode;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};
use tkeyclient::TKey;
use zeroize::{Zeroize, Zeroizing};
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut tkey = TKey::connect(None)?;
    //makes it easier rather than having to copy multiple files pretty nice QOL but its not perfect
    let bin = include_bytes!("../../../client/clientApp");
    if bin.len() < 1000 {
        panic!("did you recompile before passing onto dispVM?")
    }
    tkey.load_app(bin, None)?;
    drop(tkey);
    let mut tkey = serialport::new("/dev/ttyACM0", 62500)
        .timeout(Duration::from_secs(30))
        .open()?;
    let mut nonce = [0u8; 32];
    tkey.read_exact(&mut nonce)?;
    let mut qrexec = Command::new("/usr/bin/qrexec-client-vm")
        .args(["dom0", "qubes.TPMProxy"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut stdin = qrexec.stdin.take().expect("failed to take qrexec stdin");
    let mut stdout = qrexec.stdout.take().expect("failed to take qrexec stdout");
    stdin.write_all(&nonce)?;
    let mut b = [0u8; 1];
    stdout.read_exact(&mut b)?;
    match HostMessage::try_from(b[0]) {
        Ok(HostMessage::TpmSigned) => {
            let mut sig_bytes = [0u8; 64];
            stdout.read_exact(&mut sig_bytes)?;
            tkey.write_all(&[HostMessage::TpmSigned as u8])?;
            tkey.write_all(&sig_bytes)?;
        }
        Err(HostErr::TpmRefusedToSign) => {
            println!("tpm refused to sign..");
            tkey.write_all(&[HostErr::TpmRefusedToSign as u8])?;
        }
        _ => Err(ClientError::OutOfsync)?,
    }
    // this makes sure tpm signature is fine (will wait until it is if its not)
    match check_status(&mut *tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        Ok(_) => Err("tkey and host are out of sync (but sig is fine?) restart app.")?,
        Err(ClientError::InvalidSig) => {
            println!("sig is invalid (expected if already rebooted on a update.)")
        }
        Err(e) => Err(e)?,
    }
    pass_enroll(&mut *tkey)?;
    let mut keyfile = [0u8; 32];
    tkey.read_exact(&mut keyfile)?;
    let current_passphrase = rpassword::prompt_password("input current luks Password.")?;
    stdin.write_all(&[current_passphrase.len() as u8])?;
    stdin.write_all(current_passphrase.as_bytes())?;
    stdin.write_all(&keyfile)?;
    if qrexec.wait()?.success() {
        println!("success!!");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("failure, was passphrase correct?");
        Ok(ExitCode::FAILURE)
    }
}
fn pass_enroll(tkey: &mut dyn SerialPort) -> Result<(), Box<dyn std::error::Error>> {
    match check_status(tkey) {
        Ok(ClientMessage::Ready4pass) => {}
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    };
    println!(
        "enrolling passphrase now,you'll need to type this in exactly everytime to unlock your disk. (wont be echoed)"
    );
    let pass1: Zeroizing<String> = rpassword::prompt_password(">")?.into();
    println!("type in again for confirmation.");
    let pass2: Zeroizing<String> = rpassword::prompt_password(">")?.into();
    if pass1 != pass2 {
        println!("passwords DID NOT match, try again.");
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        pass_enroll(tkey)?;
        return Ok(());
    };
    let mut pass_len = pass1.trim_end().len();
    if pass_len > u8::MAX as usize || pass_len < 8 {
        pass_len.zeroize();
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    tkey.write_all(&[pass_len as u8])?;
    pass_len.zeroize();
    tkey.write_all(pass1.trim_end().as_bytes())?;
    match check_status(tkey) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    }
}
