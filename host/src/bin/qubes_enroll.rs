//enrollment for qubesOS tested with qubes version 4.3.1
//check qubes_guide.md for setup help you should still audit the code before doing so though
//uses qrexec to talk to dom0 which owns tpm this will talk to verify bin enrollment should be done
//inside an airgapped dispVM.
use host::{ClientError, ClientMessage, HostMessage, check_status};
use serialport::SerialPort;
use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};
use tkeyclient::TKey;
use zeroize::Zeroize;
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
    let mut sig_bytes = [0u8; 64];
    stdout.read_exact(&mut sig_bytes)?;
    println!(" qrexec exit code: {}", qrexec.wait()?.code().unwrap());
    tkey.write_all(&[HostMessage::TpmSigned as u8])?;
    tkey.write_all(&sig_bytes)?;
    // this makes sure tpm signature is fine (will wait until it is if its not)
    match check_status(&mut *tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        Ok(ClientMessage::Ready4pass) | Ok(ClientMessage::GoodPass) => {
            Err("tkey and host are out of sync (but sig is fine?) restart app.")?
        }
        Err(e) => Err(e)?,
    }
    pass_enroll(&mut *tkey)?;
    write_keyfile(&mut *tkey)?;
    Ok(ExitCode::SUCCESS)
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
    let mut pass1 = rpassword::prompt_password(">")?;
    println!("type in again for confirmation.");
    let mut pass2 = rpassword::prompt_password(">")?;
    if pass1 != pass2 {
        println!("passwords DID NOT match, try again.");
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        pass_enroll(tkey)?;
        return Ok(());
    };
    pass2.zeroize();
    let mut pass_len = pass1.trim_end().len();
    if pass_len > u8::MAX as usize || pass_len < 8 {
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    tkey.write_all(&[pass_len as u8])?;
    tkey.write_all(pass1.trim_end().as_bytes())?;
    pass1.zeroize();
    pass_len.zeroize();
    match check_status(tkey) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    }
}
//should only be used if you need really it as a file e.g when enrolling onto qubes' dom0 any other
//case do use enroll() instead which is miles safer, this is meant to be used inside a minimal
//DispVM and will never be default written to /tmp because its ram backed make sure you write to
// /tmp in dom0 as well.
fn write_keyfile(tkey: &mut dyn SerialPort) -> Result<(), Box<dyn std::error::Error>> {
    println!("getting keyfile from tkey and writting to /tmp/keyfile");
    let mut keyfile = [0u8; 32];
    tkey.read_exact(&mut keyfile)?;
    fs::write("/tmp/keyfile", keyfile)?;
    keyfile.zeroize();
    tkey.write_all(&[HostMessage::DecryptionSuccess as u8])?;
    Ok(())
}
