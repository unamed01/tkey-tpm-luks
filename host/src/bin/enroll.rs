//enrollment works by doing exactly what we'd do at runtime with less eror handling we want to make
//sure we give host a somewhat known good state
use host::{ClientError, ClientMessage, HostErr, HostMessage, check_status, verify};
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
//this goes trough the exact same process as it would in initramfs but instead piping into
//cryptsetup to enroll a keyslot
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut tkey = TKey::connect(None)?;
    let bin = fs::read("../../../client/clientApp")?;
    if bin.len() < 1000 {
        panic!("did you recompile before trying to enroll?")
    }
    tkey.load_app(bin.as_slice(), None)?;
    drop(tkey);
    let mut tkey = serialport::new("/dev/ttyACM0", 62500)
        .timeout(Duration::from_secs(30))
        .open()?;
    let mut nonce = [0u8; 32];
    tkey.read_exact(&mut nonce)?;
    let sig_bytes = verify(&nonce)?;
    tkey.write_all(&sig_bytes)?;

    // this makes sure tpm signature is fine (will wait until it is if its not)
    match check_status(&mut *tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        _ => return Err("host and tkey are out of sync restart the app")?,
    }
    pass_enroll(&mut *tkey)?;
    match enroll(&mut tkey) {
        Ok(_) => Ok(ExitCode::SUCCESS),
        Err(HostErr::CryptsetupErr) => Ok(ExitCode::FAILURE),
        Err(e) => return Err(e)?,
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
    let mut pass_len = pass1.len();
    if pass_len > u8::MAX as usize {
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    tkey.write_all(&[pass_len as u8])?;
    tkey.write_all(pass1.as_bytes())?;
    pass1.zeroize();
    pass_len.zeroize();
    match check_status(tkey) {
        Ok(ClientMessage::GoodSig) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    }
}
fn enroll(tkey: &mut Box<dyn SerialPort>) -> Result<(), HostErr> {
    let args = &[
        "luksAddKey",
        "--key-file",
        "-",
        "--keyfile-size",
        "-y",
        "32",
        host::ENCRYPTEDDISK,
    ];
    let mut keyfile = [0u8; 32];
    tkey.read_exact(&mut keyfile)?;
    let mut cryptsetup = Command::new("/usr/sbin/cryptsetup")
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
        stdin.write_all(&keyfile)?;
    }
    keyfile.zeroize();
    //extract status code (.code() should only fail if process is killed which is very unlikely)
    let status_code = match cryptsetup.wait()?.code() {
        Some(s) => s,
        None => return Err(HostErr::CryptsetupKilled),
    };
    if status_code == 0 {
        println!("successful luks enrollment moving on..");
        tkey.write_all(&[HostMessage::DecryptionSuccess as u8])?;
        Ok(())
    } else {
        tkey.write_all(&[HostMessage::DecryptionError as u8])?;
        Err(HostErr::CryptsetupErr)
    }
}
