use std::{
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};
use tkeyclient::TKey;
use zeroize::{Zeroize, Zeroizing};
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
        Err(ClientError::InvalidSig) => println!("sig is invalid should only happen if updating."),
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
    let mut pass_len = pass1.len();
    if pass_len > u8::MAX as usize {
        pass_len.zeroize();
        tkey.write_all(&[0u8])?;
        _ = check_status(tkey);
        Err(ClientError::PassLen)?;
    }
    tkey.write_all(&[pass_len as u8])?;
    tkey.write_all(pass1.as_bytes())?;
    pass_len.zeroize();
    match check_status(tkey) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for enrollment.");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    }
}
fn enroll(tkey: &mut Box<dyn SerialPort>) -> Result<(), HostErr> {
    println!("to enroll you must type in your currently enrolled passphrase (won't be echoed)");
    let current_pass = rpassword::prompt_password(">")?;
    let current_pass_len = current_pass.len().to_string();
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
    stdin.write_all(current_pass.as_bytes())?;
    {
        let mut keyfile = [0u8; 32];
        tkey.read_exact(&mut keyfile)?;
        stdin.write_all(&keyfile)?;
        keyfile.zeroize();
    }
    //extract status code (.code() should only fail if process is killed which is very unlikely)
    let status_code = match cryptsetup.wait()?.code() {
        Some(s) => s,
        None => return Err(HostErr::CryptsetupKilled),
    };
    if status_code == 0 {
        println!("successful enrollment, everything should work!");
        tkey.write_all(&[HostMessage::DecryptionSuccess as u8])?;
        Ok(())
    } else {
        tkey.write_all(&[HostErr::DecryptionError as u8])?;
        Err(HostErr::CryptsetupErr)
    }
}
