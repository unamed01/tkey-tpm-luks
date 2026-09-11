// qubes_enroll.rs
//enrollment for qubesOS tested with qubes version 4.3.1
//check README.md for setup help you should still audit the code before doing so though
//uses qrexec to talk to dom0 which owns tpm this will talk to verify bin.
//enrollment should be done inside an airgapped dispVM.
use chacha20::cipher::stream::{StreamCipher, StreamCipherCoreWrapper};
use chacha20::{ChaChaCore, R20, variants::Ietf};
use host::{ClientError, ClientMessage, HostErr, HostMessage, Tkey, check_status, load_app};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::process::ExitCode;
use std::{
    io::Read,
    process::{Command, Stdio},
};
use zeroize::{Zeroize, Zeroizing};
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let code = match run() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERR: {e}");
            eprintln!("\nfailed to enroll, please try again.");
            eprintln!("open a issue, if this issue persists.");
            println!("press enter to exit.");
            let mut str = String::new();
            std::io::stdin().read_line(&mut str)?;
            return Err(e);
        }
    };
    println!("\nsuccessfully enrolled keyslot with tkey reboot and everything should work!");
    println!("press enter to exit.");
    let mut str = String::new();
    std::io::stdin().read_line(&mut str)?;
    Ok(code)
}
fn run() -> Result<ExitCode, Box<dyn Error>> {
    let argv: Vec<String> = std::env::args().collect();
    let kill_slot = argv.len() == 3 && argv[1] == "--kill-slot";
    let slot_to_kill: Option<u8> = if argv.len() == 3 {
        println!("running in kill slot mode.");
        argv[2].parse().ok()
    } else {
        None
    };
    let mut tkey = Tkey::new()?;
    //makes it easier rather than having to copy multiple files pretty nice QOL but its not perfect
    let bin = if kill_slot {
        fs::read("/home/user/QubesIncoming/dom0/client")?
    } else {
        let bin = include_bytes!("../../../client/clientApp");
        if bin.len() < 1000 {
            Err("did you recompile before passing onto dispVM?")?
        }
        bin.to_vec()
    };
    load_app(&mut tkey, &bin)?;
    drop(bin);
    let mut nonce = [0u8; 32];
    tkey.read_exact(&mut nonce)?;
    let mut qrexec = if kill_slot {
        Command::new("/usr/bin/qrexec-client-vm")
            .args(["dom0", "qubes.LuksKillSlot"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?
    } else {
        Command::new("/usr/bin/qrexec-client-vm")
            .args(["dom0", "qubes.TPMProxy"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?
    };
    let mut stdin = qrexec.stdin.take().expect("failed to take qrexec stdin");
    let mut stdout = qrexec.stdout.take().expect("failed to take qrexec stdout");
    let (mut cipher, challange) = host::get_chacha20_cipher(&mut tkey, nonce)?;
    stdin.write_all(&challange)?;
    let mut b = [0u8];
    stdout.read_exact(&mut b)?;
    match HostMessage::try_from(b[0]) {
        Ok(HostMessage::TpmSigned) => {
            let mut sig_bytes = [0u8; 64];
            stdout.read_exact(&mut sig_bytes)?;
            tkey.write_all(&[HostMessage::TpmSigned as u8])?;
            tkey.write_all(&sig_bytes)?;
        }
        Err(HostErr::TpmRefusedToSign) => {
            if kill_slot {
                Err("refusing to continue, current binary isn't enrolled with TPM")?;
            }
            println!("tpm refused to sign..");
            tkey.write_all(&[HostErr::TpmRefusedToSign as u8])?;
        }
        _ => Err(ClientError::OutOfsync)?,
    }
    // this makes sure tpm signature is fine (will wait until it is if its not)
    match check_status(&mut tkey) {
        Ok(ClientMessage::GoodSig) => println!(
            "tkey successfully authenticated with tpm (ALWAYS make sure tkey light is green before proceeding with passphrase.)"
        ),
        Ok(_) => Err("tkey and host are out of sync (but sig is fine?) restart app.")?,
        Err(ClientError::InvalidSig) => {
            println!("sig is invalid (expected if already rebooted on a update.)")
        }
        Err(e) => Err(e)?,
    }
    match check_status(&mut tkey) {
        Ok(ClientMessage::Ready4pass) => {}
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    };
    pass_enroll(&mut tkey, &mut cipher)?;
    let mut encrypted_keyfile = [0u8; 32];
    tkey.read_exact(&mut encrypted_keyfile)?;
    let mut keyfile = [0u8; 32];
    cipher.apply_keystream_b2b(&encrypted_keyfile, &mut keyfile);
    if !kill_slot {
        let current_passphrase = rpassword::prompt_password("input current luks Password>")?;
        stdin.write_all(&[current_passphrase.len() as u8])?;
        stdin.write_all(current_passphrase.as_bytes())?;
    } else {
        stdin.write_all(&[slot_to_kill.unwrap()])?;
    }
    stdin.write_all(&keyfile)?;
    let code = qrexec.wait()?;
    if code.success() {
        println!("success!!");
        tkey.write_all(&[HostMessage::DecryptionSuccess as u8])?;
        Ok(ExitCode::SUCCESS)
    } else {
        Err("failed to  enroll, dom0 indicated an error. was password correct?".into())
    }
}
fn pass_enroll(
    tkey: &mut Tkey,
    cipher: &mut StreamCipherCoreWrapper<ChaChaCore<R20, Ietf>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "enrolling passphrase now,you'll need to type this in exactly everytime to unlock your disk. (wont be echoed)"
    );
    let pass1: Zeroizing<String> = rpassword::prompt_password(">")?.into();
    println!("type in again for confirmation.");
    let pass2: Zeroizing<String> = rpassword::prompt_password(">")?.into();
    if pass1 != pass2 {
        println!("passwords DID NOT match, try again.");
        pass_enroll(tkey, cipher)?;
        return Ok(());
    };
    let mut pass_len = pass1.len();
    if pass_len > u8::MAX as usize || pass_len < 8 {
        pass_len.zeroize();
        pass_enroll(tkey, cipher)?;
        return Ok(());
    }
    let argon2 = host::get_argon2();
    let mut hashed_pass = [0u8; 32];
    if let Err(e) = argon2.hash_password_into(pass1.as_bytes(), host::SALT, &mut hashed_pass) {
        eprintln!("ERR: failed to hash passphrase");
        eprintln!("this shouldn't happen, please report this issue.");
        eprintln!("{e}");
        return Err("{e}".into());
    }
    cipher.apply_keystream(&mut hashed_pass);
    tkey.write_all(&hashed_pass)?;
    hashed_pass.zeroize();
    match check_status(tkey) {
        Ok(ClientMessage::GoodPass) => {
            println!("keyfile received sending onto cryptsetup for decryption");
            Ok(())
        }
        Err(e) => Err(e)?,
        _ => Err(ClientError::OutOfsync)?,
    }
}
