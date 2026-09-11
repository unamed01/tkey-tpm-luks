//kill-slot
use host::{HostErr, HostMessage, verify};
use std::fs;
use std::process::ExitCode;
use std::process::{Command, Stdio};
use std::{
    io,
    io::{Read, Write, stdin, stdout},
};
use zeroize::Zeroizing;

//this is the code that actually gets run in dom0.
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut challange = [0u8; 108];
    std::io::stdin().read_exact(&mut challange)?;
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/root/tkey-files/Qubes_Kill_slot.rs")?;
    match verify(challange) {
        Ok(s) => {
            stdout().write_all(&[HostMessage::TpmSigned as u8])?;
            stdout().write_all(&s)?;
            stdout().flush()?;
        }
        Err(e) => {
            writeln!(f, "tpm refused to unseal")?;
            writeln!(f, "{}", e)?;
            stdout().write_all(&[HostErr::TpmError as u8])?;
            Err(e)?
        }
    };
    kill_slot()?;
    writeln!(f, "successfully wiped old luks slot..")?;
    Ok(ExitCode::SUCCESS)
}

fn kill_slot() -> Result<(), HostErr> {
    let mut keyslot = [0u8; 1];
    stdin().read_exact(&mut keyslot)?;
    let args = &[
        "luksKillSlot",
        "--key-file=-",
        "--keyfile-size=32",
        host::ENCRYPTEDDISK,
        &keyslot[0].to_string(),
    ];
    let mut cryptsetup = Command::new("/usr/sbin/cryptsetup")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = match cryptsetup.stdin.take() {
        Some(stdin) => stdin,
        None => {
            return Err(HostErr::PipeError);
        }
    };
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
        Ok(())
    } else {
        Err(HostErr::CryptsetupErr)
    }
}
