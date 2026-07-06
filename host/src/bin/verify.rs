use std::io::{self, Read, Write};
use std::process::ExitCode;

use host::verify;

//this is the code that actually gets run in dom0 minimal on purpose allows as much vm isolation as
//possible.
fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut nonce = [0u8; 32];
    io::stdin().read_exact(&mut nonce)?;
    let sig = verify(&nonce)?;
    io::stdout().write_all(&sig)?;
    Ok(ExitCode::SUCCESS)
}
