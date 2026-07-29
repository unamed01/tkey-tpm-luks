use std::error::Error;
use std::path::Path;
use std::{self, fs};

fn main() -> Result<(), Box<dyn Error>> {
    //allows include_bytes! macros which are pretty convinient specially for qubes.
    if !Path::new("../client/clientApp").exists() {
        let bytes = b"placeholder to allow include_bytes! (will cause runtime fail if not rebuilt and replaced)";
        fs::write("../client/clientApp", bytes)?;
    }
    Ok(())
}
