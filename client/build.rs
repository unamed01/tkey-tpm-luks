use std::{fs, io::Read};

use p256::ecdsa::VerifyingKey;

fn main() {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return;
    }
    //sanity check to make sure that tpm key is good before putting it on
    let mut f = fs::File::open("../tpm_pubkey_raw.bin").unwrap();
    let mut bytes = vec![];
    if f.read_to_end(&mut bytes).unwrap() != 91 {
        eprintln!("pubkey is wrong size");
        std::process::exit(1)
    }
    if VerifyingKey::from_sec1_bytes(&bytes[26..91]).is_err() {
        println!("ERROR: your public key from tpm is malformed.");
        println!("make sure you have tpm2-tools installed");
        println!("file an issue on github if that doesnt fix it.");
        std::process::exit(1)
    }
}
