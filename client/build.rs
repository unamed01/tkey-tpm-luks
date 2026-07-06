use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};

fn main() {
    //sanity check to make sure that tpm key is good.
    if VerifyingKey::from_public_key_der(include_bytes!("../tpm_pubkey_raw.bin")).is_err() {
        println!("ERROR: your public key from tpm is malformed.");
        println!("make sure you have tpm2-tools installed");
        println!("file an issue on github if that doesnt fix it.");
        std::process::exit(1)
    }
}
