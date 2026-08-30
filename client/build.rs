use p256::ecdsa::VerifyingKey;

fn main() {
    //sanity check to make sure that tpm key is good.
    let bytes: &[u8; 91] = include_bytes!("../tpm_pubkey_raw.bin");
    if VerifyingKey::from_sec1_bytes(&bytes[26..91]).is_err() {
        println!("ERROR: your public key from tpm is malformed.");
        println!("make sure you have tpm2-tools installed");
        println!("file an issue on github if that doesnt fix it.");
        std::process::exit(1)
    }
}
