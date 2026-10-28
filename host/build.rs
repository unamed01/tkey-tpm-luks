use argon2::PasswordHash;
use std::str::FromStr;

fn main() {
    let duress_hash_str = include_str!("../duress.argon2");
    if !duress_hash_str.is_empty() {
        assert!(PasswordHash::from_str(duress_hash_str.trim()).is_ok())
    }
}
