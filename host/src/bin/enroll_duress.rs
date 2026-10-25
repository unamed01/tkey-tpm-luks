use std::fs;

use argon2::PasswordHasher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("type in new duress password: >").unwrap();
    println!("confirm duress password");
    let password2 = rpassword::prompt_password("type in new duress password again: >").unwrap();
    if password != password2 {
        eprintln!("\nERR: passswords do NOT match try again.");
        #[allow(clippy::main_recursion)]
        main()?;
        return Ok(());
    }
    let argon2 = host::get_argon2();
    let hash = argon2
        .hash_password_with_salt(password.as_bytes(), host::SALT)
        .expect("couldn't hash password");
    fs::write(
        format!("{}/tkey-tpm-luks/duress.argon2", std::env::var("HOME")?),
        format!("{}", hash).as_bytes(),
    )?;
    Ok(())
}
