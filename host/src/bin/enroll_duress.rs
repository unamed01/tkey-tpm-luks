// Copyright 2026 Unamed01
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
    fs::write("../duress.argon2", hash.to_string())?;
    Ok(())
}
