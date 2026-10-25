use std::io::{self, Write};

use secrecy::SecretString;

/// Prompts once for a password with input hidden (no echo). Used whenever
/// an existing password (master password to unlock, entry password when
/// showing/removing context) just needs to be typed back in.
pub fn prompt_password_once(label: &str) -> io::Result<SecretString> {
    let value = rpassword::prompt_password(label)?;
    Ok(SecretString::new(value))
}

/// Prompts twice and requires both entries to match. Used whenever a new
/// password is being *set* (vault init, entry creation, password reset),
/// since a hidden field can't otherwise be double-checked for typos.
pub fn prompt_new_password(label: &str, confirm_label: &str) -> io::Result<SecretString> {
    loop {
        let first = rpassword::prompt_password(label)?;
        let second = rpassword::prompt_password(confirm_label)?;
        if first == second {
            return Ok(SecretString::new(first));
        }
        println!("Entries did not match — try again.");
    }
}

/// Prompts for a plain, visible line of input (used for the recovery
/// phrase, which the user needs to see clearly to type or paste
/// correctly).
pub fn prompt_line(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
