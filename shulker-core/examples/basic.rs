//! Run with: cargo run --example basic
//!
//! Creates a vault in a temp directory, adds one entry, saves it, then
//! reopens it two ways: with the master password, and with the recovery
//! phrase. Deletes the vault file at the end so repeat runs stay clean.

use secrecy::SecretString;
use shulker_core::{Vault, VaultEntry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join("shulker-box-example.shulker");
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    let password = SecretString::new("correct horse battery staple".to_string());

    // Create the vault. `phrase` is shown once — in a real app this must be
    // displayed to the user and never logged or stored.
    let (mut vault, phrase) = Vault::init(&path, &password, None)?;
    println!("Vault created at {}", path.display());
    println!("Recovery phrase (write this down): {phrase}");

    vault.add_entry(VaultEntry {
        id: "1".into(),
        title: "Example Site".into(),
        username: "user@example.com".into(),
        password: "s3cr3t-password".into(),
        url: "https://example.com".into(),
        notes: String::new(),
    });
    vault.save()?;
    println!("Saved {} entry(ies)", vault.entries().len());

    // Drop the in-memory vault (zeroizes the VEK) and reopen from disk with
    // the master password.
    drop(vault);
    let reopened = Vault::open(&path, &password)?;
    println!(
        "Reopened with password — entry title: {}",
        reopened.entries()[0].title
    );
    drop(reopened);

    // Reopen again using only the recovery phrase, as if the password were
    // forgotten.
    let recovered = Vault::open_with_recovery(&path, &phrase)?;
    println!(
        "Reopened with recovery phrase — entry title: {}",
        recovered.entries()[0].title
    );

    std::fs::remove_file(&path)?;
    Ok(())
}
