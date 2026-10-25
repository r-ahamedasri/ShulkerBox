use std::path::Path;

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};
use secrecy::ExposeSecret;
use shulker_core::{Vault, VaultEntry, VaultError};

use crate::banner;
use crate::prompt;
use crate::util::{find_entry, print_entry_table, random_id};

const MAX_UNLOCK_ATTEMPTS: u32 = 3;

/// Runs the interactive menu: banner, unlock-or-create, then the
/// add/view/list/remove loop until the user locks and exits.
pub fn run(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", banner::render("SHULKER BOX"));
    println!("Local-first, zero-knowledge password manager");
    println!("(vault: {})\n", path.display());

    let Some(mut vault) = unlock_or_create(path)? else {
        return Ok(()); // user chose to exit before unlocking
    };

    loop {
        let items = [
            "Add a new password",
            "View a password",
            "List all entries",
            "Remove an entry",
            "Lock and exit",
        ];
        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&items)
            .default(0)
            .interact()?;

        println!();
        match choice {
            0 => add_entry(&mut vault)?,
            1 => view_entry(&vault)?,
            2 => print_entry_table(vault.entries()),
            3 => remove_entry(&mut vault)?,
            _ => {
                println!("Vault locked. Goodbye!");
                break;
            }
        }
        println!();
    }

    Ok(())
}

/// Handles the pre-unlock flow: if no vault exists yet, offers to create
/// one; otherwise offers to unlock with the master password or recover
/// with the phrase. Returns `Ok(None)` if the user chose to exit.
fn unlock_or_create(path: &Path) -> Result<Option<Vault>, Box<dyn std::error::Error>> {
    if !path.exists() {
        let items = ["Create a new vault", "Exit"];
        let choice = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("No vault found here yet. What would you like to do?")
            .items(&items)
            .default(0)
            .interact()?;
        if choice != 0 {
            return Ok(None);
        }

        let password =
            prompt::prompt_new_password("Set a master password: ", "Confirm master password: ")?;
        let (vault, phrase) = Vault::init(path, &password, None)?;

        println!("\nVault created at {}", path.display());
        println!("=====================================================================");
        println!("RECOVERY PHRASE — write this down and store it somewhere safe.");
        println!("It will not be shown again, and it is the only way back into this");
        println!("vault if you forget your master password.");
        println!();
        println!("{phrase}");
        println!("=====================================================================");
        prompt::prompt_line("\nPress Enter to continue: ")?;

        return Ok(Some(vault));
    }

    let items = [
        "Unlock with master password",
        "Forgot password — use recovery phrase",
        "Exit",
    ];
    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Vault found. What would you like to do?")
        .items(&items)
        .default(0)
        .interact()?;

    match choice {
        0 => {
            for attempt in 1..=MAX_UNLOCK_ATTEMPTS {
                let password = prompt::prompt_password_once("Master password: ")?;
                match Vault::open(path, &password) {
                    Ok(vault) => return Ok(Some(vault)),
                    Err(VaultError::AuthenticationFailed) => {
                        println!(
                            "Incorrect password ({attempt}/{MAX_UNLOCK_ATTEMPTS} attempts)."
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err("too many incorrect attempts".into())
        }
        1 => {
            let phrase = prompt::prompt_line("Recovery phrase: ")?;
            let mut vault = Vault::open_with_recovery(path, &phrase)?;
            let new_password = prompt::prompt_new_password(
                "New master password: ",
                "Confirm new master password: ",
            )?;
            vault.rewrap_master_password(&new_password, None)?;
            vault.save()?;
            println!("Master password updated.\n");
            Ok(Some(vault))
        }
        _ => Ok(None),
    }
}

fn add_entry(vault: &mut Vault) -> Result<(), Box<dyn std::error::Error>> {
    let title = prompt::prompt_line("Title (e.g. GitHub): ")?;
    let username = prompt::prompt_line("Username (optional): ")?;
    let url = prompt::prompt_line("URL (optional): ")?;
    let notes = prompt::prompt_line("Notes (optional): ")?;
    let password = prompt::prompt_new_password("Password to store: ", "Confirm password: ")?;

    let entry = VaultEntry {
        id: random_id(),
        title: title.clone(),
        username,
        password: password.expose_secret().to_string(),
        url,
        notes,
    };
    let id = entry.id.clone();

    vault.add_entry(entry);
    vault.save()?;
    println!("Saved '{title}' (id: {id})");
    Ok(())
}

fn view_entry(vault: &Vault) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = select_entry(vault.entries(), "Which entry?")? else {
        return Ok(());
    };

    println!("Title:    {}", entry.title);
    println!("Username: {}", entry.username);
    println!("Password: {}", entry.password);
    println!("URL:      {}", entry.url);
    println!("Notes:    {}", entry.notes);
    prompt::prompt_line("\nPress Enter to continue: ")?;
    Ok(())
}

fn remove_entry(vault: &mut Vault) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = select_entry(vault.entries(), "Remove which entry?")? else {
        return Ok(());
    };
    let id = entry.id.clone();
    let title = entry.title.clone();

    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Remove '{title}'? This cannot be undone."))
        .default(false)
        .interact()?;
    if !confirmed {
        println!("Cancelled.");
        return Ok(());
    }

    vault.remove_entry(&id);
    vault.save()?;
    println!("Removed '{title}'");
    Ok(())
}

/// Shows an arrow-key picker over the vault's entries (by "title —
/// username"). Returns `None` if the vault is empty.
fn select_entry<'a>(
    entries: &'a [VaultEntry],
    prompt_text: &str,
) -> Result<Option<&'a VaultEntry>, Box<dyn std::error::Error>> {
    if entries.is_empty() {
        println!("(vault is empty)");
        return Ok(None);
    }

    let labels: Vec<String> = entries
        .iter()
        .map(|e| {
            if e.username.is_empty() {
                e.title.clone()
            } else {
                format!("{} — {}", e.title, e.username)
            }
        })
        .collect();

    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt_text)
        .items(&labels)
        .default(0)
        .interact()?;

    // Re-resolve by id rather than trusting the index stays valid, in case
    // this is ever called after entries could have changed mid-selection.
    let id = &entries[idx].id;
    Ok(find_entry(entries, id))
}
