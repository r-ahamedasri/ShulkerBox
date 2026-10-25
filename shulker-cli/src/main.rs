mod banner;
mod cli;
mod interactive;
mod prompt;
mod util;

use clap::Parser;
use secrecy::ExposeSecret;
use shulker_core::{Vault, VaultEntry};

use cli::{Cli, Command};
use util::{find_entry, print_entry_table, random_id};

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        None => interactive::run(&cli.path),
        Some(Command::Init) => cmd_init(&cli.path),
        Some(Command::Add {
            title,
            username,
            url,
            notes,
        }) => cmd_add(&cli.path, title, username, url, notes),
        Some(Command::List) => cmd_list(&cli.path),
        Some(Command::Show { id_or_title }) => cmd_show(&cli.path, &id_or_title),
        Some(Command::Remove { id_or_title }) => cmd_remove(&cli.path, &id_or_title),
        Some(Command::Recover) => cmd_recover(&cli.path),
    }
}

fn cmd_init(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(format!("a vault already exists at {}", path.display()).into());
    }

    let password = prompt::prompt_new_password(
        "Set a master password: ",
        "Confirm master password: ",
    )?;

    let (_vault, phrase) = Vault::init(path, &password, None)?;

    println!("Vault created at {}", path.display());
    println!();
    println!("=====================================================================");
    println!("RECOVERY PHRASE — write this down and store it somewhere safe.");
    println!("It will not be shown again, and it is the only way back into this");
    println!("vault if you forget your master password.");
    println!();
    println!("{phrase}");
    println!("=====================================================================");

    Ok(())
}

fn cmd_add(
    path: &std::path::Path,
    title: String,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let master_password = prompt::prompt_password_once("Master password: ")?;
    let mut vault = Vault::open(path, &master_password)?;

    let entry_password =
        prompt::prompt_new_password("Password to store: ", "Confirm password: ")?;

    let entry = VaultEntry {
        id: random_id(),
        title,
        username: username.unwrap_or_default(),
        password: entry_password.expose_secret().to_string(),
        url: url.unwrap_or_default(),
        notes: notes.unwrap_or_default(),
    };
    let id = entry.id.clone();
    let title = entry.title.clone();

    vault.add_entry(entry);
    vault.save()?;

    println!("Saved '{title}' (id: {id})");
    Ok(())
}

fn cmd_list(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let master_password = prompt::prompt_password_once("Master password: ")?;
    let vault = Vault::open(path, &master_password)?;
    print_entry_table(vault.entries());
    Ok(())
}

fn cmd_show(path: &std::path::Path, id_or_title: &str) -> Result<(), Box<dyn std::error::Error>> {
    let master_password = prompt::prompt_password_once("Master password: ")?;
    let vault = Vault::open(path, &master_password)?;

    let entry = find_entry(vault.entries(), id_or_title)
        .ok_or_else(|| format!("no entry matching '{id_or_title}'"))?;

    println!("Title:    {}", entry.title);
    println!("Username: {}", entry.username);
    println!("Password: {}", entry.password);
    println!("URL:      {}", entry.url);
    println!("Notes:    {}", entry.notes);
    Ok(())
}

fn cmd_remove(
    path: &std::path::Path,
    id_or_title: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let master_password = prompt::prompt_password_once("Master password: ")?;
    let mut vault = Vault::open(path, &master_password)?;

    let id = find_entry(vault.entries(), id_or_title)
        .ok_or_else(|| format!("no entry matching '{id_or_title}'"))?
        .id
        .clone();

    vault.remove_entry(&id);
    vault.save()?;
    println!("Removed entry {id}");
    Ok(())
}

fn cmd_recover(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let phrase = prompt::prompt_line("Recovery phrase: ")?;
    let mut vault = Vault::open_with_recovery(path, &phrase)?;

    let new_password =
        prompt::prompt_new_password("New master password: ", "Confirm new master password: ")?;
    vault.rewrap_master_password(&new_password, None)?;
    vault.save()?;

    println!("Master password updated. Your entries were not changed.");
    Ok(())
}
