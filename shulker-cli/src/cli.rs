use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Shulker Box — a local-first, zero-knowledge password and key manager.
#[derive(Parser)]
#[command(name = "shulker", version, about, long_about = None)]
pub struct Cli {
    /// Path to the vault file. Defaults to a fixed location in your home
    /// directory (~/.shulker/vault.shulker, or
    /// %USERPROFILE%\.shulker\vault.shulker on Windows) so it's the same
    /// vault no matter what directory you run `shulker` from, or where
    /// this project/binary itself lives.
    #[arg(long, global = true, default_value_os_t = default_vault_path())]
    pub path: PathBuf,

    /// Subcommand to run. If omitted, launches the interactive menu.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The default vault location: `<home directory>/.shulker/vault.shulker`.
/// Resolved fresh on every run (not baked in at compile time), so it
/// tracks whichever account the command is actually running under.
/// Falls back to the current directory if no home directory can be found
/// (e.g. `HOME`/`USERPROFILE` unset).
fn default_vault_path() -> PathBuf {
    home_dir().join(".shulker").join("vault.shulker")
}

fn home_dir() -> PathBuf {
    #[cfg(windows)]
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("HOME") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(".")
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new vault. Prints a one-time recovery phrase — write it
    /// down; it cannot be shown again.
    Init,

    /// Add a new entry to the vault.
    Add {
        /// A short name for this entry, e.g. "GitHub" or "Home Wi-Fi".
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },

    /// List every entry's title, username, and URL (never the password).
    List,

    /// Show one entry, including its password, in the terminal.
    Show {
        /// The entry's id (shown by `list`) or its exact title.
        id_or_title: String,
    },

    /// Delete an entry from the vault.
    Remove {
        /// The entry's id (shown by `list`) or its exact title.
        id_or_title: String,
    },

    /// Regain access using the recovery phrase and set a new master
    /// password. Entries are untouched.
    Recover,
}
