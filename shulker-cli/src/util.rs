use rand_core::{OsRng, RngCore};
use shulker_core::VaultEntry;

/// Generates a short random hex id for a new entry (not security-relevant
/// — this is a label, not key material).
pub fn random_id() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Finds an entry by exact id, falling back to a case-insensitive exact
/// title match.
pub fn find_entry<'a>(entries: &'a [VaultEntry], id_or_title: &str) -> Option<&'a VaultEntry> {
    entries
        .iter()
        .find(|e| e.id == id_or_title)
        .or_else(|| entries.iter().find(|e| e.title.eq_ignore_ascii_case(id_or_title)))
}

/// Prints the id / title / username / URL table shared by `list` and the
/// interactive menu's "list all entries" action.
pub fn print_entry_table(entries: &[VaultEntry]) {
    if entries.is_empty() {
        println!("(vault is empty)");
        return;
    }
    println!("{:<10} {:<24} {:<24} {}", "ID", "TITLE", "USERNAME", "URL");
    for entry in entries {
        println!(
            "{:<10} {:<24} {:<24} {}",
            entry.id, entry.title, entry.username, entry.url
        );
    }
}
