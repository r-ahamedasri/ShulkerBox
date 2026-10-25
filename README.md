# Shulker Box

A local-first, zero-knowledge password and recovery-key manager, written
in Rust.

Two crates in one Cargo workspace: `shulker-core`, the vault logic (key
derivation, encryption, the on-disk file format, atomic writes), and
`shulker-cli`, a command-line frontend built on top of it. The command is
invoked as `shulker`. Running it with no arguments launches an interactive
menu — an ASCII title, arrow-key navigation, Enter to select — so you
don't need to memorize subcommands.

## Table of Contents

- [Design](#design)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup (Windows / PowerShell)](#setup-windows--powershell)
- [Setup (Linux / macOS)](#setup-linux--macos)
- [Interactive Menu](#interactive-menu)
- [Scriptable Subcommands](#scriptable-subcommands)
- [Carrying It Between Devices](#carrying-it-between-devices)
- [Using the Library Directly](#using-the-library-directly)
- [Testing](#testing)
- [Security Notes](#security-notes)
- [Status](#status)
- [License](#license)

## Design

```
master password --Argon2id--> Master Key (memory only, never stored)
                                    |
                                    v wraps (XChaCha20-Poly1305)
                             Vault Encryption Key (VEK)  <--wraps-- recovery wrapping key <--HKDF-- recovery phrase
                                    |
                                    v encrypts (XChaCha20-Poly1305)
                               vault entries
```

- **Master Key** — derived from the master password with Argon2id. Held
  only in process memory, never written to disk, wiped on drop.
- **Vault Encryption Key (VEK)** — a random 256-bit key that directly
  encrypts vault entries. Wrapped (encrypted) two independent ways: once
  under the Master Key, once under a key derived from a BIP39 recovery
  phrase, so either credential recovers it on its own without weakening
  the other.
- **Recovery phrase** — a 24-word BIP39 mnemonic generated from 256 bits
  of CSPRNG entropy, shown once at vault creation. It is not stored; if
  lost, it cannot be regenerated.
- **Vault file** — a single file with an unencrypted header (format
  version, Argon2id parameters, salts, both wrapped VEK copies) and an
  encrypted blob of vault entries. Writes are atomic (temp file, fsync,
  rename, then directory fsync) so a crash or power loss cannot corrupt
  the vault.

Argon2id parameters are enforced at a hard floor of 64 MiB memory and 3
iterations; weaker parameters are rejected rather than used, even if read
back from an existing vault file. The default used by `shulker init` is
higher still (256 MiB, 4 iterations), which is intentionally slow —
expect unlocking to take a few seconds.

The vault is unlocked once per `shulker` run (whether interactive or a
single subcommand) and held in memory only for that run; there is no
background process or persistent session to auto-lock.

## Project Structure

```
shulker-box/                  workspace root
├── Cargo.toml                 workspace manifest (lists both members)
├── LICENSE
├── README.md
├── shulker-core/               the vault library
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs              crate root: module wiring and public exports
│   │   ├── error.rs            VaultError type used throughout the crate
│   │   ├── keys.rs             zeroizing key material wrappers
│   │   ├── kdf.rs               Argon2id master key derivation and parameter validation
│   │   ├── crypto.rs           XChaCha20-Poly1305 encrypt/decrypt primitives
│   │   ├── recovery.rs         BIP39 recovery phrase generation and HKDF wrapping key derivation
│   │   └── vault.rs             vault file format, header, and the init/open/save API
│   └── examples/
│       └── basic.rs             runnable end-to-end library demo
└── shulker-cli/                the `shulker` command-line binary
    ├── Cargo.toml               produces the `shulker` binary ([[bin]] name = "shulker")
    └── src/
        ├── main.rs               entry point; dispatches to a subcommand or the interactive menu
        ├── cli.rs                clap argument/subcommand definitions, default vault path
        ├── banner.rs             "SHULKER BOX" ASCII title shown by the interactive menu
        ├── interactive.rs        the arrow-key menu: unlock/create flow, add/view/list/remove loop
        ├── prompt.rs             hidden-input and line-input terminal prompts
        └── util.rs               helpers shared by the subcommands and the interactive menu
```

## Requirements

- Rust (stable toolchain) with Cargo
- Windows, Linux, or macOS
- A real, interactive terminal — the CLI reads passwords with echo
  disabled via `/dev/tty` / the Windows console, and the menu reads raw
  key presses for arrow-key navigation. It will not work with input
  piped from a non-interactive source.

## Setup (Windows / PowerShell)

Install Rust via [rustup](https://rustup.rs) if you don't already have it:

```powershell
winget install Rustlang.Rustup
```

Restart your terminal, then verify:

```powershell
cargo --version
```

Clone and build everything (both crates, via the workspace):

```powershell
git clone https://github.com/r-ahamedasri/shulker-box.git
cd shulker-box
cargo build --release
```

The `shulker` binary is written to `target\release\shulker.exe`. Either
run it with that full path, or add `target\release` to your `PATH` for
the session:

```powershell
$env:Path += ";$PWD\target\release"
shulker
```

## Setup (Linux / macOS)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/r-ahamedasri/shulker-box.git
cd shulker-box
cargo build --release
./target/release/shulker
```

## Interactive Menu

Running `shulker` with no subcommand launches the menu. This is the
easiest way to use the app day to day.

```
shulker
```

What you'll see, in order:

1. The "SHULKER BOX" ASCII title.
2. If no vault exists yet at the default location, a prompt to create
   one — set a master password (typed twice), then the one-time recovery
   phrase is shown. Write it down; it's never shown again.
3. If a vault already exists, a choice between unlocking with the master
   password or, if you've forgotten it, recovering with the phrase.
4. The main menu:
   - **Add a new password** — prompts for title, username, URL, notes
     (all but title optional), then the password itself, typed twice.
   - **View a password** — pick an entry with the arrow keys, see its
     full details including the password, printed to the terminal.
   - **List all entries** — titles, usernames, and URLs only; never
     passwords.
   - **Remove an entry** — pick an entry, confirm, it's deleted.
   - **Lock and exit** — ends the session; the vault's decrypted contents
     and keys are wiped from memory.

Navigate with the up/down arrow keys, confirm with Enter.

## Scriptable Subcommands

The individual subcommands still work directly, for scripting or if you
prefer typing a full command over navigating a menu:

```
shulker init
shulker add "GitHub" --username octocat --url https://github.com
shulker list
shulker show GitHub
shulker remove GitHub
shulker recover
```

These behave exactly as the equivalent interactive menu actions, just
without the menu — see each command's `--help` for its exact flags, or
the [Design](#design)-adjacent behavior described above.

All commands accept `--path <FILE>` to point at a different vault file
than the default `~/.shulker/vault.shulker` (see below).

## Carrying It Between Devices

By default, every run uses the same vault at a fixed location in your
home directory:

- Linux/macOS: `~/.shulker/vault.shulker`
- Windows: `%USERPROFILE%\.shulker\vault.shulker`

This does **not** depend on your current directory, or on where this
project or the compiled `shulker` binary lives — you can move, rebuild,
or delete the project folder, and the interactive menu or any subcommand
will still find the same vault. Use `--path <FILE>` to point at a
different vault file instead.

The vault is a single, self-contained encrypted file — nothing about it
is tied to the machine it was created on. To use the same vault from more
than one computer:

1. Put `vault.shulker` inside a folder that syncs itself (Dropbox, Google
   Drive, OneDrive, Syncthing, iCloud Drive, etc.) instead of
   `~/.shulker/`.
2. On each machine, point `shulker` at that synced copy with `--path`,
   e.g. `shulker --path "C:\Users\you\Dropbox\vault.shulker"`.

Because it's zero-knowledge, the sync provider only ever sees ciphertext.

One real caveat: it's a single file, not a database with merge logic. If
you edit it (add/remove an entry) on two devices before they've finished
syncing, whichever sync completes last overwrites the other — there's no
merging. Only edit from one device at a time, and let it finish syncing
before touching it elsewhere.

There is currently no mobile app — the CLI runs on Windows, Linux, and
macOS. `shulker-core` (the library) is architected separately from the
CLI specifically so a phone or GUI frontend can be built on it later
without touching the vault logic itself.

## Using the Library Directly

If you're building your own frontend on `shulker-core` instead of using
the CLI, add it as a path (or git) dependency:

```toml
[dependencies]
shulker-core = { path = "../shulker-box/shulker-core" }
```

```rust
use secrecy::SecretString;
use shulker_core::{Vault, VaultEntry};

// Create a new vault. `phrase` is the recovery phrase — show it to the
// user once; it is not stored anywhere.
let password = SecretString::new("a strong master password".to_string());
let (mut vault, phrase) = Vault::init("vault.shulker", &password, None)?;
println!("Recovery phrase (write this down): {phrase}");

vault.add_entry(VaultEntry {
    id: "1".into(),
    title: "Example".into(),
    username: "user@example.com".into(),
    password: "s3cr3t".into(),
    url: "https://example.com".into(),
    notes: String::new(),
});
vault.save()?;

// Later, reopen with the master password...
let vault = Vault::open("vault.shulker", &password)?;

// ...or with the recovery phrase if the password is lost.
let vault = Vault::open_with_recovery("vault.shulker", &phrase)?;
```

A runnable version of this is at `shulker-core/examples/basic.rs`:

```bash
cargo run -p shulker-core --example basic
```

## Testing

```bash
cargo test --workspace
```

The `shulker-core` suite covers the full init/open/save round trip,
wrong-password and wrong-recovery-phrase rejection, tamper detection on
the ciphertext, master-password rotation, and confirms no temp files are
left behind after a save. The interactive menu and subcommands were
verified by hand against a real terminal session (create, unlock, add,
list, view, remove, recover, lock-and-exit).

## Security Notes

- No key material is ever written to disk in recoverable form — only the
  Argon2id parameters, salts, and AEAD-wrapped VEK copies are persisted.
- All in-memory key types are zeroized on drop (via the `zeroize` crate).
- Decryption failures (wrong password, wrong recovery phrase, tampered
  ciphertext) all surface as the same error, so the error type alone
  can't be used to distinguish the cause.
- Setting a new password or secret (vault init, adding an entry,
  recovery-based reset) always requires typing it twice, since hidden
  input can't otherwise be checked for typos.
- The recovery phrase prompt is a plain, visible line of input, not
  hidden — it needs to be readable to type or paste correctly. Be
  mindful of shoulder-surfing when entering it.
- The interactive menu's "View a password" prints the password directly
  to the terminal (by design, per your preference) rather than copying
  it to the clipboard — anyone able to see your screen at that moment
  can see it.
- This project has not undergone an independent security audit.

## Status

Core library, scriptable subcommands, and the interactive menu are all
implemented. Not yet implemented: a password generator, clipboard
support, idle auto-lock (not applicable to the current one-session-per-run
design), and a GUI/mobile app.

## License

MIT © r-ahamedasri
