use thiserror::Error;

/// All errors that can be produced by `vault-core`.
///
/// Error messages are intentionally generic where an overly specific message
/// could leak information useful to an attacker (e.g. we do not distinguish
/// "wrong password" from "corrupted ciphertext" — both surface as
/// [`VaultError::AuthenticationFailed`]).
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault file not found or unreadable: {0}")]
    Io(#[from] std::io::Error),

    #[error("vault file is malformed or uses an unsupported encoding")]
    Serialization(#[from] Box<bincode::ErrorKind>),

    #[error("vault file has an invalid header (bad magic bytes)")]
    InvalidMagic,

    #[error("vault file format version {found} is not supported (expected {expected})")]
    UnsupportedVersion { found: u8, expected: u8 },

    #[error("KDF parameters are below the minimum security threshold")]
    WeakKdfParams,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("incorrect master password or recovery key, or the vault is corrupted")]
    AuthenticationFailed,

    #[error("recovery phrase is not a valid mnemonic")]
    InvalidRecoveryPhrase,

    #[error("vault is locked; unlock before performing this operation")]
    VaultLocked,

    #[error("a vault already exists at this path")]
    AlreadyExists,
}

pub type Result<T> = std::result::Result<T, VaultError>;
