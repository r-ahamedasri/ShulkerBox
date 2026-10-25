//! Core library for Shulker Box: a local-first, zero-knowledge password
//! and key manager.
//!
//! ## Key hierarchy
//!
//! ```text
//! master password --Argon2id--> Master Key (memory only)
//!                                     |
//!                                     v wraps
//!                              Vault Encryption Key (VEK) <--wraps-- recovery wrapping key <--HKDF-- recovery phrase
//!                                     |
//!                                     v encrypts (XChaCha20-Poly1305)
//!                                vault entries
//! ```
//!
//! The Master Key and the recovery wrapping key each independently wrap
//! (encrypt) the same random VEK, which is what actually encrypts vault
//! entries. Either credential recovers the VEK on its own; neither weakens
//! the other, and the server (there is none — this is local-first) never
//! sees any of it. Nothing here ever transmits or persists key material in
//! recoverable form outside this process's memory.
//!
//! This crate is UI-agnostic: it has no CLI or GUI code, so both can be
//! built on top of it.

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod recovery;
pub mod vault;

pub use error::{Result, VaultError};
pub use kdf::KdfParams;
pub use recovery::GeneratedRecovery;
pub use vault::{Vault, VaultEntry};
