use zeroize::{Zeroize, ZeroizeOnDrop};

/// A fixed-size 32-byte secret that is guaranteed to be wiped from memory
/// when it goes out of scope.
///
/// This is the building block for every piece of key material that ever
/// exists in process memory: the Master Key, the Vault Encryption Key, and
/// the recovery wrapping key. None of these are ever written to disk.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32(pub(crate) [u8; 32]);

impl SecretKey32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generates 32 bytes of key material from an OS-backed CSPRNG.
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

// Deliberately no `Debug` impl: printing a `SecretKey32` (e.g. via `{:?}` in
// a log statement) must be a compile error, not a runtime information leak.

/// The Master Key: derived from the user's master password via Argon2id.
/// Held only in memory for the lifetime of an unlocked session.
pub struct MasterKey(pub SecretKey32);

/// The Vault Encryption Key (VEK): a random key that directly encrypts vault
/// entries. Wrapped (encrypted) at rest by both the Master Key and the
/// recovery wrapping key, so either credential independently recovers it.
pub struct VaultEncryptionKey(pub SecretKey32);

impl VaultEncryptionKey {
    pub fn random() -> Self {
        Self(SecretKey32::random())
    }
}

/// A key derived (via HKDF) from the user's recovery phrase entropy, used
/// only to unwrap the VEK during recovery.
pub struct RecoveryWrappingKey(pub SecretKey32);
