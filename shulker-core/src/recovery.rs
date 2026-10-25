use bip39::Mnemonic;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::keys::{RecoveryWrappingKey, SecretKey32};

pub const RECOVERY_SALT_LEN: usize = 16;
/// 256 bits of entropy -> a 24-word BIP39 mnemonic.
const RECOVERY_ENTROPY_LEN: usize = 32;

/// Info string for HKDF domain separation, so a recovery wrapping key can
/// never be confused with key material derived elsewhere in the crate.
const HKDF_INFO: &[u8] = b"shulker-core/recovery-wrapping-key/v1";

/// A freshly generated recovery credential: the human-readable BIP39 phrase
/// to show the user (once) and the raw entropy behind it, kept only long
/// enough to derive the wrapping key.
pub struct GeneratedRecovery {
    pub mnemonic: Mnemonic,
    entropy: [u8; RECOVERY_ENTROPY_LEN],
}

impl Drop for GeneratedRecovery {
    fn drop(&mut self) {
        self.entropy.zeroize();
    }
}

impl GeneratedRecovery {
    /// Generates a new 24-word BIP39 recovery phrase from 256 bits of
    /// OS-CSPRNG entropy. High enough entropy that, unlike the master
    /// password, it does not need a memory-hard KDF before use.
    pub fn generate() -> Self {
        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        OsRng.fill_bytes(&mut entropy);
        // Entropy length is fixed and valid, so mnemonic construction cannot fail.
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid entropy length");
        Self { mnemonic, entropy }
    }

    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    pub fn derive_wrapping_key(&self, salt: &[u8; RECOVERY_SALT_LEN]) -> RecoveryWrappingKey {
        derive_wrapping_key_from_entropy(&self.entropy, salt)
    }
}

/// Re-derives the recovery wrapping key from a phrase the user typed back
/// in during recovery. Returns [`VaultError::InvalidRecoveryPhrase`] if the
/// phrase isn't a well-formed BIP39 mnemonic (bad word, bad checksum,
/// wrong length) — this is a format check, distinct from the AEAD
/// authentication failure raised later if the key itself is wrong.
pub fn wrapping_key_from_phrase(
    phrase: &str,
    salt: &[u8; RECOVERY_SALT_LEN],
) -> Result<RecoveryWrappingKey> {
    let mnemonic: Mnemonic = phrase
        .parse()
        .map_err(|_| VaultError::InvalidRecoveryPhrase)?;
    let mut entropy_vec = mnemonic.to_entropy();
    let key = if entropy_vec.len() == RECOVERY_ENTROPY_LEN {
        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        entropy.copy_from_slice(&entropy_vec);
        let key = derive_wrapping_key_from_entropy(&entropy, salt);
        entropy.zeroize();
        key
    } else {
        entropy_vec.zeroize();
        return Err(VaultError::InvalidRecoveryPhrase);
    };
    entropy_vec.zeroize();
    Ok(key)
}

fn derive_wrapping_key_from_entropy(
    entropy: &[u8; RECOVERY_ENTROPY_LEN],
    salt: &[u8; RECOVERY_SALT_LEN],
) -> RecoveryWrappingKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), entropy);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    RecoveryWrappingKey(SecretKey32::from_bytes(out))
}

pub fn random_recovery_salt() -> [u8; RECOVERY_SALT_LEN] {
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrase_round_trips_to_same_key() {
        let generated = GeneratedRecovery::generate();
        let salt = random_recovery_salt();
        let k1 = generated.derive_wrapping_key(&salt);

        let phrase = generated.phrase();
        let k2 = wrapping_key_from_phrase(&phrase, &salt).unwrap();

        assert_eq!(k1.0.as_bytes(), k2.0.as_bytes());
    }

    #[test]
    fn garbage_phrase_is_rejected() {
        let salt = random_recovery_salt();
        let result = wrapping_key_from_phrase("not a real bip39 phrase at all", &salt);
        assert!(matches!(result, Err(VaultError::InvalidRecoveryPhrase)));
    }

    #[test]
    fn different_salt_yields_different_key() {
        let generated = GeneratedRecovery::generate();
        let salt_a = random_recovery_salt();
        let mut salt_b = salt_a;
        salt_b[0] ^= 0xFF;

        let k1 = generated.derive_wrapping_key(&salt_a);
        let k2 = generated.derive_wrapping_key(&salt_b);
        assert_ne!(k1.0.as_bytes(), k2.0.as_bytes());
    }
}
