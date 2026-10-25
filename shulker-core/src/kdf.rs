use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::keys::{MasterKey, SecretKey32};

pub const SALT_LEN: usize = 16;

/// Minimum memory cost, in KiB: 64 MiB. This is a floor, not a
/// recommendation — [`KdfParams::recommended`] uses a higher default.
pub const MIN_MEMORY_KIB: u32 = 64 * 1024;
/// Minimum number of Argon2id passes.
pub const MIN_ITERATIONS: u32 = 3;
/// Minimum degree of parallelism.
pub const MIN_PARALLELISM: u32 = 1;

/// Argon2id parameters used to derive the Master Key from the master
/// password. Stored unencrypted in the vault header — these are not secret,
/// only the password and the resulting key are.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Generates fresh parameters at the library's recommended strength
    /// (256 MiB, 4 iterations, single-threaded) with a random salt.
    ///
    /// Single-threaded (`parallelism = 1`) is intentional: it keeps the
    /// memory-hardness guarantee meaningful on constrained hardware and
    /// keeps derivation time predictable across platforms.
    pub fn recommended() -> Self {
        Self::with_cost(256 * 1024, 4, 1)
    }

    /// Generates fresh parameters with caller-chosen cost and a random salt.
    /// Returns weak parameters as-is; they are rejected later at derivation
    /// time by [`derive_master_key`], not silently upgraded here.
    pub fn with_cost(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            memory_kib,
            iterations,
            parallelism,
            salt,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.memory_kib < MIN_MEMORY_KIB
            || self.iterations < MIN_ITERATIONS
            || self.parallelism < MIN_PARALLELISM
        {
            return Err(VaultError::WeakKdfParams);
        }
        Ok(())
    }
}

/// Derives the Master Key from the master password using Argon2id.
///
/// Enforces [`MIN_MEMORY_KIB`] / [`MIN_ITERATIONS`] / [`MIN_PARALLELISM`] as
/// a hard floor: params weaker than that are rejected rather than used, so a
/// tampered or downgraded header can't silently weaken derivation.
pub fn derive_master_key(password: &SecretString, params: &KdfParams) -> Result<MasterKey> {
    params.validate()?;

    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| VaultError::KeyDerivation)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), &params.salt, &mut out)
        .map_err(|_| VaultError::KeyDerivation)?;

    Ok(MasterKey(SecretKey32::from_bytes(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_weak_params() {
        let password = SecretString::new("correct horse battery staple".into());
        let weak = KdfParams::with_cost(8 * 1024, 1, 1);
        let result = derive_master_key(&password, &weak);
        assert!(matches!(result, Err(VaultError::WeakKdfParams)));
    }

    #[test]
    fn same_password_and_salt_are_deterministic() {
        let password = SecretString::new("correct horse battery staple".into());
        // Use a small-but-valid cost to keep the test fast.
        let params = KdfParams::with_cost(MIN_MEMORY_KIB, MIN_ITERATIONS, 1);
        let k1 = derive_master_key(&password, &params).unwrap();
        let k2 = derive_master_key(&password, &params).unwrap();
        assert_eq!(k1.0.as_bytes(), k2.0.as_bytes());
    }

    #[test]
    fn different_salts_yield_different_keys() {
        let password = SecretString::new("correct horse battery staple".into());
        let p1 = KdfParams::with_cost(MIN_MEMORY_KIB, MIN_ITERATIONS, 1);
        let mut p2 = p1.clone();
        p2.salt[0] ^= 0xFF;
        let k1 = derive_master_key(&password, &p1).unwrap();
        let k2 = derive_master_key(&password, &p2).unwrap();
        assert_ne!(k1.0.as_bytes(), k2.0.as_bytes());
    }
}
