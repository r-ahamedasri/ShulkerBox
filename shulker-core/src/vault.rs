use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, EncryptedBlob};
use crate::error::{Result, VaultError};
use crate::kdf::{self, KdfParams};
use crate::keys::VaultEncryptionKey;
use crate::recovery::{self, GeneratedRecovery, RECOVERY_SALT_LEN};

pub const MAGIC: [u8; 4] = *b"SHLK";
pub const FORMAT_VERSION: u8 = 1;

const AAD_VEK_MASTER: &[u8] = b"shulker-core/vek-wrap/master/v1";
const AAD_VEK_RECOVERY: &[u8] = b"shulker-core/vek-wrap/recovery/v1";
const AAD_ENTRIES: &[u8] = b"shulker-core/entries/v1";

/// One credential/secret held in the vault. `password` covers any secret
/// value — a password, a recovery key for some other service, an API
/// token, etc.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

/// The full set of entries, as it exists decrypted in memory and as it is
/// serialized (then encrypted) to disk. Zeroized on drop.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Zeroize)]
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
}

/// The unencrypted portion of the vault file: format identifiers, KDF
/// parameters, salts, and the VEK wrapped two independent ways. None of
/// this is secret on its own — an attacker who obtains the file still needs
/// either the master password or the recovery phrase to derive a key that
/// unwraps the VEK.
#[derive(Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub master_kdf: KdfParams,
    pub recovery_salt: [u8; RECOVERY_SALT_LEN],
    pub wrapped_vek_master: EncryptedBlob,
    pub wrapped_vek_recovery: EncryptedBlob,
}

/// The complete on-disk representation: header plus the encrypted entries.
#[derive(Serialize, Deserialize)]
struct VaultFile {
    header: VaultHeader,
    data: EncryptedBlob,
}

/// An unlocked vault: decrypted entries and the VEK held in memory for the
/// lifetime of this value. Dropping it zeroizes both.
pub struct Vault {
    path: PathBuf,
    header: VaultHeader,
    vek: VaultEncryptionKey,
    data: VaultData,
}

impl Vault {
    /// Creates a new vault at `path`.
    ///
    /// Fails with [`VaultError::AlreadyExists`] if a file is already there,
    /// so this can never silently clobber an existing vault. `kdf_params`
    /// defaults to [`KdfParams::recommended`] when `None`.
    ///
    /// Returns the unlocked `Vault` plus the one-time recovery phrase. The
    /// phrase is generated fresh, used to derive the recovery wrapping key,
    /// and then dropped (zeroized) — the caller must show/store it now,
    /// because `vault-core` never persists it in recoverable form.
    pub fn init(
        path: impl AsRef<Path>,
        master_password: &SecretString,
        kdf_params: Option<KdfParams>,
    ) -> Result<(Vault, String)> {
        let path = path.as_ref();
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        let master_kdf = kdf_params.unwrap_or_else(KdfParams::recommended);
        let master_key = kdf::derive_master_key(master_password, &master_kdf)?;

        let vek = VaultEncryptionKey::random();
        let wrapped_vek_master = crypto::encrypt(&master_key.0, vek.0.as_bytes(), AAD_VEK_MASTER)?;

        let recovery = GeneratedRecovery::generate();
        let recovery_salt = recovery::random_recovery_salt();
        let recovery_key = recovery.derive_wrapping_key(&recovery_salt);
        let wrapped_vek_recovery =
            crypto::encrypt(&recovery_key.0, vek.0.as_bytes(), AAD_VEK_RECOVERY)?;
        let phrase = recovery.phrase();

        let header = VaultHeader {
            magic: MAGIC,
            version: FORMAT_VERSION,
            master_kdf,
            recovery_salt,
            wrapped_vek_master,
            wrapped_vek_recovery,
        };

        let data = VaultData::default();
        let vault = Vault {
            path: path.to_path_buf(),
            header,
            vek,
            data,
        };
        vault.save()?;

        Ok((vault, phrase))
    }

    /// Opens an existing vault with the master password.
    pub fn open(path: impl AsRef<Path>, master_password: &SecretString) -> Result<Vault> {
        let path = path.as_ref();
        let file = read_vault_file(path)?;

        let master_key = kdf::derive_master_key(master_password, &file.header.master_kdf)?;
        let vek_bytes = crypto::decrypt(
            &master_key.0,
            &file.header.wrapped_vek_master,
            AAD_VEK_MASTER,
        )?;
        let vek = bytes_to_vek(vek_bytes)?;

        let data = decrypt_entries(&vek, &file.data)?;

        Ok(Vault {
            path: path.to_path_buf(),
            header: file.header,
            vek,
            data,
        })
    }

    /// Opens an existing vault using the BIP39 recovery phrase instead of
    /// the master password. Useful both for actual recovery and for
    /// changing a forgotten master password (open via recovery, then call
    /// [`Vault::rewrap_master_password`]).
    pub fn open_with_recovery(path: impl AsRef<Path>, recovery_phrase: &str) -> Result<Vault> {
        let path = path.as_ref();
        let file = read_vault_file(path)?;

        let recovery_key =
            recovery::wrapping_key_from_phrase(recovery_phrase, &file.header.recovery_salt)?;
        let vek_bytes = crypto::decrypt(
            &recovery_key.0,
            &file.header.wrapped_vek_recovery,
            AAD_VEK_RECOVERY,
        )?;
        let vek = bytes_to_vek(vek_bytes)?;

        let data = decrypt_entries(&vek, &file.data)?;

        Ok(Vault {
            path: path.to_path_buf(),
            header: file.header,
            vek,
            data,
        })
    }

    pub fn entries(&self) -> &[VaultEntry] {
        &self.data.entries
    }

    pub fn add_entry(&mut self, entry: VaultEntry) {
        self.data.entries.push(entry);
    }

    /// Removes the entry with the given id. Returns `true` if an entry was
    /// removed.
    pub fn remove_entry(&mut self, id: &str) -> bool {
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        self.data.entries.len() != before
    }

    /// Re-derives the Master Key from a new password and re-wraps the
    /// existing VEK under it, in place. The VEK itself — and therefore
    /// every entry encrypted with it — is unchanged, so this does not
    /// require re-encrypting vault contents.
    pub fn rewrap_master_password(
        &mut self,
        new_password: &SecretString,
        kdf_params: Option<KdfParams>,
    ) -> Result<()> {
        let master_kdf = kdf_params.unwrap_or_else(KdfParams::recommended);
        let master_key = kdf::derive_master_key(new_password, &master_kdf)?;
        self.header.wrapped_vek_master =
            crypto::encrypt(&master_key.0, self.vek.0.as_bytes(), AAD_VEK_MASTER)?;
        self.header.master_kdf = master_kdf;
        Ok(())
    }

    /// Re-encrypts the current entries under the VEK with a fresh nonce and
    /// atomically overwrites the vault file on disk (temp file + fsync +
    /// rename), so a crash or power loss during the write can never leave
    /// a partially-written vault behind.
    pub fn save(&self) -> Result<()> {
        let plaintext =
            bincode::serialize(&self.data).map_err(|e| VaultError::Serialization(e))?;
        let data_blob = crypto::encrypt(&self.vek.0, &plaintext, AAD_ENTRIES)?;

        let file = VaultFile {
            header: clone_header(&self.header),
            data: data_blob,
        };
        let bytes = bincode::serialize(&file).map_err(|e| VaultError::Serialization(e))?;

        write_atomic(&self.path, &bytes)
    }
}

fn bytes_to_vek(mut bytes: Vec<u8>) -> Result<VaultEncryptionKey> {
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(VaultError::AuthenticationFailed);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(VaultEncryptionKey(crate::keys::SecretKey32::from_bytes(arr)))
}

fn decrypt_entries(vek: &VaultEncryptionKey, blob: &EncryptedBlob) -> Result<VaultData> {
    let mut plaintext = crypto::decrypt(&vek.0, blob, AAD_ENTRIES)?;
    let data: VaultData =
        bincode::deserialize(&plaintext).map_err(|e| VaultError::Serialization(e))?;
    plaintext.zeroize();
    Ok(data)
}

fn clone_header(header: &VaultHeader) -> VaultHeader {
    VaultHeader {
        magic: header.magic,
        version: header.version,
        master_kdf: header.master_kdf.clone(),
        recovery_salt: header.recovery_salt,
        wrapped_vek_master: header.wrapped_vek_master.clone(),
        wrapped_vek_recovery: header.wrapped_vek_recovery.clone(),
    }
}

fn read_vault_file(path: &Path) -> Result<VaultFile> {
    let bytes = fs::read(path)?;
    let file: VaultFile =
        bincode::deserialize(&bytes).map_err(|e| VaultError::Serialization(e))?;

    if file.header.magic != MAGIC {
        return Err(VaultError::InvalidMagic);
    }
    if file.header.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion {
            found: file.header.version,
            expected: FORMAT_VERSION,
        });
    }

    Ok(file)
}

/// Writes `bytes` to `path` without ever leaving a partially-written or
/// mixed old/new file on disk, even across a crash or power loss:
///
/// 1. write the full contents to a temp file in the *same directory*
///    (guarantees the later rename is on the same filesystem, so it's atomic)
/// 2. fsync the temp file's contents to durable storage
/// 3. rename the temp file over the target path (atomic on POSIX and Windows)
/// 4. fsync the containing directory, so the rename itself is durable
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(path.file_name().unwrap_or_default());
    tmp_name.push(format!(".tmp-{}", std::process::id()));
    let tmp_path = dir.join(tmp_name);

    {
        let mut tmp_file = File::create(&tmp_path)?;
        tmp_file.write_all(bytes)?;
        tmp_file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;

    // Best-effort: fsync the directory entry so the rename survives a crash.
    // Not available in a meaningful form on all platforms (e.g. Windows),
    // so failures here are ignored rather than propagated.
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn pw(s: &str) -> SecretString {
        SecretString::new(s.to_string())
    }

    fn fast_params() -> KdfParams {
        KdfParams::with_cost(kdf::MIN_MEMORY_KIB, kdf::MIN_ITERATIONS, 1)
    }

    #[test]
    fn init_creates_file_and_opens_with_same_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");

        let (vault, _phrase) = Vault::init(&path, &pw("hunter2-hunter2"), Some(fast_params()))
            .expect("init should succeed");
        drop(vault);

        assert!(path.exists());

        let opened = Vault::open(&path, &pw("hunter2-hunter2")).expect("open should succeed");
        assert!(opened.entries().is_empty());
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        let result = Vault::open(&path, &pw("wrong-password"));
        assert!(matches!(result, Err(VaultError::AuthenticationFailed)));
    }

    #[test]
    fn recovery_phrase_unlocks_vault_independently_of_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        let (_vault, phrase) =
            Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        let opened =
            Vault::open_with_recovery(&path, &phrase).expect("recovery phrase should unlock");
        assert!(opened.entries().is_empty());
    }

    #[test]
    fn wrong_recovery_phrase_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        let other = GeneratedRecovery::generate();
        let result = Vault::open_with_recovery(&path, &other.phrase());
        assert!(matches!(
            result,
            Err(VaultError::AuthenticationFailed) | Err(VaultError::InvalidRecoveryPhrase)
        ));
    }

    #[test]
    fn entries_round_trip_through_save_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        let (mut vault, _phrase) =
            Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        vault.add_entry(VaultEntry {
            id: "1".into(),
            title: "GitHub".into(),
            username: "r-ahamedasri".into(),
            password: "s3cr3t!".into(),
            url: "https://github.com".into(),
            notes: "personal account".into(),
        });
        vault.save().unwrap();
        drop(vault);

        let reopened = Vault::open(&path, &pw("correct-password")).unwrap();
        assert_eq!(reopened.entries().len(), 1);
        assert_eq!(reopened.entries()[0].title, "GitHub");
        assert_eq!(reopened.entries()[0].password, "s3cr3t!");
    }

    #[test]
    fn init_refuses_to_overwrite_existing_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        let result = Vault::init(&path, &pw("another-password"), Some(fast_params()));
        assert!(matches!(result, Err(VaultError::AlreadyExists)));
    }

    #[test]
    fn tampered_vault_file_fails_to_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        Vault::init(&path, &pw("correct-password"), Some(fast_params())).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let result = Vault::open(&path, &pw("correct-password"));
        assert!(result.is_err());
    }

    #[test]
    fn rewrapping_master_password_lets_new_password_open_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        let (mut vault, _phrase) =
            Vault::init(&path, &pw("old-password"), Some(fast_params())).unwrap();

        vault
            .rewrap_master_password(&pw("new-password"), Some(fast_params()))
            .unwrap();
        vault.save().unwrap();
        drop(vault);

        assert!(Vault::open(&path, &pw("new-password")).is_ok());
        assert!(matches!(
            Vault::open(&path, &pw("old-password")),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn no_temp_files_left_behind_after_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.shulker");
        let (vault, _phrase) = Vault::init(&path, &pw("correct-password"), Some(fast_params()))
            .unwrap();
        vault.save().unwrap();

        let leftover: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftover.is_empty(), "temp file left behind after save");
    }
}
