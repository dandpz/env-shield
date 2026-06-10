//! Vault file format, (de)serialization, and atomic persistence.
//!
//! On-disk layout (all fields raw bytes, no framing needed since the
//! ciphertext runs to EOF):
//!
//! ```text
//! +----------+-----------+------------+----------------------+
//! | MAGIC(8) | salt (16) | nonce (24) | ciphertext (rest)    |
//! +----------+-----------+------------+----------------------+
//! ```
//!
//! The plaintext payload is a JSON document holding multiple named
//! environments plus the name of the default one:
//!
//! ```json
//! { "default_env": "dev", "envs": { "dev": { "KEY": "VALUE" } } }
//! ```
//!
//! Vaults written by env-shield 0.1 (a bare `{ "KEY": "VALUE" }` map) are
//! transparently migrated into a single `default` environment on load.
//!
//! Every `save` re-derives the key under a fresh salt and fresh nonce, so a
//! nonce is never reused across writes.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, CryptoError, NONCE_LEN, SALT_LEN};

const MAGIC: &[u8; 8] = b"ENVSHLD\x01";
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;

/// Name of the environment created by `init` and used for legacy migration.
pub const DEFAULT_ENV: &str = "default";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("no vault found at `{0}`; run `env-shield init` first")]
    NotFound(String),
    #[error("`{0}` is not an env-shield vault or is corrupted")]
    Malformed(String),
    #[error("environment `{0}` does not exist (create it with `env-shield env add {0}`)")]
    NoSuchEnv(String),
    #[error("environment `{0}` already exists")]
    EnvExists(String),
    #[error(
        "cannot remove `{0}`: it is the default environment (switch first with `env-shield env use <other>`)"
    )]
    RemoveDefault(String),
    #[error("invalid environment name `{0}`")]
    InvalidEnvName(String),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault payload could not be (de)serialized")]
    Payload,
}

/// A decrypted secret map for one environment. Keys and values are zeroized
/// on drop.
#[derive(Default, Serialize, Deserialize)]
pub struct Secrets(BTreeMap<String, String>);

impl Secrets {
    /// Inserts or replaces a secret, wiping any displaced previous value.
    pub fn insert(&mut self, key: String, value: String) {
        if let Some(mut old) = self.0.insert(key, value) {
            old.zeroize();
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Zeroize for Secrets {
    fn zeroize(&mut self) {
        // BTreeMap offers no in-place mutable access to keys, so take the
        // map apart and wipe each entry as it is consumed.
        for (mut key, mut value) in std::mem::take(&mut self.0) {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The decrypted vault: named environments plus the default's name.
///
/// Environment names are not treated as secrets; the [`Secrets`] they hold
/// zeroize themselves on drop.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    default_env: String,
    envs: BTreeMap<String, Secrets>,
}

impl Default for Vault {
    fn default() -> Self {
        let mut envs = BTreeMap::new();
        envs.insert(DEFAULT_ENV.to_string(), Secrets::default());
        Self {
            default_env: DEFAULT_ENV.to_string(),
            envs,
        }
    }
}

impl Vault {
    pub fn default_env(&self) -> &str {
        &self.default_env
    }

    pub fn env_names(&self) -> impl Iterator<Item = &str> {
        self.envs.keys().map(String::as_str)
    }

    /// Resolves `env` (or the default when `None`) to its name.
    pub fn resolve_name<'a>(&'a self, env: Option<&'a str>) -> &'a str {
        env.unwrap_or(&self.default_env)
    }

    pub fn secrets(&self, env: Option<&str>) -> Result<&Secrets, VaultError> {
        let name = self.resolve_name(env);
        self.envs
            .get(name)
            .ok_or_else(|| VaultError::NoSuchEnv(name.to_string()))
    }

    pub fn secrets_mut(&mut self, env: Option<&str>) -> Result<&mut Secrets, VaultError> {
        let name = self.resolve_name(env).to_string();
        self.envs.get_mut(&name).ok_or(VaultError::NoSuchEnv(name))
    }

    pub fn add_env(&mut self, name: &str) -> Result<(), VaultError> {
        if name.is_empty() || name.contains('\0') {
            return Err(VaultError::InvalidEnvName(name.to_string()));
        }
        if self.envs.contains_key(name) {
            return Err(VaultError::EnvExists(name.to_string()));
        }
        self.envs.insert(name.to_string(), Secrets::default());
        Ok(())
    }

    /// Removes an environment; its secrets are zeroized when dropped.
    pub fn remove_env(&mut self, name: &str) -> Result<(), VaultError> {
        if name == self.default_env {
            return Err(VaultError::RemoveDefault(name.to_string()));
        }
        self.envs
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| VaultError::NoSuchEnv(name.to_string()))
    }

    pub fn set_default(&mut self, name: &str) -> Result<(), VaultError> {
        if !self.envs.contains_key(name) {
            return Err(VaultError::NoSuchEnv(name.to_string()));
        }
        self.default_env = name.to_string();
        Ok(())
    }
}

/// Reads and decrypts the vault at `path`.
pub fn load(path: &Path, password: &[u8]) -> Result<Vault, VaultError> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::NotFound(path.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };

    if data.len() <= HEADER_LEN || &data[..MAGIC.len()] != MAGIC {
        return Err(VaultError::Malformed(path.display().to_string()));
    }
    let salt: [u8; SALT_LEN] = data[MAGIC.len()..MAGIC.len() + SALT_LEN]
        .try_into()
        .expect("slice length checked above");
    let nonce: [u8; NONCE_LEN] = data[MAGIC.len() + SALT_LEN..HEADER_LEN]
        .try_into()
        .expect("slice length checked above");
    let ciphertext = &data[HEADER_LEN..];

    let key = crypto::derive_key(password, &salt)?;
    let plaintext = crypto::decrypt(&key, &nonce, ciphertext)?;
    deserialize_payload(&plaintext)
}

/// Parses the decrypted payload, transparently migrating the legacy
/// single-map format (env-shield 0.1) into a lone `default` environment.
fn deserialize_payload(plaintext: &[u8]) -> Result<Vault, VaultError> {
    if let Ok(vault) = serde_json::from_slice::<Vault>(plaintext) {
        return Ok(vault);
    }
    let legacy: Secrets = serde_json::from_slice(plaintext).map_err(|_| VaultError::Payload)?;
    let mut envs = BTreeMap::new();
    envs.insert(DEFAULT_ENV.to_string(), legacy);
    Ok(Vault {
        default_env: DEFAULT_ENV.to_string(),
        envs,
    })
}

/// Encrypts the vault and writes it to `path` atomically.
pub fn save(path: &Path, password: &[u8], vault: &Vault) -> Result<(), VaultError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(vault).map_err(|_| VaultError::Payload)?);

    let salt = crypto::random_salt();
    let key = crypto::derive_key(password, &salt)?;
    let (nonce, ciphertext) = crypto::encrypt(&key, &plaintext)?;

    let mut blob = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    write_atomic(path, &blob)
}

/// Writes via a same-directory temp file followed by a rename, so a crash
/// mid-write never leaves a truncated vault. The file is created with
/// owner-only permissions on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| VaultError::Malformed(path.display().to_string()))?;
    let tmp_path = dir.join(format!("{}.tmp", file_name.to_string_lossy()));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // Remove any stale temp file from a previous crash so create_new (which
    // guarantees our restrictive mode is applied) cannot spuriously fail.
    let _ = fs::remove_file(&tmp_path);

    let mut file = options.open(&tmp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vault {
        let mut vault = Vault::default();
        vault.add_env("staging").unwrap();
        vault
            .secrets_mut(None)
            .unwrap()
            .insert("API_KEY".into(), "sk-12345".into());
        vault
            .secrets_mut(Some("staging"))
            .unwrap()
            .insert("API_KEY".into(), "sk-staging".into());
        vault
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");

        save(&path, b"hunter2", &sample()).unwrap();
        let loaded = load(&path, b"hunter2").unwrap();

        assert_eq!(loaded.default_env(), DEFAULT_ENV);
        assert_eq!(
            loaded.env_names().collect::<Vec<_>>(),
            vec!["default", "staging"]
        );
        let (key, value) = loaded.secrets(None).unwrap().iter().next().unwrap();
        assert_eq!((key.as_str(), value.as_str()), ("API_KEY", "sk-12345"));
        let (key, value) = loaded
            .secrets(Some("staging"))
            .unwrap()
            .iter()
            .next()
            .unwrap();
        assert_eq!((key.as_str(), value.as_str()), ("API_KEY", "sk-staging"));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");

        save(&path, b"hunter2", &sample()).unwrap();
        assert!(matches!(
            load(&path, b"*******"),
            Err(VaultError::Crypto(CryptoError::Decrypt))
        ));
    }

    #[test]
    fn missing_vault_reports_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.bin");
        assert!(matches!(load(&path, b"pw"), Err(VaultError::NotFound(_))));
    }

    #[test]
    fn garbage_file_reports_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.bin");
        fs::write(&path, b"definitely not a vault").unwrap();
        assert!(matches!(load(&path, b"pw"), Err(VaultError::Malformed(_))));
    }

    #[test]
    fn legacy_single_map_vault_is_migrated() {
        // Hand-craft a 0.1-format vault: payload is a bare key/value map.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.bin");

        let salt = crypto::random_salt();
        let key = crypto::derive_key(b"hunter2", &salt).unwrap();
        let (nonce, ciphertext) = crypto::encrypt(&key, br#"{"OLD_KEY":"old-value"}"#).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        fs::write(&path, blob).unwrap();

        let vault = load(&path, b"hunter2").unwrap();
        assert_eq!(vault.default_env(), DEFAULT_ENV);
        let (key, value) = vault.secrets(None).unwrap().iter().next().unwrap();
        assert_eq!((key.as_str(), value.as_str()), ("OLD_KEY", "old-value"));
    }

    #[test]
    fn env_management() {
        let mut vault = Vault::default();

        vault.add_env("staging").unwrap();
        assert!(matches!(
            vault.add_env("staging"),
            Err(VaultError::EnvExists(_))
        ));
        assert!(matches!(
            vault.add_env(""),
            Err(VaultError::InvalidEnvName(_))
        ));

        assert!(matches!(
            vault.secrets(Some("prod")),
            Err(VaultError::NoSuchEnv(_))
        ));

        // Default cannot be removed until another env takes its place.
        assert!(matches!(
            vault.remove_env(DEFAULT_ENV),
            Err(VaultError::RemoveDefault(_))
        ));
        vault.set_default("staging").unwrap();
        assert_eq!(vault.default_env(), "staging");
        vault.remove_env(DEFAULT_ENV).unwrap();
        assert_eq!(vault.env_names().collect::<Vec<_>>(), vec!["staging"]);

        assert!(matches!(
            vault.set_default("ghost"),
            Err(VaultError::NoSuchEnv(_))
        ));
    }

    #[test]
    fn replacing_a_value_wipes_the_old_one() {
        let mut vault = sample();
        let secrets = vault.secrets_mut(None).unwrap();
        secrets.insert("API_KEY".into(), "sk-67890".into());
        assert_eq!(secrets.len(), 1);
        let value = secrets
            .iter()
            .find(|(k, _)| k.as_str() == "API_KEY")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(value, "sk-67890");
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.bin");
        save(&path, b"pw", &sample()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
