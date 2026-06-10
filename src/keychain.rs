//! OS keychain integration for passwordless `run`.
//!
//! The master password is stored under the `env-shield` service with the
//! canonical vault path as the account, so multiple vaults coexist. The
//! backing store is the OS-native one: macOS Keychain, Windows Credential
//! Manager, or the Secret Service (GNOME Keyring / `KWallet`) on Linux — all
//! encrypted at rest and gated by the OS login session.

use std::path::Path;

use anyhow::{Context, Result};
use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE: &str = "env-shield";

fn entry_for(vault_path: &Path) -> Result<Entry> {
    // Canonicalize so `./.env-shield` and its absolute path share one entry;
    // fall back to the given path when the vault does not exist yet.
    let account = vault_path
        .canonicalize()
        .unwrap_or_else(|_| vault_path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    Entry::new(SERVICE, &account).context("failed to access the OS keychain")
}

/// Stores the master password for this vault.
pub fn store(vault_path: &Path, password: &str) -> Result<()> {
    entry_for(vault_path)?
        .set_password(password)
        .context("failed to store the master password in the OS keychain")
}

/// Fetches the stored master password, or `None` when there is no entry or
/// no usable keychain (e.g. headless CI) — callers fall back to prompting.
pub fn get(vault_path: &Path) -> Option<Zeroizing<String>> {
    let entry = entry_for(vault_path).ok()?;
    entry.get_password().ok().map(Zeroizing::new)
}

/// Removes the stored master password. Returns whether an entry existed.
pub fn forget(vault_path: &Path) -> Result<bool> {
    match entry_for(vault_path)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(e).context("failed to remove the master password from the OS keychain"),
    }
}
