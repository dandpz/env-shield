//! Password-based key derivation and authenticated encryption.
//!
//! Master password --Argon2id--> 32-byte key --XChaCha20-Poly1305--> vault
//! payload. The derived key and every decrypted buffer are zeroized when
//! dropped.

use argon2::Argon2;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit},
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Argon2 salt length in bytes.
pub const SALT_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Symmetric key length in bytes.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (wrong password or corrupted vault)")]
    Decrypt,
}

/// A derived vault key. Wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

/// Derives a [`VaultKey`] from the master password using Argon2id with the
/// crate's default (OWASP-recommended) parameters: m = 19 MiB, t = 2, p = 1.
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<VaultKey, CryptoError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(VaultKey(key))
}

/// Generates a fresh random salt from the OS CSPRNG.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Encrypts `plaintext` under `key` with a freshly generated random nonce.
///
/// Returns `(nonce, ciphertext)`. The 192-bit `XChaCha20` nonce is large
/// enough that random generation carries no practical collision risk.
pub fn encrypt(
    key: &VaultKey,
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce
        .as_slice()
        .try_into()
        .expect("XChaCha20 nonce is always 24 bytes");
    Ok((nonce_bytes, ciphertext))
}

/// Decrypts and authenticates `ciphertext`. Any tampering with the
/// ciphertext, nonce, or use of a wrong key fails the Poly1305 tag check.
///
/// The returned buffer is zeroized when dropped.
pub fn decrypt(
    key: &VaultKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let salt = random_salt();
        let key = derive_key(b"correct horse battery staple", &salt).unwrap();
        let (nonce, ciphertext) = encrypt(&key, b"DATABASE_URL=postgres://x").unwrap();
        let plaintext = decrypt(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(&*plaintext, b"DATABASE_URL=postgres://x");
    }

    #[test]
    fn wrong_password_fails() {
        let salt = random_salt();
        let key = derive_key(b"right password", &salt).unwrap();
        let (nonce, ciphertext) = encrypt(&key, b"secret").unwrap();

        let wrong = derive_key(b"wrong password", &salt).unwrap();
        assert!(matches!(
            decrypt(&wrong, &nonce, &ciphertext),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let salt = random_salt();
        let key = derive_key(b"pw", &salt).unwrap();
        let (nonce, mut ciphertext) = encrypt(&key, b"secret").unwrap();
        ciphertext[0] ^= 0x01;
        assert!(matches!(
            decrypt(&key, &nonce, &ciphertext),
            Err(CryptoError::Decrypt)
        ));
    }
}
