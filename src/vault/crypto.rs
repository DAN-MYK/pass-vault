use crate::vault::model::{PasswordOptions, VaultError};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    Ok(key)
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::Crypto("encrypt failed".into()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    if data.len() < 12 {
        return Err(VaultError::Crypto("ciphertext too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Crypto("decrypt failed".into()))
}

pub fn generate_password(opts: &PasswordOptions) -> String {
    let mut charset: Vec<char> = "abcdefghijkmnopqrstuvwxyz".chars().collect();
    if opts.uppercase {
        charset.extend("ABCDEFGHJKLMNPQRSTUVWXYZ".chars());
    }
    if opts.digits {
        charset.extend("23456789".chars());
    }
    if !opts.exclude_ambiguous {
        charset.extend("0O1lI".chars());
    }
    if opts.symbols {
        charset.extend("!@#$%^&*()-_=+[]{}".chars());
    }

    let mut rng = OsRng;
    (0..opts.length)
        .map(|_| charset[rng.gen_range(0..charset.len())])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = derive_key(b"password", b"saltsaltsaltsalt").unwrap();
        let key2 = derive_key(b"password", b"saltsaltsaltsalt").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"secret password";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt(b"secret", &key1).unwrap();
        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_generate_password_length() {
        let opts = PasswordOptions {
            length: 24,
            ..Default::default()
        };
        let pwd = generate_password(&opts);
        assert_eq!(pwd.len(), 24);
    }

    #[test]
    fn test_generate_password_no_symbols() {
        let opts = PasswordOptions {
            length: 100,
            symbols: false,
            ..Default::default()
        };
        let pwd = generate_password(&opts);
        assert!(pwd.chars().all(|c| c.is_alphanumeric()));
    }
}
