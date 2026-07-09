use crate::aes;
use crate::common::DecryptError;
use log::warn;
use md5::Md5;
use sha2::Digest;

/// The type of hash to use when generating a key/iv pair from a passphrase
#[derive(Clone, Debug)]
pub enum MessageDigest {
    MD5,
    SHA256,
}

impl MessageDigest {
    const fn size(&self) -> usize {
        match self {
            MessageDigest::MD5 => 16,
            MessageDigest::SHA256 => 32,
        }
    }
}

#[derive(Clone, Debug)]
struct OpenSSLCryptInfo {
    iv: Vec<u8>,
    key: Vec<u8>,
}

/// Returns the SHA256 hash of the provided data as if it were all concatenated
fn sha256_digest(data: &[&[u8]]) -> Vec<u8> {
    let mut digest = sha2::Sha256::new();
    for &item in data {
        digest.update(item);
    }
    digest.finalize().to_vec()
}

/// Returns the MD5 hash of the provided data as if it were all concatenated
fn md5_digest(data: &[&[u8]]) -> Vec<u8> {
    let mut digest = Md5::new();
    for &item in data {
        digest.update(item);
    }
    digest.finalize().to_vec()
}

/// Returns the request hash of the provided data, as if it were all concatenated
fn digest(data: &[&[u8]], hash_type: &MessageDigest) -> Vec<u8> {
    match hash_type {
        MessageDigest::MD5 => md5_digest(data),
        MessageDigest::SHA256 => sha256_digest(data),
    }
}

/// Calculates the encryption key and IV from the password and salt values.
fn derive_key_iv(
    password: &str,
    salt: &[u8],
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> OpenSSLCryptInfo {
    const IV_LEN: usize = 16;
    const KEY_LEN: usize = 32;

    // Generate a hash of the password + salt
    let mut hash = digest(&[password.as_bytes(), salt], &hash_type);

    // Because KEY_LEN is evenly divisible by 16 (md5 size) and 32 (sha256 size), this won't lose
    // any key material, if we need to continue generating key material for the IV
    const {
        assert!(KEY_LEN.is_multiple_of(MessageDigest::MD5.size()));
        assert!(KEY_LEN.is_multiple_of(MessageDigest::SHA256.size()));
    }
    let mut key = [0; KEY_LEN];
    let (first, rest) = key.split_at_mut(hash.len());
    first.copy_from_slice(&hash);

    generate_key_material(&mut hash, password.as_bytes(), salt, &hash_type, rest);

    let iv = match iv {
        Some(user_iv) => user_iv.to_vec(),
        None => {
            let mut iv = [0; IV_LEN];
            generate_key_material(&mut hash, password.as_bytes(), salt, &hash_type, &mut iv);
            iv.to_vec()
        }
    };
    OpenSSLCryptInfo {
        key: key.to_vec(),
        iv,
    }
}

fn generate_key_material(
    hash: &mut Vec<u8>,
    password: &[u8],
    salt: &[u8],
    hash_type: &MessageDigest,
    dst: &mut [u8],
) {
    debug_assert_eq!(hash_type.size(), hash.len());
    let mut chunks = dst.chunks_exact_mut(hash_type.size());
    for chunk in &mut chunks {
        // Create a new hash from the last hash + password + salt
        *hash = digest(&[hash.as_slice(), password, salt], hash_type);
        // Append the most recently calculated hash to key_material
        chunk.copy_from_slice(hash);
    }
    let remainder = chunks.into_remainder();
    if !remainder.is_empty() {
        *hash = digest(&[hash.as_slice(), password, salt], hash_type);
        remainder.copy_from_slice(&hash[..remainder.len()]);
    }
}

/// Decrypts an OpenSSL encrypted file
fn decrypt(
    openssl_data: &[u8],
    password: &str,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    const OPENSSL_FILE_MAGIC: &[u8] = b"Salted__";

    // Get and validate the magic file bytes
    if let Some(magic) = openssl_data.get(0..8) {
        if magic == OPENSSL_FILE_MAGIC {
            // Get the 64-bit salt value
            if let Some(salt) = openssl_data.get(8..16) {
                // Derive the encryption key and IV from the salt and provided password
                let crypt = derive_key_iv(password, salt, hash_type, iv);

                // Everything after the salt is the encrypted data
                if let Some(encrypted_data) = openssl_data.get(16..) {
                    // Perform the requested decryption
                    aes::aes_256_cbc_decrypt(encrypted_data, &crypt.key, &crypt.iv)
                } else {
                    warn!("Failed to read OpenSSL encrypted data");
                    Err(DecryptError::Input)
                }
            } else {
                warn!("Failed to read OpenSSL salt");
                Err(DecryptError::Input)
            }
        } else {
            warn!("OpenSSL file magic does not match");
            Err(DecryptError::Input)
        }
    } else {
        warn!("Failed to read OpenSSL magic bytes");
        Err(DecryptError::Input)
    }
}

/// Extract the key and IV from an OpenSSL-format encrypted blob.
pub(crate) fn extract_openssl_key_iv(
    openssl_data: &[u8],
    password: &str,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), DecryptError> {
    let body = openssl_data
        .strip_prefix(b"Salted__")
        .ok_or(DecryptError::Input)?;
    let salt = body.get(..8).ok_or(DecryptError::Input)?;
    let crypt = derive_key_iv(password, salt, hash_type, iv);
    Ok((crypt.key, crypt.iv))
}

/// Decrypts OpenSSL encrypted data using AES-256-CBC
pub fn aes_256_cbc_decrypt(
    openssl_data: &[u8],
    password: &str,
    hash_type: MessageDigest,
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, DecryptError> {
    decrypt(openssl_data, password, hash_type, iv)
}
