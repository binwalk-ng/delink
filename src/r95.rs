use crate::common::DecryptError;
use crate::openssl::{MessageDigest, aes_256_cbc_decrypt};
use log::debug;

/// Decrypt R95/M95/R36/M36 firmware
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Decrypted data is expected to be a DTB file
    const MAGIC: &[u8] = b"\xd0\x0d\xfe\xed";
    const MAGIC_START: usize = 0;
    const MAGIC_END: usize = MAGIC_START + MAGIC.len();
    const OPENSSL_MAGIC: &[u8] = b"Salted__";
    const OPENSSL_MAGIC_OFFSET: usize = 512;

    // Known encryption passwords for these models
    const PASSWORDS: &[&str] = &[
        // R36
        "CAD1C42B11F1982FFA94B6A24C260A43",
        // M36
        "A11E331C15CE73ABA8E06171A11D2FB6",
        // R95
        "BE81AE1B6F523AC7164C4FD67B6BD8FD",
        // M95
        "91A9A3AF2218F4EA60AC37D5835EB318",
    ];

    let openssl_data = encrypted_data
        .get(OPENSSL_MAGIC_OFFSET..)
        .filter(|rest| rest.starts_with(OPENSSL_MAGIC))
        .unwrap_or(encrypted_data);

    for &password in PASSWORDS {
        let Ok(decrypted_data) =
            aes_256_cbc_decrypt(openssl_data, password, MessageDigest::SHA256, None)
        else {
            continue;
        };

        if decrypted_data.get(MAGIC_START..MAGIC_END) == Some(MAGIC) {
            return Ok(decrypted_data);
        }
    }

    debug!("Failed to decrypt with known keys");
    Err(DecryptError::Decrypt)
}
