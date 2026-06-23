use crate::aes::aes_128_ecb_decrypt_pkcs7;
use crate::common::DecryptError;
use log::debug;

/// Decrypt DAP-1325 A1 and DAP-1610 B1 (v1.03+) firmware.
///
/// These devices use AES-128-ECB with a hardcoded key.
/// The first 0x40 bytes are a plaintext header; the rest is encrypted.
pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
    const HEADER_SIZE: usize = 0x40;

    const AES_KEY: &[u8] = b"\x3b\xae\x35\x16\x28\xae\xd2\xa6\x0b\xf7\x15\x28\xc9\xcf\xdf\x3c";

    const MAGIC_START: usize = 0;

    const DECRYPTED_MAGIC: &[u8] = b"ustar";
    const DECRYPTED_MAGIC_START: usize = 0x101;

    if encrypted_data.len() <= HEADER_SIZE {
        debug!("Data too small for DAP-1325 header");
        return Err(DecryptError::Input);
    }

    let Some(header_magic) = encrypted_data.get(MAGIC_START..8) else {
        debug!("Failed to read header magic bytes");
        return Err(DecryptError::Input);
    };

    // Check for supported device magic strings in the header
    let is_dap1325 = header_magic.starts_with(b"DAP-1325");
    let is_dap1610 = header_magic.starts_with(b"DAP-1610");

    if !is_dap1325 && !is_dap1610 {
        debug!("Header magic does not match DAP-1325 or DAP-1610");
        return Err(DecryptError::Input);
    }

    let header = &encrypted_data[..HEADER_SIZE];
    let cipher_data = &encrypted_data[HEADER_SIZE..];

    match aes_128_ecb_decrypt_pkcs7(cipher_data, AES_KEY) {
        Err(e) => {
            debug!("AES-128-ECB decryption failed: {}", e);
            Err(e)
        }
        Ok(decrypted_body) => {
            if let Some(decrypted_magic) = decrypted_body
                .get(DECRYPTED_MAGIC_START..DECRYPTED_MAGIC_START + DECRYPTED_MAGIC.len())
            {
                if decrypted_magic == DECRYPTED_MAGIC {
                    let mut result = Vec::with_capacity(header.len() + decrypted_body.len());
                    result.extend_from_slice(header);
                    result.extend_from_slice(&decrypted_body);
                    Ok(result)
                } else {
                    debug!("Decrypted magic bytes do not match ustar");
                    Err(DecryptError::Output)
                }
            } else {
                debug!("Failed to read decrypted magic bytes");
                Err(DecryptError::Output)
            }
        }
    }
}
