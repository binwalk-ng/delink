use crate::common::DecryptError;
use aes::cipher::{
    Array, BlockCipherDecrypt, BlockModeDecrypt, KeyInit, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
    typenum,
};
use log::warn;

pub enum AesKeySize {
    AES128 = 16,
    _AES192 = 24,
    AES256 = 32,
}

/// Padding modes for AES decryption
#[derive(Debug, Clone, Copy)]
pub enum AesPaddingMode {
    /// No padding - input must be a multiple of the block size
    NoPadding,
    /// PKCS7 padding
    WithPadding,
}

/// Decrypts data without padding using an initialized decryptor
fn decrypt_unpadded<M: BlockModeDecrypt>(
    decryptor: M,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if !encrypted_data.len().is_multiple_of(16) {
        return Err(DecryptError::InvalidInputLength);
    }

    let mut output_buffer = encrypted_data.to_vec();
    decryptor
        .decrypt_padded::<NoPadding>(&mut output_buffer)
        .map_err(|_| DecryptError::InvalidInputLength)?;

    Ok(output_buffer)
}

/// Decrypts data with PKCS7 padding using an initialized decryptor
fn decrypt_padded<M: BlockModeDecrypt>(
    decryptor: M,
    encrypted_data: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let mut output_buffer = encrypted_data.to_vec();
    decryptor
        .decrypt_padded::<Pkcs7>(&mut output_buffer)
        .map(|data| data.to_vec())
        .map_err(|_| {
            warn!("Decryption failed with padding");
            DecryptError::Decrypt
        })
}

/// Generic AES-CBC decryption function
pub fn aes_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
    key_size: AesKeySize,
    padding: AesPaddingMode,
) -> Result<Vec<u8>, DecryptError> {
    let key_len = key_size as usize;
    let cropped_key = key
        .get(..key_len)
        .ok_or(DecryptError::InvalidKeySize(key.len()))?;

    // IV for AES is universally 16 bytes.
    let iv_bytes: &[u8; 16] = iv
        .get(..16)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DecryptError::InvalidInputLength)?;

    // Instantiate the decryptor engine and immediately process the data
    match key_len {
        16 => {
            let key_bytes: &[u8; 16] = cropped_key.try_into().map_err(|_| DecryptError::Decrypt)?;
            let decryptor = cbc::Decryptor::<aes::Aes128>::new(key_bytes.into(), iv_bytes.into());
            match padding {
                AesPaddingMode::NoPadding => decrypt_unpadded(decryptor, encrypted_data),
                AesPaddingMode::WithPadding => decrypt_padded(decryptor, encrypted_data),
            }
        }
        24 => {
            let key_bytes: &[u8; 24] = cropped_key.try_into().map_err(|_| DecryptError::Decrypt)?;
            let decryptor = cbc::Decryptor::<aes::Aes192>::new(key_bytes.into(), iv_bytes.into());
            match padding {
                AesPaddingMode::NoPadding => decrypt_unpadded(decryptor, encrypted_data),
                AesPaddingMode::WithPadding => decrypt_padded(decryptor, encrypted_data),
            }
        }
        32 => {
            let key_bytes: &[u8; 32] = cropped_key.try_into().map_err(|_| DecryptError::Decrypt)?;
            let decryptor = cbc::Decryptor::<aes::Aes256>::new(key_bytes.into(), iv_bytes.into());
            match padding {
                AesPaddingMode::NoPadding => decrypt_unpadded(decryptor, encrypted_data),
                AesPaddingMode::WithPadding => decrypt_padded(decryptor, encrypted_data),
            }
        }
        size => Err(DecryptError::InvalidKeySize(size)),
    }
}

/// Convenience function for AES-128-CBC decryption with padding
pub fn aes_128_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES128,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-128-CBC decryption without padding
pub fn aes_128_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES128,
        AesPaddingMode::NoPadding,
    )
}

/// Convenience function for AES-192-CBC decryption with padding
pub fn _aes_192_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::_AES192,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-192-CBC decryption without padding
pub fn _aes_192_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::_AES192,
        AesPaddingMode::NoPadding,
    )
}

/// Convenience function for AES-256-CBC decryption with padding
pub fn aes_256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES256,
        AesPaddingMode::WithPadding,
    )
}

/// Convenience function for AES-256-CBC decryption without padding
pub fn aes_256_cbc_decrypt_unpadded(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    aes_cbc_decrypt(
        encrypted_data,
        key,
        iv,
        AesKeySize::AES256,
        AesPaddingMode::NoPadding,
    )
}

/// Decrypts data using AES-128-ECB (no padding removal).
///
/// The input length must be a multiple of 16.
pub fn aes_128_ecb_decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if !encrypted_data.len().is_multiple_of(16) {
        return Err(DecryptError::InvalidInputLength);
    }

    let key_bytes: &[u8; 16] = key
        .get(..16)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DecryptError::InvalidKeySize(key.len()))?;
    let cipher = aes::Aes128::new(key_bytes.into());

    let mut decrypted = Vec::with_capacity(encrypted_data.len());
    for chunk in encrypted_data.chunks(16) {
        let mut block: Array<u8, typenum::U16> = chunk
            .try_into()
            .map_err(|_| DecryptError::InvalidInputLength)?;
        cipher.decrypt_block(&mut block);
        decrypted.extend_from_slice(&block);
    }

    Ok(decrypted)
}

/// Decrypts data using AES-128-ECB, then strips PKCS7 padding.
///
/// The last byte of the decrypted output indicates the number of padding bytes.
pub fn aes_128_ecb_decrypt_pkcs7(
    encrypted_data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let decrypted = aes_128_ecb_decrypt(encrypted_data, key)?;

    // PKCS7: the last byte indicates the number of padding bytes
    let pad_byte = *decrypted.last().ok_or(DecryptError::Decrypt)?;
    let pad_len = pad_byte as usize;

    if pad_len == 0 || pad_len > decrypted.len() || pad_len > 16 {
        return Err(DecryptError::Decrypt);
    }

    // Verify all padding bytes match the expected value
    if !decrypted[decrypted.len() - pad_len..]
        .iter()
        .all(|&b| b == pad_byte)
    {
        return Err(DecryptError::Decrypt);
    }

    Ok(decrypted[..decrypted.len() - pad_len].to_vec())
}
