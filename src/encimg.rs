use crate::aes::aes_256_cbc_decrypt_unpadded;
use crate::common::DecryptError;
use log::debug;

#[derive(Copy, Clone, Debug)]
struct EncimgFirmware {
    name: &'static str,
    encrypted_data_offset: usize,
    image_sign: ImageSign,
}

#[derive(Copy, Clone, Debug)]
enum ImageSign {
    ComputedKeys([EncimgKey; PROG_BOARD_FWS.len()]),
    AtOffset(usize),
}

/// Decrypts firmware that has been encrypted using D-Link's encimg tool.
pub fn decrypt(encrypted_image: &[u8]) -> Result<Vec<u8>, DecryptError> {
    const MAGIC_LEN: usize = 4;

    // Valid decrypted magic bytes
    const KNOWN_DECRYPTED_MAGICS: &[[u8; MAGIC_LEN]] = &[
        *b"\x5E\xA3\xA4\x17",
        *b"\xD0\x0D\xFE\xED",
        *b"\x5D\x00\x00\x80",
    ];

    // Loop through all known firmwares
    for firmware in KNOWN_FIRMWARES {
        debug!("Trying {} keys", firmware.name);

        // Get the actual encrypted data
        if let Some(encrypted_data) = encrypted_image.get(firmware.encrypted_data_offset..) {
            let keys_storage;
            // Most keys are statically computable, so we can use them directly,
            // but some (DIR-2610) require generating keys based on data in the image itself.
            let keys = match firmware.image_sign {
                ImageSign::ComputedKeys(ref keys) => keys,
                ImageSign::AtOffset(offset) => {
                    let signing_value = encrypted_image.get(offset..).unwrap_or(&[]);
                    let len = signing_value
                        .iter()
                        .position(|b| *b == b'\0')
                        .unwrap_or(signing_value.len());
                    // Sanity check
                    if len == 0 {
                        debug!("No image sign");
                        return Err(DecryptError::Input);
                    }
                    let signing_value = &signing_value[..len];
                    keys_storage = keygen(signing_value);
                    &keys_storage
                }
            };
            for crypto in keys {
                if let Some(first_block) = encrypted_data.get(..16)
                    && let Ok(first_block) =
                        aes_256_cbc_decrypt_unpadded(first_block, &crypto.key, &crypto.iv)
                    && KNOWN_DECRYPTED_MAGICS
                        .iter()
                        .any(|m| first_block.starts_with(m))
                {
                    debug!("Decryption of first block OK");
                    if let Ok(decrypted) =
                        aes_256_cbc_decrypt_unpadded(encrypted_data, &crypto.key, &crypto.iv)
                    {
                        return Ok(decrypted);
                    }
                }
            }
        }
    }

    debug!("All decryption keys have failed");
    Err(DecryptError::Decrypt)
}

#[derive(Copy, Debug, Default, Clone)]
pub struct EncimgKey {
    pub iv: [u8; 16],
    pub key: [u8; 32],
}

/// Derive possible decryption keys from a given image_sign string
pub const fn keygen(image_sign: &[u8]) -> [EncimgKey; PROG_BOARD_FWS.len()] {
    let mut keys = PROG_BOARD_KEYS;
    let mut i = 0;
    while i < keys.len() {
        encrypt_xor(image_sign, &mut keys[i].iv);
        encrypt_xor(image_sign, &mut keys[i].key);
        i += 1;
    }
    keys
}

/// Same as the encrypt_xor function in the encimg binary
pub const fn encrypt_xor(image_sign: &[u8], data: &mut [u8]) {
    const MAX_XOR_BYTE: u8 = 0xFB;

    let mut xor_byte: u8 = 1;
    let mut i = 0;
    while i < data.len() {
        let sign_byte = image_sign[i % image_sign.len()];
        data[i] ^= sign_byte ^ xor_byte;
        xor_byte += 1;
        if xor_byte > MAX_XOR_BYTE {
            xor_byte = 0;
        }
        i += 1;
    }
}

// All known firmware images and their associated image_sign values.
// Some are re-used amongst other devices.
const KNOWN_FIRMWARES: &[EncimgFirmware] = &[
    EncimgFirmware {
        name: "DAP-1665",
        image_sign: ImageSign::ComputedKeys(keygen(b"wapac25_dlink.2015_dap1665")),
        encrypted_data_offset: 0,
    },
    EncimgFirmware {
        name: "DIR-822",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac43s_dlink.2015_dir822c1")),
        encrypted_data_offset: 0,
    },
    EncimgFirmware {
        name: "DIR-842",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac65_dlink.2015_dir842")),
        encrypted_data_offset: 0,
    },
    EncimgFirmware {
        name: "DIR-850L A1",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac05_dlob.hans_dir850l")),
        encrypted_data_offset: 0,
    },
    EncimgFirmware {
        name: "DIR-850L B1",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac25_dlink.2013gui_dir850l")),
        encrypted_data_offset: 0,
    },
    // DIR-880L Rev A v1.08b06. Pairs with the DIR-880L prog_board_fw seed;
    // decryption verified against DIR880A1_FW108b06_beta02.bin.
    EncimgFirmware {
        name: "DIR-880L",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac16_dlink.2013gui_dir880")),
        encrypted_data_offset: 0,
    },
    // DIR-885L Rev A v1.21B03. Pairs with the DIR-885L prog_board_fw seed;
    // decryption verified against DIR885LA1_FW121b03.bin.
    EncimgFirmware {
        name: "DIR-885L",
        image_sign: ImageSign::ComputedKeys(keygen(b"wrgac42_dlink.2015_dir885l")),
        encrypted_data_offset: 0,
    },
    // DAP-1720 Ax FW102b01. Pairs with the DAP-1720 prog_board_fw seed;
    // image_sign recovered from firmware, not yet verified against a sample image.
    EncimgFirmware {
        name: "DAP-1720",
        image_sign: ImageSign::ComputedKeys(keygen(b"wapac28_dlink.2015_dap1720")),
        encrypted_data_offset: 0,
    },
    EncimgFirmware {
        name: "DIR-2610",
        image_sign: ImageSign::AtOffset(0),
        encrypted_data_offset: 0xA0,
    },
];

// Doing some contortions to keep this `const` evaluatable, but this should mean
// only these values will be included in the binary, rather than the whole values
// in PROG_BOARD_FWS
//
// Returned EncimgKeys are not yet xor-encrypted
const PROG_BOARD_KEYS: [EncimgKey; PROG_BOARD_FWS.len()] = {
    const KEY_SEED_START: usize = 0x20;

    const IV_SEED_START: usize = 0x60;

    let mut results = [EncimgKey {
        iv: [0; 16],
        key: [0; 32],
    }; PROG_BOARD_FWS.len()];

    let mut i = 0;
    while i < PROG_BOARD_FWS.len() {
        let key = {
            let (_, rest) = PROG_BOARD_FWS[i].split_at(KEY_SEED_START);
            let (key, _) = rest.split_at(32);
            key
        };
        results[i].key.copy_from_slice(key);
        let iv = {
            let (_, rest) = PROG_BOARD_FWS[i].split_at(IV_SEED_START);
            let (iv, _) = rest.split_at(16);
            iv
        };
        results[i].iv.copy_from_slice(iv);

        i += 1;
    }

    results
};

// List of known prog_board_fw strings from various encimg releases.
// Multiple devices may use the same prog_board_fw string.
const PROG_BOARD_FWS: &[[u8; 0x80]] = &[
    // Device(s): DAP-1665
    // Firmware:  DAP-1665 Rev B v2.03B02, DAP-1665 B1 v2.06b01, DAP1665 FW202WWb05 / FW203WWb02 / FW203WWb03
    *b"5gHW13MScSB4Xqqr8Mg8xl0zlQXCfykXEfCHXytwsC6F0zsedwZc+9vDbCjE3ge4Ts0682B35XQG\nP2tuxxuLMlvCJ266ZlnggPy917jwESpnfXmMiZRNcSviifjxTlg",
    // Device(s): DIR-850L A1
    // Firmware:  DIR-850L Rev A v1.21B06 / v1.21B07, DIR850LA1 FW115WWb04 / FW120WWb03 / FW121WWb06 / FW121WWb07
    *b"vzoLuJSCIFc3UwLZ6Is4Tyu95dFg9MssBIuS1CVMEQG+0pUeE99jnR+vLlLd9unrlvhwEvRdn99R\nEYmbe6y0HeABq/NtIXwf3+odwHhmJL1ceW16UsU3xgR7QH0CO9c",
    // Device(s): DIR-850L B1
    // Firmware:  DIR-850L Rev B v2.20B03 / v2.22B02, DIR850LB1 FW210WWb03 / FW220WWb03 / FW222WWb02
    *b"k5NI1+bvWEfZ6ohtpUOwynOdUcivqwEZqQehHMEmEPQ5izL+cabn8bNHZXHjkp6WCl9yn9CIkiI1\nmTFu21TEEPo66JBFv9BMmb+IKQgnO8OuF4bz4frGPdN67gYLuOs",
    // Device(s): DAP-2610, DAP-2680, DAP-2682 (shared seed)
    // Firmware:  DAP-2680 Rev A v2.00.044, DAP2680 v100-rc011, DAP-2682 Rev A v1.00R022, DAP2682 v100-r022
    *b"db6zOuf7GJWGI64bm0DXpZ1rn4hFmPTxoVhq0hvXHdfaGFLdubM4/QvuVHdKee7vh6tC/sBL2t8h\n9GtlNghPDnf9wPrYOLk0BO5nlYankuVBe4sWaltHEHh7NToCSdq",
    // Device(s): DIR-822 C1
    // Firmware:  DIR-822 Rev C v3.12B04 / v3.15B02, DIR822C1 FW303WWb04 / FW312WWb04 / FW315WWb02
    *b"2q02Oz+DDDKjLmMENiZN+3M8VucG4rYfKNpsEntCcsep1jdFIs3wnXySKRGNCGmfzYHzJEPD3GbX\ne/AF4zbvpjuPlmq58fHuph587JdKHrtAUlrli4/FkiKXBfDFbn2",
    // Device(s): DIR-842 C1
    // Firmware:  DIR-842 Rev C v3.11B05 / v3.12B01 / v3.13B05 / v3.13B10, DIR842C1 FW311b05 / FW312WWb01 / FW313WWb05 / FW313betab10
    *b"XYWFilP+ZyydvsXAJSgKeF/p15q05g68xQYoRZeD726UAbRb846kO7TeNw8eZa6ucKxYrhxNbzjP\nbpgFJ7Yxa6sBeujdJ7fzufEbNF3kUafxFiESBRQI6qQbszYOvJI",
    // Device(s): DIR-880L
    // Firmware:  DIR-880L Rev A v1.08b06
    *b"zUKwzudh76LnvKn9ZuU7iCEKLn4AyZTzFA83N1HdSQ9a5YcaaR1lqgkNdoEMeC1Kiagz1vo2YQby\nDmbiJ26WkCUONBWMRAHpQkgnYasQKO8a85wFo/Afeai1osr1EMs",
    // Device(s): DIR-885L
    // Firmware:  DIR-885L Rev A v1.21B03
    *b"HmV3mM6LvKgme0I1ItdkG6GI6zF1z4dxB1QrUHCIiUnKDLmHe+1Z4F/GlkTtrbk4ke+WpvIIYUz2\naRNm8ctukxR8Chx4NtGsWa+i+wqeloTIefj73nDe1ZJ1GH3YlfY",
    // Device(s): DAP-1720 Ax
    // Firmware:  DAP-1720 Ax FW102b01
    *b"0F7Suq0T6zpS1oglmOWAZrtGAzhbVZ5zqBiz6o/1RVQTtJBd3FS7FDbqogE8yoBm8+xNhquuPyrT\njjSmIagnLik1G/uNmJGEfDMqWWxHCOhEqgYAooA3QPHAShwPOP5",
];
