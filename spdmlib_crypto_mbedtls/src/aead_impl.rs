// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmAead;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_PARAMETER};

use spdmlib::protocol::{SpdmAeadAlgo, SpdmAeadIvStruct, SpdmAeadKeyStruct};

use crate::ffi::{
    spdm_aead_aes_gcm_decrypt, spdm_aead_aes_gcm_encrypt, spdm_aead_chacha20_poly1305_decrypt,
    spdm_aead_chacha20_poly1305_encrypt,
};

pub static DEFAULT: SpdmAead = SpdmAead {
    encrypt_cb: encrypt,
    decrypt_cb: decrypt,
};

fn encrypt(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    match aead_algo {
        SpdmAeadAlgo::AES_128_GCM | SpdmAeadAlgo::AES_256_GCM => unsafe {
            let mut cipher_len: usize = cipher_text.len();
            let res = spdm_aead_aes_gcm_encrypt(
                key.as_ref().as_ptr(),
                key.data_size as usize,
                iv.as_ref().as_ptr(),
                iv.data_size as usize,
                aad.as_ptr(),
                aad.len(),
                plain_text.as_ptr(),
                plain_text.len(),
                tag.as_mut_ptr(),
                tag.len(),
                cipher_text.as_mut_ptr(),
                &mut cipher_len as *mut usize,
            );
            if res == 0 {
                panic!("gcm_encrypt error!");
            }
            Ok((cipher_len, tag.len()))
        },
        SpdmAeadAlgo::CHACHA20_POLY1305 => unsafe {
            let mut cipher_text_len: usize = cipher_text.len();
            spdm_aead_chacha20_poly1305_encrypt(
                key.as_ref().as_ptr(),
                key.data_size as usize,
                iv.as_ref().as_ptr(),
                iv.data_size as usize,
                aad.as_ptr(),
                aad.len(),
                plain_text.as_ptr(),
                plain_text.len(),
                tag.as_mut_ptr(),
                tag.len(),
                cipher_text.as_mut_ptr(),
                &mut cipher_text_len as *mut usize,
            );
            Ok((cipher_text_len, tag.len()))
        },
        _ => Err(SPDM_STATUS_INVALID_PARAMETER),
    }
}

fn decrypt(
    aead_algo: SpdmAeadAlgo,
    key: &SpdmAeadKeyStruct,
    iv: &SpdmAeadIvStruct,
    aad: &[u8],
    cipher_text: &[u8],
    tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    match aead_algo {
        SpdmAeadAlgo::AES_128_GCM | SpdmAeadAlgo::AES_256_GCM => unsafe {
            let mut plain_text_len: usize = plain_text.len();
            spdm_aead_aes_gcm_decrypt(
                key.as_ref().as_ptr(),
                key.data_size as usize,
                iv.as_ref().as_ptr(),
                iv.data_size as usize,
                aad.as_ptr(),
                aad.len(),
                cipher_text.as_ptr(),
                cipher_text.len(),
                tag.as_ptr(),
                tag.len(),
                plain_text.as_mut_ptr(),
                &mut plain_text_len as *mut usize,
            );
            Ok(plain_text_len)
        },
        SpdmAeadAlgo::CHACHA20_POLY1305 => {
            let mut plain_text_len: usize = plain_text.len();
            unsafe {
                spdm_aead_chacha20_poly1305_decrypt(
                    key.as_ref().as_ptr(),
                    key.data_size as usize,
                    iv.as_ref().as_ptr(),
                    iv.data_size as usize,
                    aad.as_ptr(),
                    aad.len(),
                    cipher_text.as_ptr(),
                    cipher_text.len(),
                    tag.as_ptr(),
                    tag.len(),
                    plain_text.as_mut_ptr(),
                    (&mut plain_text_len) as *mut usize,
                );
                Ok(plain_text_len)
            }
        }
        _ => Err(SPDM_STATUS_INVALID_PARAMETER),
    }
}

#[cfg(all(test,))]
mod tests {
    use spdmlib::protocol::{SPDM_MAX_AEAD_IV_SIZE, SPDM_MAX_AEAD_KEY_SIZE};

    use super::*;

    #[test]
    fn test_case0() {
        let aead_algo = SpdmAeadAlgo::AES_128_GCM;
        let key = &SpdmAeadKeyStruct {
            data_size: 16,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let aad = &[0u8; 16];
        let plain_text = &b"hello"[..];
        let tag = &mut [0u8; 16];
        let cipher_text = &mut [0u8; 16];

        let plain_text_out = &mut [0u8; 100][..];

        let _ = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).and_then(
            |(cipher_text_len, tag_len)| {
                let res = decrypt(
                    aead_algo,
                    key,
                    iv,
                    aad,
                    &cipher_text[0..cipher_text_len][..],
                    &tag[0..tag_len][..],
                    &mut plain_text_out[..],
                )
                .unwrap();
                assert_eq!(plain_text, &plain_text_out[0..res]);
                return Ok(());
            },
        );
    }
    #[test]
    fn test_case0_encrypt() {
        let aead_algo = SpdmAeadAlgo::AES_128_GCM;
        let key = &SpdmAeadKeyStruct {
            data_size: 16,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [0u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];

        let status = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case1_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &SpdmAeadKeyStruct {
            data_size: 32,
            data: Box::new([100u8; SPDM_MAX_AEAD_KEY_SIZE]),
        };
        let iv = &SpdmAeadIvStruct {
            data_size: 12,
            data: Box::new([100u8; SPDM_MAX_AEAD_IV_SIZE]),
        };
        let plain_text = &mut [100u8; 16];
        let tag = &mut [0u8; 16];

        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];

        let status = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).is_ok();
        assert!(status);
    }
}
