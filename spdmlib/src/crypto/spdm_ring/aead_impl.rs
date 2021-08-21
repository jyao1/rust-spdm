// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto::SpdmAead;
use crate::error::SpdmResult;
use bytes::BytesMut;

use crate::msgs::SpdmAeadAlgo;

pub static DEFAULT: SpdmAead = SpdmAead {
    encrypt_cb: encrypt,
    decrypt_cb: decrypt,
};

fn encrypt(
    aead_algo: SpdmAeadAlgo,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    let algorithm = match aead_algo {
        SpdmAeadAlgo::AES_128_GCM => &ring::aead::AES_128_GCM,
        SpdmAeadAlgo::AES_256_GCM => &ring::aead::AES_256_GCM,
        SpdmAeadAlgo::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305,
        _ => {
            panic!();
        }
    };

    if key.len() != aead_algo.get_key_size() as usize {
        panic!("key len invalid");
    }
    if iv.len() != aead_algo.get_iv_size() as usize {
        panic!("iv len invalid");
    }
    let tag_size = tag.len();
    if tag_size != aead_algo.get_tag_size() as usize {
        panic!("tag len invalid");
    }
    let plain_text_size = plain_text.len();

    if cipher_text.len() != plain_text_size as usize {
        panic!("cipher_text len invalid");
    }

    //debug!("encryption:\n");
    //debug!("key - {:02x?}\n", key);
    //debug!("iv - {:02x?}\n", iv);
    //debug!("aad - {:02x?}\n", aad);
    //debug!("plain_text - {:02x?}\n", plain_text);

    let mut d = [0u8; ring::aead::NONCE_LEN];
    d.copy_from_slice(&iv[..ring::aead::NONCE_LEN]);
    let nonce = ring::aead::Nonce::assume_unique_for_key(d);

    let mut in_out = BytesMut::new();
    in_out.extend_from_slice(plain_text);

    let mut s_key: ring::aead::SealingKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    match s_key.seal_in_place_append_tag(ring::aead::Aad::from(aad), &mut in_out) {
        Ok(()) => {
            cipher_text.copy_from_slice(&in_out[..plain_text_size]);
            tag.copy_from_slice(&in_out[plain_text_size..(plain_text_size + tag_size)]);
            //debug!("tag - {:02x?}\n", tag);
            //debug!("cipher_text - {:02x?}\n", cipher_text);
            Ok((plain_text_size, tag_size))
        }
        Err(_) => spdm_result_err!(EFAULT),
    }
}

fn decrypt(
    aead_algo: SpdmAeadAlgo,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    cipher_text: &[u8],
    tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    let algorithm = match aead_algo {
        SpdmAeadAlgo::AES_128_GCM => &ring::aead::AES_128_GCM,
        SpdmAeadAlgo::AES_256_GCM => &ring::aead::AES_256_GCM,
        SpdmAeadAlgo::CHACHA20_POLY1305 => &ring::aead::CHACHA20_POLY1305,
        _ => {
            panic!();
        }
    };

    if key.len() != aead_algo.get_key_size() as usize {
        panic!("key len invalid");
    }
    if iv.len() != aead_algo.get_iv_size() as usize {
        panic!("iv len invalid");
    }
    let tag_size = tag.len();
    if tag_size != aead_algo.get_tag_size() as usize {
        panic!("tag len invalid");
    }
    let cipher_text_size = cipher_text.len();

    if plain_text.len() != cipher_text_size as usize {
        panic!("plain_text len invalid");
    }

    //debug!("decryption:\n");
    //debug!("key - {:02x?}\n", key);
    //debug!("iv - {:02x?}\n", iv);
    //debug!("aad - {:02x?}\n", aad);
    //debug!("tag - {:02x?}\n", tag);
    //debug!("cipher_text - {:02x?}\n", cipher_text);

    let mut d = [0u8; ring::aead::NONCE_LEN];
    d.copy_from_slice(&iv[..ring::aead::NONCE_LEN]);
    let nonce = ring::aead::Nonce::assume_unique_for_key(d);

    let mut in_out = BytesMut::new();
    in_out.extend_from_slice(cipher_text);
    in_out.extend_from_slice(tag);

    let mut o_key: ring::aead::OpeningKey<OneNonceSequence> = make_key(algorithm, key, nonce);
    match o_key.open_in_place(ring::aead::Aad::from(aad), &mut in_out) {
        Ok(in_out_result) => {
            plain_text.copy_from_slice(&in_out_result[..cipher_text_size]);
            //info!("plain_text - {:02x?}\n", plain_text);
            Ok(cipher_text_size)
        }
        Err(_) => spdm_result_err!(EFAULT),
    }
}

struct OneNonceSequence(Option<ring::aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: ring::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

fn make_key<K: ring::aead::BoundKey<OneNonceSequence>>(
    algorithm: &'static ring::aead::Algorithm,
    key: &[u8],
    nonce: ring::aead::Nonce,
) -> K {
    let key = ring::aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = OneNonceSequence::new(nonce);
    K::new(key, nonce_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgs::*;

    #[test]
    fn test_case0_encrypt() {
        let aead_algo = SpdmAeadAlgo::AES_128_GCM;
        let key = &mut [100u8; 16];
        let iv = &mut [100u8; 12];
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
        let key = &mut [100u8; 32];
        let iv = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [0u8; 16];

        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        
        let status = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text).is_ok();
        assert!(status);
    }
    #[test]
    #[should_panic]
    fn test_case2_encrypt() {
        let aead_algo = SpdmAeadAlgo::empty();
        let key = &mut [100u8; 1];
        let iv = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case3_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &mut [100u8; 1];
        let iv = &mut [100u8; 32];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case4_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &mut [100u8; 32];
        let iv = &mut [100u8; 1];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 32];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 16];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case5_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &mut [100u8; 32];
        let iv = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 1];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case6_encrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &mut [100u8; 32];
        let iv = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];
        let tag = &mut [100u8; 32];
        let aad = &mut [100u8; 16];
        let cipher_text = &mut [100u8; 1];
        let ret_tag_size = encrypt(aead_algo, key, iv, aad, plain_text, tag, cipher_text);
        println!("ret_tag_size{:?}", ret_tag_size);
    }
    #[test]
    #[should_panic]
    fn test_case0_decrypt() {
        let aead_algo = SpdmAeadAlgo::CHACHA20_POLY1305;
        let key = &mut [100u8; 32];
        let iv = &mut [100u8; 12];
        let cipher_text = &mut [100u8; 16];
        let tag = &mut [100u8; 16];
        let aad = &mut [100u8; 12];
        let plain_text = &mut [100u8; 16];

        let ret_tag_size = decrypt(aead_algo, key, iv, aad, cipher_text, tag, plain_text);

        match ret_tag_size {
            Ok(16) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
}
