// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::crypto::{SpdmAead, SpdmAsymVerify, SpdmHkdf, SpdmHmac};
use spdmlib::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use spdmlib::protocol::*;

pub static FAKE_HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: fake_hmac,
    hmac_verify_cb: fake_hmac_verify,
};

pub static FAKE_AEAD: SpdmAead = SpdmAead {
    encrypt_cb: fake_encrypt,
    decrypt_cb: fake_decrypt,
};

pub static FAKE_RAND: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

pub static FAKE_ASYM_VERIFY: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: fake_asym_verify,
};

pub static FAKE_HKDF: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: fake_hkdf_extract,
    hkdf_expand_cb: fake_hkdf_expand,
};

fn fake_hmac(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
) -> Option<SpdmDigestStruct> {
    let tag = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([10u8; SPDM_MAX_HASH_SIZE]),
    };
    Some(tag)
}

fn fake_hmac_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let SpdmDigestStruct { data_size, .. } = hmac;
    match data_size {
        48 => Ok(()),
        _ => Err(SPDM_STATUS_VERIF_FAIL),
    }
}

fn fake_encrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("cipher_text len invalid");
    }
    cipher_text.copy_from_slice(plain_text);
    Ok((plain_text_size, tag.len()))
}

fn fake_decrypt(
    _aead_algo: SpdmAeadAlgo,
    _key: &[u8],
    _iv: &[u8],
    _aad: &[u8],
    cipher_text: &[u8],
    _tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize> {
    let plain_text_size = plain_text.len();
    let cipher_text_size = cipher_text.len();
    if cipher_text_size != plain_text_size {
        panic!("plain_text len invalid");
    }
    plain_text.copy_from_slice(cipher_text);
    Ok(cipher_text_size)
}

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    #[allow(clippy::needless_range_loop)]
    for i in 0..data.len() {
        data[i] = 0xff;
    }

    Ok(data.len())
}

fn fake_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _base_asym_algo: SpdmBaseAsymAlgo,
    _public_cert_der: &[u8],
    _data: &[u8],
    _signature: &SpdmSignatureStruct,
) -> SpdmResult {
    Ok(())
}

fn fake_hkdf_extract(
    _hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &[u8],
) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::default())
}

fn fake_hkdf_expand(
    _hash_algo: SpdmBaseHashAlgo,
    _pk: &[u8],
    _info: &[u8],
    _out_size: u16,
) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::default())
}
