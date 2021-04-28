// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;

extern crate alloc;
use alloc::boxed::Box;

use crate::msgs::{
    SpdmAeadAlgo, SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmDheAlgo, SpdmDheExchangeStruct,
    SpdmDheFinalKeyStruct, SpdmDigestStruct, SpdmSignatureStruct,
};

#[derive(Clone, Copy)]
pub struct SpdmHash {
    pub hash_all_cb: fn(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct>,
}

#[derive(Clone, Copy)]
pub struct SpdmHmac {
    pub hmac_cb:
        fn(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct>,

    pub hmac_verify_cb: fn(
        base_hash_algo: SpdmBaseHashAlgo,
        key: &[u8],
        data: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult,
}

type EncryptCb = fn(
    aead_algo: SpdmAeadAlgo,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plain_text: &[u8],
    tag: &mut [u8],
    cipher_text: &mut [u8],
) -> SpdmResult<(usize, usize)>;

type DecryptCb = fn(
    aead_algo: SpdmAeadAlgo,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    cipher_text: &[u8],
    tag: &[u8],
    plain_text: &mut [u8],
) -> SpdmResult<usize>;

#[derive(Clone, Copy)]
pub struct SpdmAead {
    pub encrypt_cb: EncryptCb,

    pub decrypt_cb: DecryptCb,
}

#[derive(Clone, Copy)]
pub struct SpdmAsymSign {
    pub sign_cb: fn(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct>,
}

#[derive(Clone, Copy)]
pub struct SpdmAsymVerify {
    pub verify_cb: fn(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        public_cert_der: &[u8],
        data: &[u8],
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult,
}

#[derive(Clone, Copy)]
pub struct SpdmHkdf {
    pub hkdf_expand_cb: fn(
        hash_algo: SpdmBaseHashAlgo,
        pk: &[u8],
        info: &[u8],
        out_size: u16,
    ) -> Option<SpdmDigestStruct>,
}

type GetCertFromCertChainCb = fn(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)>;

#[derive(Clone, Copy)]
pub struct SpdmCertOperation {
    pub get_cert_from_cert_chain_cb: GetCertFromCertChainCb,

    pub verify_cert_chain_cb: fn(cert_chain: &[u8]) -> SpdmResult,
}

type GenerateKeyPairCb =
    fn(dhe_algo: SpdmDheAlgo) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange>)>;

#[derive(Clone, Copy)]
pub struct SpdmDhe {
    pub generate_key_pair_cb: GenerateKeyPairCb,
}

pub trait SpdmDheKeyExchange {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct>;
}
