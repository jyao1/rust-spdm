// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmHmac;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};
use core::ffi::c_int;

const MBEDTLS_MD_SHA256: c_int = 6;
const MBEDTLS_MD_SHA384: c_int = 7;
const MBEDTLS_MD_SHA512: c_int = 8;

use super::ffi::{mbedtls_md_get_size, mbedtls_md_hmac, mbedtls_md_info_from_type};

fn hmac(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => MBEDTLS_MD_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => MBEDTLS_MD_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => MBEDTLS_MD_SHA512,
        _ => {
            panic!();
        }
    };

    let mut digest = SpdmDigestStruct::default();
    unsafe {
        let md_info = mbedtls_md_info_from_type(algorithm);
        if md_info.is_null() {
            return None;
        }
        let olen = mbedtls_md_get_size(md_info) as usize;
        let ret = mbedtls_md_hmac(
            md_info,
            key.as_ptr(),
            key.len(),
            data.as_ptr(),
            data.len(),
            digest.data.as_mut_ptr(),
        );
        if ret != 0 {
            return None;
        }
        digest.data_size = olen as u16;
    }
    Some(digest)
}

fn hmac_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
    message_digest: &SpdmDigestStruct,
) -> SpdmResult {
    let digest = hmac(base_hash_algo, key, data).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
    if digest.as_ref() == message_digest.as_ref() {
        Ok(())
    } else {
        Err(SPDM_STATUS_CRYPTO_ERROR)
    }
}

#[cfg(all(test,))]
mod tests {
    use spdmlib::protocol::SPDM_MAX_HASH_SIZE;

    use super::*;
    #[test]
    fn test_case_rfc4231_2() {
        let key = &mut SpdmFinishedKeyStruct {
            data_size: 4,
            data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
        };
        key.data[0..4].copy_from_slice(&[0x4a, 0x65, 0x66, 0x65]);
        let data: &[u8] = &[
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ][..];
        let hmac_256: &[u8] = &[
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ][..];
        let hmac_512: &[u8] = &[
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
            0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
            0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03,
            0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
            0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
        ][..];

        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_digest = hmac(base_hash_algo, key, data).unwrap();
        assert_eq!(spdm_digest.as_ref(), hmac_512);

        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let spdm_digest = hmac(base_hash_algo, key, data).unwrap();
        assert_eq!(spdm_digest.as_ref(), hmac_256);

        let digest = SpdmDigestStruct::from(hmac_256);
        hmac_verify(base_hash_algo, key, data, &digest).unwrap();
    }
}
