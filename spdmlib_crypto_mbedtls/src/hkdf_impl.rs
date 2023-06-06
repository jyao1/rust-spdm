// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmHkdf;
use spdmlib::protocol::{
    SpdmBaseHashAlgo, SpdmHkdfInputKeyingMaterial, SpdmHkdfOutputKeyingMaterial,
    SpdmHkdfPseudoRandomKey,
};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: hkdf_extract,
    hkdf_expand_cb: hkdf_expand,
};

use super::ffi::{
    mbedtls_hkdf_expand, mbedtls_md_get_size, mbedtls_md_hmac, mbedtls_md_info_from_type,
};
use core::ffi::c_int;
const MBEDTLS_MD_SHA256: c_int = 6;
const MBEDTLS_MD_SHA384: c_int = 7;
const MBEDTLS_MD_SHA512: c_int = 8;

fn hkdf_extract(
    hash_algo: SpdmBaseHashAlgo,
    salt: &[u8],
    ikm: &SpdmHkdfInputKeyingMaterial,
) -> Option<SpdmHkdfPseudoRandomKey> {
    let algorithm = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => MBEDTLS_MD_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => MBEDTLS_MD_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => MBEDTLS_MD_SHA512,
        _ => {
            panic!();
        }
    };

    let mut prk = SpdmHkdfPseudoRandomKey::default();
    unsafe {
        let md_info = mbedtls_md_info_from_type(algorithm);
        if md_info.is_null() {
            return None;
        }
        let olen = mbedtls_md_get_size(md_info) as usize;
        let ret = mbedtls_md_hmac(
            md_info,
            salt.as_ptr(),
            salt.len(),
            ikm.as_ref().as_ptr(),
            ikm.get_data_size() as usize,
            prk.data.as_mut_ptr(),
        );
        if ret != 0 {
            return None;
        }
        prk.data_size = olen as u16;
    }
    Some(prk)
}

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    prk: &SpdmHkdfPseudoRandomKey,
    info: &[u8],
    out_size: u16,
) -> Option<SpdmHkdfOutputKeyingMaterial> {
    let algorithm = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(MBEDTLS_MD_SHA256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(MBEDTLS_MD_SHA384),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(MBEDTLS_MD_SHA512),
        _ => None,
    }?;
    let mut okm = SpdmHkdfOutputKeyingMaterial::default();
    unsafe {
        let md_info = mbedtls_md_info_from_type(algorithm);
        if md_info.is_null() {
            return None;
        }
        let res = mbedtls_hkdf_expand(
            md_info,
            prk.as_ref().as_ptr(),
            prk.data_size as usize,
            info.as_ptr(),
            info.len(),
            okm.data.as_mut_ptr(),
            out_size as usize,
        );
        if res != 0 {
            return None;
        }
        okm.data_size = out_size;
    }
    Some(okm)
}

#[cfg(all(test,))]
mod tests {
    use spdmlib::protocol::SPDM_MAX_HASH_SIZE;

    use super::*;

    #[test]
    fn test_case0_hkdf_expand() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let prk = &SpdmDigestStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(
            base_hash_algo,
            &SpdmHkdfInputKeyingMaterial::SpdmDigest(prk),
            info,
            out_size,
        );

        match hkdf_expand {
            Some(_) => {
                assert!(true)
            }
            None => {
                assert!(false)
            }
        }
    }
    #[test]
    #[should_panic]
    fn test_case1_hkdf_expand() {
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let prk = &SpdmDigestStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(
            base_hash_algo,
            &SpdmHkdfInputKeyingMaterial::SpdmDigest(prk),
            info,
            out_size,
        );

        match hkdf_expand {
            Some(_) => {
                assert!(true)
            }
            None => {
                assert!(false)
            }
        }
    }
}
