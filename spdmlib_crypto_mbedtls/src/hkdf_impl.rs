// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmHkdf;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_expand_cb: hkdf_expand,
};

use super::ffi::{mbedtls_hkdf_expand, mbedtls_md_info_from_type};
use core::ffi::c_int;
const MBEDTLS_MD_SHA256: c_int = 6;
const MBEDTLS_MD_SHA384: c_int = 7;
const MBEDTLS_MD_SHA512: c_int = 8;

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    pk: &[u8],
    info: &[u8],
    out_size: u16,
) -> Option<SpdmDigestStruct> {
    let algorithm = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(MBEDTLS_MD_SHA256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(MBEDTLS_MD_SHA384),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(MBEDTLS_MD_SHA512),
        _ => None,
    }?;
    let mut digest = SpdmDigestStruct::default();
    unsafe {
        let md_info = mbedtls_md_info_from_type(algorithm);
        if md_info.is_null() {
            return None;
        }
        let res = mbedtls_hkdf_expand(
            md_info,
            pk.as_ptr(),
            pk.len(),
            info.as_ptr(),
            info.len(),
            digest.data.as_mut_ptr(),
            out_size as usize,
        );
        if res != 0 {
            return None;
        }
        digest.data_size = out_size;
    }
    Some(digest)
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_hkdf_expand() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let pk = &mut [100u8; 64];
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, pk, info, out_size);

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
        let pk = &mut [100u8; 64];
        let info = &mut [100u8; 64];
        let out_size = 64;
        let hkdf_expand = hkdf_expand(base_hash_algo, pk, info, out_size);

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
