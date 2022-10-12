// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmHash;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
};

use super::ffi::{mbedtls_sha256, mbedtls_sha512};
use core::ffi::c_uchar;

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    let d = data.as_ptr() as *const c_uchar;
    let mut spdm_digest = SpdmDigestStruct::default();
    match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => unsafe {
            let res = mbedtls_sha256(d, data.len(), spdm_digest.data.as_mut_ptr(), 0);
            if res != 0 {
                return None;
            } else {
                spdm_digest.data_size = 32;
            }
        },
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => unsafe {
            let res = mbedtls_sha512(d, data.len(), spdm_digest.data.as_mut_ptr(), 1);
            if res != 0 {
                return None;
            } else {
                spdm_digest.data_size = 48;
            }
        },
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => unsafe {
            let res = mbedtls_sha512(d, data.len(), spdm_digest.data.as_mut_ptr(), 0);
            if res != 0 {
                return None;
            } else {
                spdm_digest.data_size = 64;
            }
        },
        _ => return None,
    };
    Some(spdm_digest)
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let data = &mut [0u8; 64];

        let hash_all = hash_all(base_hash_algo, data).unwrap();
        assert_eq!(hash_all.data_size, 64);
    }
    #[test]
    fn test_case1_hash_all() {
        use std::fmt::Write;
        use std::string::String;
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let data = &b"hello"[..];

        let mut res = String::new();
        let hash_all = hash_all(base_hash_algo, data).unwrap();
        for d in hash_all.as_ref() {
            let _ = write!(&mut res, "{:02x}", d);
        }
        println!("res: {}", String::from_utf8_lossy(res.as_ref()));
        assert_eq!(hash_all.data_size, 32);

        assert_eq!(
            res,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string()
        )
    }
    #[test]
    fn test_case2_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let data = &mut [0u8; 64];

        let hash_all = hash_all(base_hash_algo, data);
        assert_eq!(hash_all.is_none(), true);
    }
}
