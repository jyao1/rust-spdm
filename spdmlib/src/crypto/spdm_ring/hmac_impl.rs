// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::algo::{SpdmBaseHashAlgo, SpdmDigestStruct};
use crate::common::error::SpdmResult;
use crate::crypto::SpdmHmac;

pub static DEFAULT: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(base_hash_algo: SpdmBaseHashAlgo, key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => ring::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => ring::hmac::HMAC_SHA512,
        _ => {
            panic!();
        }
    };

    let s_key = ring::hmac::Key::new(algorithm, key);
    let tag = ring::hmac::sign(&s_key, data);
    let tag = tag.as_ref();
    Some(SpdmDigestStruct::from(tag))
}

fn hmac_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => ring::hmac::HMAC_SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => ring::hmac::HMAC_SHA512,
        _ => {
            panic!();
        }
    };

    let v_key = ring::hmac::Key::new(algorithm, key);
    match ring::hmac::verify(&v_key, data, &hmac.data[..(hmac.data_size as usize)]) {
        Ok(()) => Ok(()),
        Err(_) => spdm_result_err!(EFAULT),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let key = &mut [100u8; 64];
        let data = &mut [100u8; 64];
        let spdm_digest = hmac(base_hash_algo, key, data).unwrap();
        let spdm_digest_struct = hmac_verify(base_hash_algo, key, data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
    #[test]
    fn test_case1_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let key = &mut [10u8; 128];
        let data = &mut [10u8; 128];
        let spdm_digest = hmac(base_hash_algo, key, data).unwrap();
        let spdm_digest_struct = hmac_verify(base_hash_algo, key, data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
    #[test]
    #[should_panic]
    fn test_case2_hmac_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let key = &mut [10u8; 128];
        let data = &mut [10u8; 128];
        let spdm_digest = hmac(base_hash_algo, key, data).unwrap();
        let data = &mut [100u8; 128];
        let spdm_digest_struct = hmac_verify(base_hash_algo, key, data, &spdm_digest);

        match spdm_digest_struct {
            Ok(()) => {
                assert!(true)
            }
            _ => {
                panic!()
            }
        }
    }
}
