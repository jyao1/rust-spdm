// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto::SpdmHkdf;
use crate::msgs::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static DEFAULT: SpdmHkdf = SpdmHkdf {
    hkdf_expand_cb: hkdf_expand,
};

fn hkdf_expand(
    hash_algo: SpdmBaseHashAlgo,
    pk: &[u8],
    info: &[u8],
    out_size: u16,
) -> Option<SpdmDigestStruct> {
    let algo = match hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => Some(ring::hkdf::HKDF_SHA256),
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => Some(ring::hkdf::HKDF_SHA384),
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => Some(ring::hkdf::HKDF_SHA512),
        _ => None,
    }?;
    let pkr = ring::hkdf::Prk::new_less_safe(algo, pk);

    let mut ret = SpdmDigestStruct::default();
    let res = pkr
        .expand(&[info], SpdmCryptoHkdfKeyLen::new(out_size))
        .and_then(|okm| {
            let len = out_size as u16;
            ret.data_size = len;
            okm.fill(&mut ret.data[..len as usize])
        });
    match res {
        Ok(_) => Some(ret),
        Err(_) => None,
    }
}

struct SpdmCryptoHkdfKeyLen {
    out_size: usize,
}
impl SpdmCryptoHkdfKeyLen {
    pub fn new(len: u16) -> Self {
        SpdmCryptoHkdfKeyLen {
            out_size: len as usize,
        }
    }
}

impl ring::hkdf::KeyType for SpdmCryptoHkdfKeyLen {
    fn len(&self) -> usize {
        self.out_size
    }
}

#[cfg(test)]
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
