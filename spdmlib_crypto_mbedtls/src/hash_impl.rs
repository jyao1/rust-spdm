// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmHash;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

#[cfg(feature = "hashed-transcript-data")]
mod hash_ext {
    extern crate alloc;
    use super::*;
    use crate::ffi_ext::*;
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use lazy_static::lazy_static;
    use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
    use spin::Mutex;
    pub type HashCtxConcrete = MbedtlsMdContextT;
    lazy_static! {
        static ref HASH_CTX_TABLE: Mutex<BTreeMap<usize, Box<HashCtxConcrete>>> =
            Mutex::new(BTreeMap::new());
    }

    pub static DEFAULT: SpdmHash = SpdmHash {
        hash_all_cb: hash_all,
        hash_ctx_init_cb: hash_ctx_init,
        hash_ctx_update_cb: hash_ctx_update,
        hash_ctx_finalize_cb: hash_ctx_finalize,
        hash_ctx_dup_cb: hash_ctx_dup,
    };

    pub(crate) fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<usize> {
        let md_type = match base_hash_algo {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => MBEDTLS_MD_SHA256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => MBEDTLS_MD_SHA384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => MBEDTLS_MD_SHA512,
            _ => return None,
        };
        let mut ctx = MbedtlsMdContextT::init();
        if !ctx.setup(md_type) {
            return None;
        }
        let ctx = Box::new(ctx);
        Some(insert_to_table(ctx))
    }

    pub(crate) fn hash_ctx_update(handle: usize, data: &[u8]) -> SpdmResult {
        let mut table = HASH_CTX_TABLE.lock();
        let ctx = table.get_mut(&handle).ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        if !ctx.update(data) {
            Err(SPDM_STATUS_CRYPTO_ERROR)
        } else {
            Ok(())
        }
    }

    pub(crate) fn hash_ctx_finalize(handle: usize) -> Option<SpdmDigestStruct> {
        let mut ctx = HASH_CTX_TABLE.lock().remove(&handle)?;
        let mut digest = SpdmDigestStruct::default();
        let digest_len = ctx.finish(digest.data.as_mut_slice())?;
        if digest_len > u16::MAX as usize {
            return None;
        }
        digest.data_size = digest_len as u16;
        Some(digest)
    }

    pub(crate) fn hash_ctx_dup(handle: usize) -> Option<usize> {
        let ctx_new = {
            let table = HASH_CTX_TABLE.lock();
            let ctx = table.get(&handle)?;
            ctx.dup()?
        };
        let ctx = Box::new(ctx_new);
        Some(insert_to_table(ctx))
    }

    pub(crate) fn insert_to_table(value: Box<HashCtxConcrete>) -> usize {
        let handle_ptr: *const HashCtxConcrete = &*value;
        let handle = handle_ptr as usize;
        HASH_CTX_TABLE.lock().insert(handle, value);
        handle
    }

    #[allow(dead_code)]
    #[cfg(test)]
    pub fn get_hash_ctx_count() -> usize {
        HASH_CTX_TABLE.lock().len()
    }
}
#[cfg(feature = "hashed-transcript-data")]
pub use hash_ext::DEFAULT;

#[cfg(not(feature = "hashed-transcript-data"))]
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
