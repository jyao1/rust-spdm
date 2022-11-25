// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto::SpdmHash;
use crate::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub type HashCtx = ring::digest::Context;

pub static DEFAULT: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
    hash_ctx_init_cb: hash_ctx_init,
    hash_ctx_update_cb: hash_ctx_update,
    hash_ctx_finalize_cb: hash_ctx_finalize,
};

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
        _ => return None,
    };
    let digest_value = ring::digest::digest(algorithm, data);
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
}

fn hash_ctx_init(base_hash_algo: SpdmBaseHashAlgo) -> Option<HashCtx> {
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
        _ => return None,
    };
    Some(HashCtx::new(algorithm))
}

fn hash_ctx_update(ctx: &mut HashCtx, data: &[u8]) {
    ctx.update(data)
}

fn hash_ctx_finalize(ctx: HashCtx) -> Option<SpdmDigestStruct> {
    let digest_value = ctx.finish();
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
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
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let data = &mut [0u8; 32];

        let hash_all = hash_all(base_hash_algo, data).unwrap();
        assert_eq!(hash_all.data_size, 32);
    }
    #[test]
    fn test_case2_hash_all() {
        let base_hash_algo = SpdmBaseHashAlgo::empty();
        let data = &mut [0u8; 64];

        let hash_all = hash_all(base_hash_algo, data);
        assert_eq!(hash_all.is_none(), true);
    }
    #[test]
    fn test_case0_hash_update() {
        let helloworld = ring::digest::digest(&ring::digest::SHA384, b"hello, world");
        let hellobuddy = ring::digest::digest(&ring::digest::SHA384, b"hello, buddy");
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA384);
        ctx.update(b"hello");
        ctx.update(b", ");
        let mut ctx_d = ctx.clone();
        ctx_d.update(b"buddy");
        ctx.update(b"world");
        let multi_part_helloworld = ctx.finish();
        let multi_part_hellobuddy = ctx_d.clone().finish();
        let multi_part_hellobuddy_twice = ctx_d.finish();
        assert_eq!(&helloworld.as_ref(), &multi_part_helloworld.as_ref());
        assert_eq!(&hellobuddy.as_ref(), &multi_part_hellobuddy.as_ref());
        assert_eq!(&hellobuddy.as_ref(), &multi_part_hellobuddy_twice.as_ref());
    }
}
