// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;

use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::{SpdmResult, SPDM_STATUS_INVALID_CERT};

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain,
    verify_cert_chain_cb: verify_cert_chain,
};

use crate::ffi::spdm_verify_cert_chain;

fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    let mut offset = 0usize;
    let mut this_index = 0isize;
    let cert_chain_size = cert_chain.len();
    loop {
        if cert_chain[offset..].len() < 4 || offset > cert_chain.len() {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if cert_chain[offset] != 0x30 || cert_chain[offset + 1] != 0x82 {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        let this_cert_len =
            ((cert_chain[offset + 2] as usize) << 8) + (cert_chain[offset + 3] as usize) + 4;
        if this_cert_len > cert_chain_size - offset {
            return Err(SPDM_STATUS_INVALID_CERT);
        }
        if this_index == index {
            // return the this one
            return Ok((offset, offset + this_cert_len));
        }
        this_index += 1;
        if (offset + this_cert_len == cert_chain_size) && (index == -1) {
            // return the last one
            return Ok((offset, offset + this_cert_len));
        }
        offset += this_cert_len;
    }
}

fn verify_cert_chain(cert_chain: &[u8]) -> SpdmResult {
    let ret = unsafe { spdm_verify_cert_chain(cert_chain.as_ptr(), cert_chain.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(SPDM_STATUS_INVALID_CERT)
    }
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);
    }

    #[test]
    fn test_case1_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, 0).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case2_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, 1).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case3_cert_from_cert_chain() {
        let cert_chain = &mut [0x1u8; 4096];
        cert_chain[0] = 0x00;
        cert_chain[1] = 0x00;
        let status = get_cert_from_cert_chain(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case4_cert_from_cert_chain() {
        let cert_chain = &mut [0x11u8; 3];
        let status = get_cert_from_cert_chain(cert_chain, 0).is_err();
        assert!(status);
    }
    #[test]
    fn test_case5_cert_from_cert_chain() {
        let cert_chain = &include_bytes!("public_cert.der")[..];
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);

        let status = verify_cert_chain(cert_chain).is_ok();
        assert!(status);
    }
}
