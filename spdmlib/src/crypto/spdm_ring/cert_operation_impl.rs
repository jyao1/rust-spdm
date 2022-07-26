// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;
use alloc::vec;
use core::convert::TryFrom;

use crate::common::error::SpdmResult;
use crate::crypto::SpdmCertOperation;

pub static DEFAULT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain,
    verify_cert_chain_cb: verify_cert_chain,
};

fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {
    let mut offset = 0usize;
    let mut this_index = 0isize;
    loop {
        if cert_chain[offset..].len() < 4 || offset > cert_chain.len() {
            return spdm_result_err!(EINVAL);
        }
        if cert_chain[offset] != 0x30 || cert_chain[offset + 1] != 0x82 {
            return spdm_result_err!(EINVAL);
        }
        let this_cert_len =
            ((cert_chain[offset + 2] as usize) << 8) + (cert_chain[offset + 3] as usize) + 4;
        //debug!("this_cert_len - 0x{:04x?}\n", this_cert_len);
        if this_index == index {
            // return the this one
            return Ok((offset, offset + this_cert_len));
        }
        this_index += 1;
        if (offset + this_cert_len == cert_chain.len()) && (index == -1) {
            // return the last one
            return Ok((offset, offset + this_cert_len));
        }
        offset += this_cert_len;
    }
}

fn verify_cert_chain(cert_chain: &[u8]) -> SpdmResult {
    // TBD
    static EKU_SPDM_RESPONDER_AUTH: &[u8] = &[40 + 3, 6, 1, 5, 5, 7, 3, 1];

    static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
        &webpki::RSA_PKCS1_2048_8192_SHA256,
        &webpki::RSA_PKCS1_2048_8192_SHA384,
        &webpki::RSA_PKCS1_2048_8192_SHA512,
        &webpki::ECDSA_P256_SHA256,
        &webpki::ECDSA_P256_SHA384,
        &webpki::ECDSA_P384_SHA256,
        &webpki::ECDSA_P384_SHA384,
    ];

    let (ca_begin, ca_end) = get_cert_from_cert_chain(cert_chain, 0)?;
    let ca = &cert_chain[ca_begin..ca_end];
    // TBD: assume only one inter cert here.
    let (inter_begin, inter_end) = get_cert_from_cert_chain(cert_chain, 1)?;
    let inter = &cert_chain[inter_begin..inter_end];
    let (ee_begin, ee_end) = get_cert_from_cert_chain(cert_chain, -1)?;
    let ee = &cert_chain[ee_begin..ee_end];

    let anchors = if let Ok(ta) = webpki::TrustAnchor::try_from_cert_der(ca) {
        vec![ta]
    } else {
        return spdm_result_err!(ESEC);
    };

    #[cfg(any(target_os = "uefi", target_os = "none"))]
    let timestamp = uefi_time::get_rtc_time() as u64;
    #[cfg(not(any(target_os = "uefi", target_os = "none")))]
    let timestamp = {
        extern crate std;
        if let Ok(ds) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            ds.as_secs()
        } else {
            return spdm_result_err!(EDEV);
        }
    };
    let time = webpki::Time::from_seconds_since_unix_epoch(timestamp);

    let cert = if let Ok(eec) = webpki::EndEntityCert::try_from(ee) {
        eec
    } else {
        return spdm_result_err!(ESEC);
    };

    // we cannot call verify_is_valid_tls_server_cert because it will check verify_cert::EKU_SERVER_AUTH.
    if cert
        .verify_cert_chain_with_eku(
            EKU_SPDM_RESPONDER_AUTH,
            ALL_SIGALGS,
            &anchors,
            &[inter],
            time,
            0,
        )
        .is_ok()
    {
        info!("Cert verification Pass\n");
        Ok(())
    } else {
        error!("Cert verification Fail\n");
        spdm_result_err!(EFAULT)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);
    }

    #[test]
    fn test_case1_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let status = get_cert_from_cert_chain(cert_chain, 0).is_ok();
        assert!(status);
    }
    #[test]
    fn test_case2_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
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
        let cert_chain = &mut cert_chain_array();
        let status = get_cert_from_cert_chain(cert_chain, -1).is_ok();
        assert!(status);

        let status = verify_cert_chain(cert_chain).is_ok();
        assert!(status);
    }
}
