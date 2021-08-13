// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::SpdmCertOperation;
use crate::error::SpdmResult;

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
    static EKU_SPDM_RESPONDER_AUTH: webpki::verify_cert::KeyPurposeId =
        webpki::verify_cert::KeyPurposeId {
            oid_value: untrusted::Input::from(&[40 + 3, 6, 1, 5, 5, 7, 3, 1]), // TBD
        };

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

    let mut anchors = Vec::new();
    anchors.push(webpki::TrustAnchor::from_cert_der(ca).unwrap());

    #[cfg(target_os = "uefi")]
    let time = webpki::Time::from_seconds_since_unix_epoch(uefi_time::get_rtc_time() as u64);
    #[cfg(feature = "std")]
    use std::convert::TryFrom;
    #[cfg(feature = "std")]
    let time = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();

    let cert = webpki::cert::parse_cert(
        untrusted::Input::from(ee),
        webpki::cert::EndEntityOrCA::EndEntity,
    )
    .unwrap();

    // we cannot call verify_is_valid_tls_server_cert because it will check verify_cert::EKU_SERVER_AUTH.
    if webpki::verify_cert::build_chain(
        EKU_SPDM_RESPONDER_AUTH,
        ALL_SIGALGS,
        &anchors,
        &[inter],
        &cert,
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
    use crate::testlib::*;
    use super::*;

    #[test]
    fn test_case0_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, -1);

        match get_cert_from_cert_chain {
            Ok((942, 0x5d4)) => {
                println!("Cert verification");
            }
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_case1_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, 0);

        match get_cert_from_cert_chain {
            Ok((0, 0x1d3)) => {
                println!("Cert verification");
            }
            _ => {
                assert!(false);
            }
        }
    }
    #[test]
    fn test_case2_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, 1);

        match get_cert_from_cert_chain {
            Ok((467, 0x3ae)) => {
                println!("Cert verification");
            }
            _ => {
                assert!(false);
            }
        }
    }
    #[test]
    fn test_case3_cert_from_cert_chain() {
        let cert_chain = &mut [0x1u8; 4096];

        cert_chain[0] = 0x00;
        cert_chain[1] = 0x00;
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, 0);

        match get_cert_from_cert_chain {
            Ok((0, 0)) => {
                assert!(false);
            }
            _ => {
                assert!(true);
            }
        }
    }
    #[test]
    fn test_case4_cert_from_cert_chain() {
        let cert_chain = &mut [0x11u8; 3];
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, 0);

        match get_cert_from_cert_chain {
            Ok((0, 0)) => {
                assert!(false);
            }
            _ => {
                assert!(true);
            }
        }
    }
    #[test]
    fn test_case5_cert_from_cert_chain() {
        let cert_chain = &mut cert_chain_array();
        let get_cert_from_cert_chain = get_cert_from_cert_chain(cert_chain, -1);

        match get_cert_from_cert_chain {
            Ok((942, 0x5d4)) => {
                println!("Cert verification");
            }
            _ => {
                assert!(false);
            }
        }
        let get_cert_from_cert_chain = verify_cert_chain(cert_chain);
        match get_cert_from_cert_chain {
            Ok(()) => {
                println!("Cert verification");
            }
            _ => {
                assert!(false);
            }
        }
    }
}
