// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmAsymVerify;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

pub static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: asym_verify,
};

use core::ffi::c_int;

const MBEDTLS_MD_SHA256: c_int = 6;
const MBEDTLS_MD_SHA384: c_int = 7;
use super::ffi::{spdm_pk_verify, spdm_rsa_pss_verify};

fn asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    if signature.data_size != base_asym_algo.get_size() {
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    let mbedtls_hash_algo = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => MBEDTLS_MD_SHA384,
        SpdmBaseHashAlgo::TPM_ALG_SHA_256 => MBEDTLS_MD_SHA256,
        _ => {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
    };

    // DER has this format: 0x30 size 0x02 r_size 0x00 [r_size] 0x02 s_size 0x00 [s_size]
    let mut der_signature = [0u8; spdmlib::protocol::ECDSA_ECC_NIST_P384_KEY_SIZE + 8];

    let signature = match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
            let der_sign_size = ecc_signature_bin_to_der(signature.as_ref(), &mut der_signature)?;
            &der_signature[0..der_sign_size]
        }
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => signature.as_ref(),
        _ => {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
    };

    let (leaf_begin, leaf_end) =
        (super::cert_operation_impl::DEFAULT.get_cert_from_cert_chain_cb)(public_cert_der, -1)?;
    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    let data_hash = (super::hash_impl::DEFAULT.hash_all_cb)(base_hash_algo, data).unwrap();

    let ret = match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
        | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => unsafe {
            spdm_pk_verify(
                mbedtls_hash_algo,
                leaf_cert_der.as_ptr(),
                leaf_cert_der.len(),
                data_hash.data.as_ptr(),
                data_hash.data_size as usize,
                signature.as_ptr(),
                signature.len(),
            )
        },
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
        | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096 => unsafe {
            spdm_rsa_pss_verify(
                mbedtls_hash_algo,
                leaf_cert_der.as_ptr(),
                leaf_cert_der.len(),
                data_hash.data.as_ptr(),
                data_hash.data_size as usize,
                signature.as_ptr(),
                signature.len(),
            )
        },
        _ => {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
    };
    match ret {
        0 => Ok(()),
        _ => Err(SPDM_STATUS_CRYPTO_ERROR),
    }
}

// add ASN.1 for the ECDSA binary signature
fn ecc_signature_bin_to_der(signature: &[u8], der_signature: &mut [u8]) -> SpdmResult<usize> {
    let sign_size = signature.len();
    let half_size = sign_size / 2;

    let mut r_index = half_size;
    for (i, item) in signature.iter().enumerate().take(half_size) {
        if *item != 0 {
            r_index = i;
            break;
        }
    }
    let r_size = half_size - r_index;
    let r = &signature[r_index..half_size];

    let mut s_index = half_size;
    for i in 0..half_size {
        if signature[i + half_size] != 0 {
            s_index = i;
            break;
        }
    }
    let s_size = half_size - s_index;
    let s = &signature[half_size + s_index..sign_size];
    if r_size == 0 || s_size == 0 {
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    let der_r_size = if r[0] < 0x80 { r_size } else { r_size + 1 };
    let der_s_size = if s[0] < 0x80 { s_size } else { s_size + 1 };
    // der_sign_size includes: 0x30 _ 0x02 _ [der_r_size] 0x02 _ [der_s_size]
    let der_sign_size = der_r_size + der_s_size + 6;

    if der_signature.len() < der_sign_size {
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    if der_r_size > u8::MAX as usize
        || der_s_size > u8::MAX as usize
        || der_sign_size > u8::MAX as usize
    {
        return Err(SPDM_STATUS_CRYPTO_ERROR);
    }

    der_signature[0] = 0x30u8;
    der_signature[1] = (der_sign_size - 2) as u8;
    der_signature[2] = 0x02u8;
    der_signature[3] = der_r_size as u8;
    if r[0] < 0x80 {
        der_signature[4..(4 + r_size)].copy_from_slice(r);
    } else {
        der_signature[4] = 0u8;
        der_signature[5..(5 + r_size)].copy_from_slice(r);
    }
    der_signature[4 + der_r_size] = 0x02u8;
    der_signature[5 + der_r_size] = der_s_size as u8;

    if s[0] < 0x80 {
        der_signature[(6 + der_r_size)..(6 + der_r_size + s_size)].copy_from_slice(s);
    } else {
        der_signature[6 + der_r_size] = 0u8;
        der_signature[(7 + der_r_size)..(7 + der_r_size + s_size)].copy_from_slice(s);
    }

    Ok(der_sign_size)
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_ecc_signature_bin_to_der() {
        let signature = &mut [0x00u8; 64];
        for i in 10..signature.len() {
            signature[i] = 0x10;
        }

        let der_signature = &mut [0u8; 64];

        let der_sign_size = ecc_signature_bin_to_der(signature, der_signature).unwrap();
        assert_eq!(der_sign_size, 60);
    }
    #[test]
    fn test_case1_ecc_signature_bin_to_der() {
        let signature = &mut [0x00u8; 32];
        for i in 10..signature.len() {
            signature[i] = 0xff;
        }

        let der_signature = &mut [0u8; 64];

        let der_sign_size = ecc_signature_bin_to_der(signature, der_signature).unwrap();
        assert_eq!(der_sign_size, 30);
    }
    #[test]
    fn test_case2_ecc_signature_bin_to_der() {
        let signature = &mut [0x0u8; 64];
        let der_signature = &mut [0u8; 64];
        signature[63] = 0xff;
        let der_sign_size = ecc_signature_bin_to_der(signature, der_signature).unwrap_or(0);
        assert_eq!(der_sign_size, 0);
    }
    #[test]
    #[should_panic]
    fn test_case3_ecc_signature_bin_to_der() {
        let signature = &mut [0xffu8; 64];
        let der_signature = &mut [0u8; 64];
        ecc_signature_bin_to_der(signature, der_signature).unwrap();
    }
    #[test]
    fn test_case0_asym_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; spdmlib::protocol::SPDM_MAX_ASYM_KEY_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        let asym_verify = asym_verify(
            base_hash_algo,
            base_asym_algo,
            public_cert_der,
            data,
            &signature,
        );
        assert!(asym_verify.is_err());
    }
    #[test]
    fn test_case1_asym_verify() {
        let base_hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        let base_asym_algo = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; spdmlib::protocol::SPDM_MAX_ASYM_KEY_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        let asym_verify = asym_verify(
            base_hash_algo,
            base_asym_algo,
            public_cert_der,
            data,
            &signature,
        );
        assert!(asym_verify.is_err());
    }
    #[test]
    fn test_case2_asym_verify() {
        let base_hash_algo = [
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        ];
        let base_asym_algo = [
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
        ];
        let mut signature = SpdmSignatureStruct {
            data_size: 512,
            data: [0x00u8; spdmlib::protocol::SPDM_MAX_ASYM_KEY_SIZE],
        };
        signature.data[250] = 0x10;
        signature.data[510] = 0x10;

        let public_cert_der = &include_bytes!("public_cert.der")[..];
        let data = &mut [0x10u8; 4096];

        for base_hash_algo in base_hash_algo.iter() {
            for base_asym_algo in base_asym_algo.iter() {
                let asym_verify = asym_verify(
                    *base_hash_algo,
                    *base_asym_algo,
                    public_cert_der,
                    data,
                    &signature,
                );
                assert!(asym_verify.is_err());
            }
        }
    }
}
