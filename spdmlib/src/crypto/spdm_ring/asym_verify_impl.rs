use crate::crypto::{self, SpdmAsymVerify};
use crate::error::SpdmResult;
use crate::msgs::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};
use core::convert::TryFrom;

pub static DEFAULT: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: asym_verify,
};

fn asym_verify(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    public_cert_der: &[u8],
    data: &[u8],
    signature: &SpdmSignatureStruct,
) -> SpdmResult {
    let algorithm = match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
            &webpki::ECDSA_P256_SHA256
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            &webpki::ECDSA_P384_SHA256
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
            &webpki::ECDSA_P256_SHA384
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            &webpki::ECDSA_P384_SHA384
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            &webpki::RSA_PKCS1_2048_8192_SHA256
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            &webpki::RSA_PKCS1_2048_8192_SHA384
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
            &webpki::RSA_PKCS1_2048_8192_SHA512
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
        | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
            &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY
        }
        _ => {
            panic!();
        }
    };

    //
    // TBD: Find leaf cert - need use WEBPKI function
    //
    let (leaf_begin, leaf_end) =
        crypto::cert_operation::get_cert_from_cert_chain(public_cert_der, -1)?;
    let leaf_cert_der = &public_cert_der[leaf_begin..leaf_end];

    //debug!("signature len - 0x{:x?}\n", signature.data_size);
    //debug!("signature - {:x?}\n", &signature.data[..(signature.data_size as usize)]);

    let res = webpki::EndEntityCert::try_from(leaf_cert_der);
    match res {
        Ok(cert) => {
            //
            // Need translate from ECDSA_P384_SHA384_FIXED_SIGNING to ECDSA_P384_SHA384_ASN1
            // webpki only support ASN1 format ECDSA signature
            //
            match base_asym_algo {
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => {
                    let mut der_signature = [0u8; 66 * 2 + 8];
                    let der_sign_size =
                        ecc_signature_bin_to_der(signature.as_ref(), &mut der_signature);

                    //debug!("der signature len - 0x{:x?}\n", der_sign_size);
                    //debug!("der signature - {:x?}\n", der_signature);

                    match cert.verify_signature(algorithm, data, &der_signature[..(der_sign_size)])
                    {
                        Ok(()) => Ok(()),
                        Err(_) => spdm_result_err!(EFAULT),
                    }
                }
                _ => {
                    // RSASSA or RSAPSS
                    match cert.verify_signature(algorithm, data, signature.as_ref()) {
                        Ok(()) => Ok(()),
                        Err(_) => spdm_result_err!(EFAULT),
                    }
                }
            }
        }
        Err(_e) => spdm_result_err!(EFAULT),
    }
}

// add ASN.1 for the ECDSA binary signature
fn ecc_signature_bin_to_der(signature: &[u8], der_signature: &mut [u8]) -> usize {
    let sign_size = signature.len();
    let half_size = sign_size / 2;

    let mut r_index = 0usize;
    for (i, item) in signature.iter().enumerate().take(half_size) {
        if *item != 0 {
            r_index = i;
            break;
        }
    }
    let r_size = half_size - r_index;
    let r = &signature[r_index..half_size];

    let mut s_index = 0usize;
    for i in 0..half_size {
        if signature[i + half_size] != 0 {
            s_index = i;
            break;
        }
    }
    let s_size = half_size - s_index;
    let s = &signature[half_size + s_index..sign_size];

    if r_size == 0 || s_size == 0 {
        return 0;
    }

    let der_r_size = if r[0] < 0x80 { r_size } else { r_size + 1 };
    let der_s_size = if s[0] < 0x80 { s_size } else { s_size + 1 };
    let der_sign_size = der_r_size + der_s_size + 6;

    if der_signature.len() < der_sign_size {
        panic!("der_signature too small");
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

    der_sign_size
}
