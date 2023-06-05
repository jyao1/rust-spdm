// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{SpdmResult, SPDM_STATUS_VERIF_FAIL};
use crate::protocol::SpdmBaseAsymAlgo;

// reference: https://www.itu.int/rec/T-REC-X.690/en
// TAG
const ASN1_TAG_CLASS_UNIVERSAL_MASK: u8 = 0x0;
const ASN1_TAG_CLASS_CONTEXT_SPECIFIC_MASK: u8 = 0x80;

const ASN1_FORM_CONSTRUCTED_MASK: u8 = 0x20;

const ASN1_TAG_NUMBER_INTEGER: u8 = 0x2;
const ASN1_TAG_NUMBER_OBJECT_IDENTIFIER: u8 = 0x6;
const ASN1_TAG_NUMBER_SEQUENCE: u8 = 0x10;

const ASN1_TAG_SEQUENCE: u8 =
    ASN1_TAG_CLASS_UNIVERSAL_MASK | ASN1_FORM_CONSTRUCTED_MASK | ASN1_TAG_NUMBER_SEQUENCE;

const ASN1_LENGTH_MULTI_OCTET_MASK: u8 = 0x80;

const X509V3_VERSION: u8 = 2;
const OID_RSA_SHA256RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
const OID_RSA_SHA384RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0cu8];
const OID_RSA_SHA512RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0du8];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02u8];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03u8];

// reference: https://www.rfc-editor.org/rfc/rfc5280.txt
// IN DER encoded certificate chain slice
// OUT Ok certificate count
// OUT Error Mulformed certificate found
// checked:
// 1. version should be x509v3.
// 2. the algorithm is match for leaf certificate
// 3. no more or less bytes found
pub fn check_cert_chain_format(
    cert_chain: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
) -> SpdmResult<usize> {
    let mut cc_walker = 0usize;
    let mut cert_count = 0usize;
    let cert_chain_size = cert_chain.len();

    while cc_walker < cert_chain_size {
        cc_walker = cc_walker + check_cert_format(&cert_chain[cc_walker..], base_asym_algo)?;
        cert_count += 1;
    }

    if cc_walker == cert_chain_size {
        Ok(cert_count)
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

// IN DER encoded certificate slice
// OUT Ok cert size
// OUT Error Mulformed certificate found
fn check_cert_format(cert: &[u8], base_asym_algo: SpdmBaseAsymAlgo) -> SpdmResult<usize> {
    let mut c_walker = 0usize;
    let len = cert.len();

    check_tag_is_sequence(cert)?;
    c_walker += 1;

    let (body_size, bytes_consumed) = check_length(&cert[c_walker..])?;
    c_walker += bytes_consumed;

    if len == c_walker + body_size {
        c_walker += check_tbs_certificate(&cert[c_walker..], base_asym_algo, true)?;
        c_walker += check_signature_algorithm(&cert[c_walker..], base_asym_algo, true)?;
    } else {
        c_walker += check_tbs_certificate(&cert[c_walker..], base_asym_algo, false)?;
        c_walker += check_signature_algorithm(&cert[c_walker..], base_asym_algo, false)?;
    }

    c_walker += check_signature_value(&cert[c_walker..], base_asym_algo)?;

    if c_walker == 1 + bytes_consumed + body_size {
        Ok(c_walker)
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

fn check_tbs_certificate(
    data: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
    is_leaf_cert: bool,
) -> SpdmResult<usize> {
    let mut t_walker = 0usize;
    let len = data.len();

    check_tag_is_sequence(data)?;
    t_walker += 1;

    let (tbs_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    let length_before_tbs = t_walker;

    if len < t_walker + tbs_length {
        return Err(SPDM_STATUS_VERIF_FAIL);
    }

    // version         [0]  EXPLICIT Version DEFAULT v1,
    let bytes_consumed = check_version(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // serialNumber         CertificateSerialNumber,
    let bytes_consumed = check_and_skip_common_tag(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // signature            AlgorithmIdentifier,
    check_tag_is_sequence(&data[t_walker..])?;
    t_walker += 1;
    let (signature_id_length, bytes_consumed) = check_length(&data[t_walker..])?;
    t_walker += bytes_consumed;

    if is_leaf_cert {
        check_object_identifier(&data[t_walker..], get_oid_by_base_asym_algo(base_asym_algo))?;
    } else {
        check_object_identifier(&data[t_walker..], None)?;
    }
    t_walker += signature_id_length;
    // issuer               Name,
    let bytes_consumed = check_name(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // validity             Validity,
    let bytes_consumed = check_validity(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // subject              Name,
    let bytes_consumed = check_name(&data[t_walker..])?;
    t_walker += bytes_consumed;

    // subjectPublicKeyInfo SubjectPublicKeyInfo,
    check_public_key_info(&data[t_walker..])?;

    // issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
    // subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
    // extensions      [3]  EXPLICIT Extensions OPTIONAL

    Ok(length_before_tbs + tbs_length)
}

fn check_signature_algorithm(
    data: &[u8],
    base_asym_algo: SpdmBaseAsymAlgo,
    is_leaf_cert: bool,
) -> SpdmResult<usize> {
    let mut s_walker = 0usize;
    // signature            AlgorithmIdentifier,
    check_tag_is_sequence(&data[s_walker..])?;
    s_walker += 1;
    let (signature_id_length, bytes_consumed) = check_length(&data[s_walker..])?;
    s_walker += bytes_consumed;

    if is_leaf_cert {
        check_object_identifier(&data[s_walker..], get_oid_by_base_asym_algo(base_asym_algo))?;
    } else {
        check_object_identifier(&data[s_walker..], None)?;
    }

    Ok(s_walker + signature_id_length)
}

fn check_signature_value(data: &[u8], _base_asym_algo: SpdmBaseAsymAlgo) -> SpdmResult<usize> {
    check_and_skip_common_tag(data)
}

fn check_tag_is_sequence(data: &[u8]) -> SpdmResult {
    if data.is_empty() {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else if data[0] == ASN1_TAG_SEQUENCE {
        Ok(())
    } else {
        Err(SPDM_STATUS_VERIF_FAIL)
    }
}

// IN bytes slice
// OUT Ok (length, bytes consumed)
// OUT Error Mulformed certificate found
fn check_length(data: &[u8]) -> SpdmResult<(usize, usize)> {
    let len = data.len();
    if len < 1 {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else if data[0] & ASN1_LENGTH_MULTI_OCTET_MASK == 0 {
        Ok((data[0] as usize, 1))
    } else {
        let length_count = data[0] - ASN1_LENGTH_MULTI_OCTET_MASK;
        if len < (length_count as usize + 1) || length_count == 0 {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            let mut length = [0u8; 8];
            for (i, b) in data[1..length_count as usize + 1].iter().rev().enumerate() {
                length[i] = *b;
            }
            Ok((usize::from_le_bytes(length), length_count as usize + 1))
        }
    }
}

fn check_version(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 5
        || data[0] != (ASN1_TAG_CLASS_CONTEXT_SPECIFIC_MASK | ASN1_FORM_CONSTRUCTED_MASK)
        || data[1] != 3
        || data[2] != ASN1_TAG_NUMBER_INTEGER
        || data[3] != 1
    {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let version = data[4];
        if version == X509V3_VERSION {
            Ok(5)
        } else {
            Err(SPDM_STATUS_VERIF_FAIL)
        }
    }
}

fn check_object_identifier(data: &[u8], oid: Option<&'static [u8]>) -> SpdmResult<usize> {
    let len = data.len();
    if len < 2 || data[0] != ASN1_TAG_NUMBER_OBJECT_IDENTIFIER {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let oid_length = data[1];
        if len < oid_length as usize + 2 || oid_length >= 0x80 {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else if let Some(oid) = oid {
            if object_identifiers_are_same(&data[2..2 + oid_length as usize], oid) {
                Ok(oid_length as usize + 2)
            } else {
                Err(SPDM_STATUS_VERIF_FAIL)
            }
        } else {
            Ok(oid_length as usize + 2)
        }
    }
}

fn check_name(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_validity(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_public_key_info(data: &[u8]) -> SpdmResult<usize> {
    check_and_skip_common_sequence(data)
}

fn check_and_skip_common_sequence(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 1 || data[0] != ASN1_TAG_SEQUENCE {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok(1 + bytes_consumed + payload_length)
        }
    }
}

fn check_and_skip_common_tag(data: &[u8]) -> SpdmResult<usize> {
    let len = data.len();
    if len < 1 {
        Err(SPDM_STATUS_VERIF_FAIL)
    } else {
        let (payload_length, bytes_consumed) = check_length(&data[1..])?;
        if len < 1 + bytes_consumed + payload_length {
            Err(SPDM_STATUS_VERIF_FAIL)
        } else {
            Ok(1 + bytes_consumed + payload_length)
        }
    }
}

fn get_oid_by_base_asym_algo(base_asym_algo: SpdmBaseAsymAlgo) -> Option<&'static [u8]> {
    match base_asym_algo {
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048 => Some(OID_RSA_SHA256RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048 => Some(OID_RSA_SHA256RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072 => Some(OID_RSA_SHA384RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072 => Some(OID_RSA_SHA384RSA),
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => Some(OID_ECDSA_SHA256),
        SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => Some(OID_RSA_SHA512RSA),
        SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096 => Some(OID_RSA_SHA512RSA),
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => Some(OID_ECDSA_SHA384),
        _ => None,
    }
}

fn object_identifiers_are_same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        false
    } else {
        for (ai, bi) in a.iter().zip(b.iter()) {
            match ai.cmp(bi) {
                core::cmp::Ordering::Equal => continue,
                _ => return false,
            }
        }
        true
    }
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_object_identifiers_are_same() {
        let lt = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
        let lt_wrong1 = [0x2b, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0bu8];
        let lt_wrong2 = [0x2b, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0xb0u8];
        let lt_empty: [u8; 0] = [];
        assert!(object_identifiers_are_same(&lt, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt, OID_RSA_SHA384RSA));
        assert!(!object_identifiers_are_same(&lt_wrong1, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt_wrong2, OID_RSA_SHA256RSA));
        assert!(!object_identifiers_are_same(&lt_empty, OID_RSA_SHA384RSA));
    }

    #[test]
    fn test_case0_get_oid_by_base_asym_algo() {
        assert_eq!(
            get_oid_by_base_asym_algo(SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048),
            Some(OID_RSA_SHA256RSA)
        );
        assert_eq!(
            get_oid_by_base_asym_algo(SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Some(OID_ECDSA_SHA256)
        );
    }

    #[test]
    fn test_case0_check_and_skip_common_tag() {
        let sq1 = [
            0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xD7, 0x9C, 0x7F, 0x26, 0x91, 0x34,
            0xA5, 0x2B, 0x79, 0xEA, 0x66, 0x15, 0x00, 0x88, 0x0A, 0x4D, 0xE7, 0xAD, 0x71, 0xC6,
            0x2E, 0xE4, 0x7E, 0x37, 0xE1, 0x86, 0xEB, 0xE8, 0x55, 0xB0, 0x2F, 0xC5, 0xF3, 0xA9,
            0xE0, 0x90, 0xF9, 0x0B, 0x82, 0xC5, 0xDF, 0x4A, 0x35, 0x9A, 0x0D, 0x35, 0x38, 0x4B,
            0x02, 0x30, 0x40, 0xA7, 0xFE, 0x70, 0x39, 0x7B, 0x4B, 0xD7, 0xC2, 0x28, 0x72, 0x93,
            0x93, 0x0C, 0x62, 0x12, 0x14, 0xF0, 0x70, 0x74, 0x0F, 0xFC, 0xB1, 0x21, 0x60, 0x40,
            0x6D, 0x13, 0xA3, 0x59, 0x0E, 0x27, 0x06, 0xC1, 0x73, 0x4E, 0xCA, 0x40, 0x4C, 0x2D,
            0xF5, 0x96, 0x48, 0x66, 0x05, 0xB1, 0xA6, 0x08,
        ];
        let sq2 = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let sq3 = [0x01, 0x01, 0xFF];
        let sq4 = [0x01, 0x01, 0xFF, 0xAA];
        let sq1_wrong = [0x01, 0x02, 0xFF];
        assert_eq!(check_and_skip_common_tag(&sq1), Ok(106));
        assert_eq!(check_and_skip_common_tag(&sq2), Ok(5));
        assert_eq!(check_and_skip_common_tag(&sq3), Ok(3));
        assert_eq!(check_and_skip_common_tag(&sq4), Ok(3));
        assert_eq!(
            check_and_skip_common_tag(&sq1_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_and_skip_common_sequence() {
        let sq1 = [
            0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
            0x81, 0x04, 0x00, 0x22,
        ];
        let sq2 = std::fs::read("../test_key/test_web_cert/Amazon.cer")
            .expect("unable to read inter cert!");
        let sq3 = [0x30, 0x03, 0x02, 0x01, 0x02];
        let sq1_wrong = [
            0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xD7, 0x9C, 0x7F, 0x26, 0x91, 0x34,
            0xA5, 0x2B, 0x79, 0xEA, 0x66, 0x15, 0x00, 0x88, 0x0A, 0x4D, 0xE7, 0xAD, 0x71, 0xC6,
            0x2E, 0xE4, 0x7E, 0x37, 0xE1, 0x86, 0xEB, 0xE8, 0x55, 0xB0, 0x2F, 0xC5, 0xF3, 0xA9,
            0xE0, 0x90, 0xF9, 0x0B, 0x82, 0xC5, 0xDF, 0x4A, 0x35, 0x9A, 0x0D, 0x35, 0x38, 0x4B,
            0x02, 0x30, 0x40, 0xA7, 0xFE, 0x70, 0x39, 0x7B, 0x4B, 0xD7, 0xC2, 0x28, 0x72, 0x93,
            0x93, 0x0C, 0x62, 0x12, 0x14, 0xF0, 0x70, 0x74, 0x0F, 0xFC, 0xB1, 0x21, 0x60, 0x40,
            0x6D, 0x13, 0xA3, 0x59, 0x0E, 0x27, 0x06, 0xC1, 0x73, 0x4E, 0xCA, 0x40, 0x4C, 0x2D,
            0xF5, 0x96, 0x48, 0x66, 0x05, 0xB1, 0xA6, 0x08,
        ];
        let sq2_wrong = [0x30, 0x03, 0x02, 0x01];
        assert_eq!(check_and_skip_common_sequence(&sq1), Ok(18));
        assert_eq!(check_and_skip_common_sequence(&sq2), Ok(2006));
        assert_eq!(check_and_skip_common_sequence(&sq3), Ok(5));
        assert_eq!(
            check_and_skip_common_sequence(&sq1_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_and_skip_common_sequence(&sq2_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_object_identifier() {
        let oid1 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
        let oid2 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
        let oid3 = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        let oid1_wrong = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ];
        let oid2_wrong = [0x06, 0x08, 0x2A, 0x86];
        let oid3_wrong: [u8; 0] = [];
        assert_eq!(
            check_object_identifier(&oid1, Some(OID_ECDSA_SHA384)),
            Ok(10)
        );
        assert_eq!(
            check_object_identifier(&oid2, Some(OID_ECDSA_SHA256)),
            Ok(10)
        );
        assert_eq!(
            check_object_identifier(&oid3, Some(OID_RSA_SHA256RSA)),
            Ok(11)
        );
        assert_eq!(
            check_object_identifier(&oid1_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_object_identifier(&oid2_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_object_identifier(&oid3_wrong, Some(OID_ECDSA_SHA384)),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_version() {
        let v1 = [0xA0, 0x03, 0x02, 0x01, 0x02];
        let v1_wrong = [0xA0, 0x03, 0x02, 0x01, 0x01];
        let v2_wrong = [0x30, 0x03, 0x02, 0x01, 0x02];
        let v3_wrong = [0xA0, 0x03, 0x02, 0x01];
        assert_eq!(check_version(&v1), Ok(5));
        assert_eq!(check_version(&v1_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_version(&v2_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_version(&v3_wrong), Err(SPDM_STATUS_VERIF_FAIL));
    }

    #[test]
    fn test_case0_check_length() {
        let l1 = [0x03];
        let l2 = [0x81, 0x12];
        let l3 = [0x82, 0x01, 0xD7];
        let l1_wrong = [0x80];
        let l2_wrong = [0x81];
        let l3_wrong = [0x82, 0x01];
        assert_eq!(check_length(&l1), Ok((3, 1)));
        assert_eq!(check_length(&l2), Ok((0x12, 2)));
        assert_eq!(check_length(&l3), Ok((0x1D7, 3)));
        assert_eq!(check_length(&l1_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_length(&l2_wrong), Err(SPDM_STATUS_VERIF_FAIL));
        assert_eq!(check_length(&l3_wrong), Err(SPDM_STATUS_VERIF_FAIL));
    }

    #[test]
    fn test_case0_check_tag_is_sequence() {
        let l1 = [0x30];
        let l1_wrong = [0x80];
        let l2_wrong = [0x81];
        let l3_wrong = [0x82, 0x01];
        assert_eq!(check_tag_is_sequence(&l1), Ok(()));
        assert_eq!(
            check_tag_is_sequence(&l1_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tag_is_sequence(&l2_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tag_is_sequence(&l3_wrong),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_signature_algorithm() {
        let s1 = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
        ];
        let s1_wrong = [
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
        ];
        let s2_wrong = [0x06, 0x08, 0x2A, 0x86];
        let s3_wrong: [u8; 0] = [];
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384, true),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384, false),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256, false),
            Ok(12)
        );
        assert_eq!(
            check_signature_algorithm(&s1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256, true),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s2_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_signature_algorithm(
                &s3_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_tbs_certificate() {
        let t1 = std::fs::read("../test_key/ecp384/ca.cert.der").expect("unable to read ca cert!");
        let t2 =
            std::fs::read("../test_key/ecp384/inter.cert.der").expect("unable to read inter cert!");
        let t3 = std::fs::read("../test_key/ecp384/end_responder.cert.der")
            .expect("unable to read leaf cert!");

        let t1_wrong = [0x30, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_tbs_certificate(
                &t1[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(350)
        );
        assert_eq!(
            check_tbs_certificate(
                &t2[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(357)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                false
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                true
            ),
            Ok(460)
        );
        assert_eq!(
            check_tbs_certificate(
                &t3[4..],
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                true
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tbs_certificate(
                &t1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                false
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_tbs_certificate(
                &t1_wrong,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                true
            ),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_cert_format() {
        let c1 = std::fs::read("../test_key/ecp384/ca.cert.der").expect("unable to read ca cert!");
        let c2 =
            std::fs::read("../test_key/ecp384/inter.cert.der").expect("unable to read inter cert!");
        let c3 = std::fs::read("../test_key/ecp384/end_responder.cert.der")
            .expect("unable to read leaf cert!");

        let c1_wrong = [0x30u8, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_cert_format(&c1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(473)
        );
        assert_eq!(
            check_cert_format(&c2, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(478)
        );
        assert_eq!(
            check_cert_format(&c3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(582)
        );
        assert_eq!(
            check_cert_format(&c3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_cert_format(&c1_wrong, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }

    #[test]
    fn test_case0_check_cert_chain_format() {
        let ct1 = std::fs::read("../test_key/ecp256/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct2 = std::fs::read("../test_key/ecp384/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct3 = std::fs::read("../test_key/rsa2048/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct4 = std::fs::read("../test_key/rsa3072/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");
        let ct5 = std::fs::read("../test_key/rsa4096/bundle_responder.certchain.der")
            .expect("unable to read ca cert!");

        let ct1_wrong = [0x30, 0x82, 0x01, 0xA8, 0xA0];

        assert_eq!(
            check_cert_chain_format(&ct1, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct2, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct3, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct4, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct5, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096),
            Ok(3)
        );
        assert_eq!(
            check_cert_chain_format(&ct3, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
        assert_eq!(
            check_cert_chain_format(&ct1_wrong, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384),
            Err(SPDM_STATUS_VERIF_FAIL)
        );
    }
}
