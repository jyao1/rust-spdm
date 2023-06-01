// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod common;
#[cfg(feature = "test_with_ring")]
mod test_mbedtls {
    use super::common::crypto_callbacks;
    use spdmlib::protocol::*;

    #[test]
    fn test_mbedtls_rsa() {
        let hash_algos = [
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        ];
        let asym_algos = [
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa2048/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa3072/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa4096/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa2048/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa3072/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
                &include_bytes!(
                    "../../../rust-spdm/test_key/rsa4096/bundle_responder.certchain.der"
                )[..],
            ),
        ];

        for hash_algo in hash_algos {
            for (asym_algo, cert_chain) in asym_algos {
                test_asym_sign_verify(hash_algo, asym_algo, cert_chain);
            }
        }
    }

    #[test]
    fn test_mbedtls_ecdsa() {
        let ecdsa_test_params = [
            (
                SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                &include_bytes!(
                    "../../../rust-spdm/test_key/ecp256/bundle_responder.certchain.der"
                )[..],
            ),
            (
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                &include_bytes!(
                    "../../../rust-spdm/test_key/ecp384/bundle_responder.certchain.der"
                )[..],
            ),
        ];
        for (hash_algo, asym_algo, cert_chain) in ecdsa_test_params {
            test_asym_sign_verify(hash_algo, asym_algo, cert_chain);
        }
    }

    fn test_asym_sign_verify(
        hash_algo: SpdmBaseHashAlgo,
        asym_algo: SpdmBaseAsymAlgo,
        cert_chain: &[u8],
    ) {
        let data = &b"hello"[..];
        let sig = (crypto_callbacks::SECRET_ASYM_IMPL_INSTANCE.sign_cb)(hash_algo, asym_algo, data)
            .unwrap();

        spdmlib::crypto::asym_verify::verify(hash_algo, asym_algo, cert_chain, data, &sig).unwrap();

        (spdmlib_crypto_mbedtls::asym_verify_impl::DEFAULT.verify_cb)(
            hash_algo, asym_algo, cert_chain, data, &sig,
        )
        .unwrap();
    }
}
