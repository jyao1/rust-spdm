// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod common;
#[cfg(feature = "test_with_ring")]
mod test_mbedtls {
    use super::common::crypto_callbacks;
    use spdmlib::protocol::*;

    #[test]
    fn test_mbedtls() {
        log::info!("test handlers");
        let data = &b"hello"[..];
        let sig = (crypto_callbacks::ASYM_SIGN_IMPL.sign_cb)(
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            data,
        )
        .unwrap();

        log::info!("signed: {:02x?}\n", sig.as_ref());

        let res =
            spdmlib::crypto::asym_verify::verify(
                SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                &include_bytes!(
                    "../../../rust-spdm/test_key/EcP256/bundle_responder.certchain.der"
                )[..],
                data,
                &sig,
            )
            .unwrap();
        log::info!("verified: {:?}\n", res);

        let res =
            (spdmlib_crypto_mbedtls::asym_verify_impl::DEFAULT.verify_cb)(
                SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                &include_bytes!(
                    "../../../rust-spdm/test_key/EcP256/bundle_responder.certchain.der"
                )[..],
                data,
                &sig,
            )
            .unwrap();

        log::info!("verified: {:?}\n", res);
    }
}
