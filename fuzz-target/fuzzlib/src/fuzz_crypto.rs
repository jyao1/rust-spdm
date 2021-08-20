use spdmlib::crypto::SpdmCertOperation;
use spdmlib::msgs::SPDM_NONCE_SIZE;
use spdmlib::msgs::SpdmBaseHashAlgo;
pub use spdmlib::spdm_err;
pub use spdmlib::spdm_result_err;
use spdmlib::msgs::SpdmDigestStruct;
use spdmlib::crypto::SpdmHash;
pub use spdmlib::crypto::SpdmCryptoRandom;
pub use spdmlib::crypto::SpdmHmac;
pub use spdmlib::error::SpdmResult;

pub static FUZZ_HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(_base_hash_algo: SpdmBaseHashAlgo, _key: &[u8], _data: &[u8]) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::default())
}

fn hmac_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let SpdmDigestStruct{data_size,..} = hmac;
    match data_size {
        48 => Ok(()),
        _ => spdm_result_err!(EFAULT),
    }
}


pub static FUZZ_RAND: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {

    let rand_data = [0xff;SPDM_NONCE_SIZE];
    data.copy_from_slice(&rand_data);

    Ok(data.len())
}

pub static FUZZ_CERT: SpdmCertOperation = SpdmCertOperation {
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
    // static EKU_SPDM_RESPONDER_AUTH: webpki::verify_cert::KeyPurposeId =
    //     webpki::verify_cert::KeyPurposeId {
    //         oid_value: untrusted::Input::from(&[40 + 3, 6, 1, 5, 5, 7, 3, 1]), // TBD
    //     };

    // static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    //     &webpki::RSA_PKCS1_2048_8192_SHA256,
    //     &webpki::RSA_PKCS1_2048_8192_SHA384,
    //     &webpki::RSA_PKCS1_2048_8192_SHA512,
    //     &webpki::ECDSA_P256_SHA256,
    //     &webpki::ECDSA_P256_SHA384,
    //     &webpki::ECDSA_P384_SHA256,
    //     &webpki::ECDSA_P384_SHA384,
    // ];

    // let (ca_begin, ca_end) = get_cert_from_cert_chain(cert_chain, 0)?;
    // let ca = &cert_chain[ca_begin..ca_end];
    // // TBD: assume only one inter cert here.
    // let (inter_begin, inter_end) = get_cert_from_cert_chain(cert_chain, 1)?;
    // let inter = &cert_chain[inter_begin..inter_end];
    // let (ee_begin, ee_end) = get_cert_from_cert_chain(cert_chain, -1)?;
    // let ee = &cert_chain[ee_begin..ee_end];

    // let mut anchors = Vec::new();
    // anchors.push(webpki::TrustAnchor::from_cert_der(ca).unwrap());

    // #[cfg(target_os = "uefi")]
    // let time = webpki::Time::from_seconds_since_unix_epoch(uefi_time::get_rtc_time() as u64);
    // #[cfg(feature = "std")]
    // use std::convert::TryFrom;
    // #[cfg(feature = "std")]
    // let time = webpki::Time::try_from(std::time::SystemTime::now()).unwrap();

    // let cert = webpki::cert::parse_cert(
    //     untrusted::Input::from(ee),
    //     webpki::cert::EndEntityOrCA::EndEntity,
    // )
    // .unwrap();

    // we cannot call verify_is_valid_tls_server_cert because it will check verify_cert::EKU_SERVER_AUTH.
    // if webpki::verify_cert::build_chain(
    //     EKU_SPDM_RESPONDER_AUTH,
    //     ALL_SIGALGS,
    //     &anchors,
    //     &[inter],
    //     &cert,
    //     time,
    //     0,
    // )
    // .is_ok()
    // {
    //     info!("Cert verification Pass\n");
    //     Ok(())
    // } else {
    //     error!("Cert verification Fail\n");
    //     spdm_result_err!(EFAULT)
    // }
    Ok(())
}


pub static FUZZ_HASH: SpdmHash = SpdmHash {
    hash_all_cb: hash_all,
};

fn hash_all(base_hash_algo: SpdmBaseHashAlgo, data: &[u8]) -> Option<SpdmDigestStruct> {
    // let algorithm = match base_hash_algo {
    //     SpdmBaseHashAlgo::TPM_ALG_SHA_256 => &ring::digest::SHA256,
    //     SpdmBaseHashAlgo::TPM_ALG_SHA_384 => &ring::digest::SHA384,
    //     SpdmBaseHashAlgo::TPM_ALG_SHA_512 => &ring::digest::SHA512,
    //     _ => return None,
    // };
    // let digest_value = ring::digest::digest(algorithm, data);
    let digest_value = SpdmDigestStruct::default();
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
}