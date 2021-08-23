use spdmlib::crypto::SpdmCertOperation;
pub use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::crypto::SpdmHash;
pub use spdmlib::crypto::SpdmHmac;
pub use spdmlib::error::SpdmResult;
use spdmlib::msgs::SpdmBaseHashAlgo;
use spdmlib::msgs::SpdmDigestStruct;
use spdmlib::msgs::SPDM_MAX_HASH_SIZE;
use spdmlib::msgs::SPDM_NONCE_SIZE;
pub use spdmlib::spdm_err;
pub use spdmlib::spdm_result_err;

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
    let SpdmDigestStruct { data_size, .. } = hmac;
    match data_size {
        48 => Ok(()),
        _ => spdm_result_err!(EFAULT),
    }
}

pub static FUZZ_RAND: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    let rand_data = [0xff; SPDM_NONCE_SIZE];
    data.copy_from_slice(&rand_data);

    Ok(data.len())
}

pub static FUZZ_CERT: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: get_cert_from_cert_chain,
    verify_cert_chain_cb: verify_cert_chain,
};

fn get_cert_from_cert_chain(cert_chain: &[u8], index: isize) -> SpdmResult<(usize, usize)> {

    Ok((0,0))
    // }
}

fn verify_cert_chain(_cert_chain: &[u8]) -> SpdmResult {

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
    let mut tmp = [0; SPDM_MAX_HASH_SIZE];
    let digest_value = match data.len() > SPDM_MAX_HASH_SIZE {
        true => {
            tmp.copy_from_slice(&data[..SPDM_MAX_HASH_SIZE]);
            SpdmDigestStruct {
            data_size: SPDM_MAX_HASH_SIZE as u16,
            data: tmp,
        }},
        false => {
            tmp[..data.len()].copy_from_slice(data);
            SpdmDigestStruct {
                data_size: data.len() as u16,
                data: tmp,
            }
        }
    };
    Some(SpdmDigestStruct::from(digest_value.as_ref()))
}
