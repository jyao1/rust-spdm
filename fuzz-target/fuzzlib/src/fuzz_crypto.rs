pub use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::crypto::SpdmHmac;
pub use spdmlib::error::SpdmResult;
use spdmlib::msgs::SpdmBaseHashAlgo;
use spdmlib::msgs::SpdmDigestStruct;
use spdmlib::msgs::SPDM_NONCE_SIZE;
pub use spdmlib::spdm_err;
pub use spdmlib::spdm_result_err;

pub static FUZZ_HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(_base_hash_algo: SpdmBaseHashAlgo, _key: &[u8], _data: &[u8]) -> Option<SpdmDigestStruct> {
    let mut hmac_data = SpdmDigestStruct::default();
    hmac_data.data_size = 48;
    Some(hmac_data)
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
