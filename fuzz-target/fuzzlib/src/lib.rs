pub mod fake_device_io;
pub mod requesterlib;
pub mod responderlib;
pub mod shared_buffer;

use std::path::PathBuf;

pub use fake_device_io::{FakeSpdmDeviceIoReceve, FuzzSpdmDeviceIoReceve};
pub use requesterlib::{
    req_create_info, ReqProcess, MESSAGE_A, MESSAGE_B, MESSAGE_C, REQ_CERT_CHAIN_DATA,
};
pub use responderlib::rsp_create_info;
pub use shared_buffer::SharedBuffer;

pub use mctp_transport::MctpTransportEncap;
pub use pcidoe_transport::PciDoeTransportEncap;
pub use spdm_emu::crypto_callback::ASYM_SIGN_IMPL;
pub use spdm_emu::spdm_emu::*;
pub use spdmlib;
pub use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap};
pub use spdmlib::crypto::SpdmHmac;
pub use spdmlib::error::SpdmResult;
pub use spdmlib::msgs::*;
pub use spdmlib::{common, requester, responder};

pub use afl;
pub use flexi_logger;
pub use flexi_logger::FileSpec;

pub fn get_test_key_directory() -> PathBuf {
    let mut crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir.pop();
    crate_dir.pop();
    crate_dir.to_path_buf()
}

pub static FUZZ_HMAC: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(_base_hash_algo: SpdmBaseHashAlgo, _key: &[u8], data: &[u8]) -> Option<SpdmDigestStruct> {
    if data.len() > SPDM_MAX_HASH_SIZE {
        return Some(SpdmDigestStruct::from(&data[..48]));
    }
    Some(SpdmDigestStruct::from(data))
}

fn hmac_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
    _hmac: &SpdmDigestStruct,
) -> SpdmResult {
    Ok(())
}
