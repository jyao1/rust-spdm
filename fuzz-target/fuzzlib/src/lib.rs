pub mod fake_device_io;
pub mod requesterlib;
pub mod responderlib;
pub mod shared_buffer;
pub mod fuzz_crypto;

use std::path::PathBuf;

pub use fake_device_io::{FakeSpdmDeviceIoReceve, FuzzSpdmDeviceIoReceve, FuzzTmpSpdmDeviceIoReceve};
pub use requesterlib::{
    req_create_info, ReqProcess, MESSAGE_A, MESSAGE_B, MESSAGE_C, REQ_CERT_CHAIN_DATA,certificata_data
};
pub use responderlib::rsp_create_info;
pub use shared_buffer::SharedBuffer;
pub use fuzz_crypto::{FUZZ_HMAC, FUZZ_RAND};

pub use mctp_transport::MctpTransportEncap;
pub use pcidoe_transport::PciDoeTransportEncap;
pub use spdm_emu::crypto_callback::ASYM_SIGN_IMPL;
pub use spdm_emu::spdm_emu::*;
pub use spdmlib;
pub use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap};
pub use spdmlib::config;
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
