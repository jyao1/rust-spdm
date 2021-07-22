pub mod shared_buffer;
pub mod fake_device_io;
pub mod responderlib;
pub mod requesterlib;

use std::path::PathBuf;

pub use fake_device_io::{FakeSpdmDeviceIoReceve, FuzzSpdmDeviceIoReceve};
pub use shared_buffer::SharedBuffer;
pub use responderlib::rsp_create_info;
pub use requesterlib::{req_create_info, ReqProcess, REQ_CERT_CHAIN_DATA, MESSAGE_A, MESSAGE_B, MESSAGE_C};

pub use mctp_transport::MctpTransportEncap;
pub use pcidoe_transport::PciDoeTransportEncap;
pub use spdm_emu::crypto_callback::ASYM_SIGN_IMPL;
pub use spdm_emu::spdm_emu::*;
pub use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap};
pub use spdmlib::msgs::*;
pub use spdmlib::error::SpdmResult;
pub use spdmlib::{common, responder, requester};
pub use spdmlib;


pub use flexi_logger;
pub use flexi_logger::FileSpec;
pub use afl;

pub fn get_test_key_directory() -> PathBuf {
    let mut crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir.pop();
    crate_dir.pop();
    crate_dir.to_path_buf()
}
