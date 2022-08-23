// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod fake_device_io;
pub mod fuzz_aead_impl;
pub mod fuzz_crypto;
pub mod requesterlib;
pub mod responderlib;
pub mod secret;
pub mod shared_buffer;
pub mod time;

use std::path::PathBuf;

pub use fake_device_io::{
    FakeSpdmDeviceIoReceve, FuzzSpdmDeviceIoReceve, FuzzTmpSpdmDeviceIoReceve,
};

pub use fuzz_aead_impl::FUZZ_AEAD;
pub use fuzz_crypto::{FUZZ_HMAC, FUZZ_RAND};
pub use requesterlib::{certificata_data, req_create_info, REQ_CERT_CHAIN_DATA};
pub use responderlib::rsp_create_info;
pub use shared_buffer::SharedBuffer;

pub use codec;
pub use mctp_transport::MctpTransportEncap;
pub use pcidoe_transport::PciDoeTransportEncap;
use simple_logger::SimpleLogger;
pub use spdm_emu::crypto_callback::ASYM_SIGN_IMPL;
pub use spdm_emu::spdm_emu::*;
pub use spdmlib;
pub use spdmlib::common::{SpdmDeviceIo, SpdmTransportEncap};
pub use spdmlib::config;
// pub use spdmlib::msgs::*;
pub use spdmlib::{common, requester, responder};

pub use flexi_logger;
pub use flexi_logger::FileSpec;
use log::LevelFilter;

pub fn get_test_key_directory() -> PathBuf {
    let mut crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir.pop();
    crate_dir.pop();
    crate_dir.to_path_buf()
}

pub fn new_logger_from_env() -> SimpleLogger {
    let level = match std::env::var("SPDM_LOG") {
        Ok(x) => match x.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            _ => LevelFilter::Error,
        },
        _ => LevelFilter::Trace,
    };

    SimpleLogger::new().with_level(level)
}
