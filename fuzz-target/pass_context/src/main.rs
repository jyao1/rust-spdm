// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod pass_responder;
use pass_responder::*;

mod pass_requester;
use pass_requester::*;

use log::LevelFilter;
use simple_logger::SimpleLogger;

fn new_logger_from_env() -> SimpleLogger {
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

fn main() {
    new_logger_from_env().init().unwrap();

    println!("run version");
    pass_rsp_handle_spdm_version();
    println!("run capability");
    pass_rsp_handle_spdm_capability();
    println!("run algorithm");
    pass_rsp_handle_spdm_algorithm();
    println!("run digests");
    pass_rsp_handle_spdm_digest();
    println!("run certificate");
    pass_rsp_handle_spdm_certificate();
    println!("run challenge");
    pass_rsp_handle_spdm_challenge();
    println!("run measurement");
    pass_rsp_handle_spdm_measurement();
    println!("run key exchange");
    pass_rsp_handle_spdm_key_exchange();
    println!("run psk exchange");
    pass_rsp_handle_spdm_psk_exchange();

    fuzz_total_requesters();
}
