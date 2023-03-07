// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    fake_device_io::FakeSpdmDeviceIo, req_create_info, rsp_create_info, spdmlib,
    spdmlib::requester::RequesterContext, spdmlib::responder::ResponderContext,
    time::SPDM_TIME_IMPL, FuzzSpdmDeviceIoReceve, PciDoeTransportEncap, SharedBuffer,
    ASYM_SIGN_IMPL,
};

#[allow(unused)]
use fuzzlib::flexi_logger;

fn fuzz_send_receive_spdm_version(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        spdmlib::time::register(SPDM_TIME_IMPL.clone());

        let mut responder = ResponderContext::new(rsp_config_info, rsp_provision_info);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

        let _ = requester
            .send_receive_spdm_version(pcidoe_transport_encap2, &mut device_io_requester)
            .is_err();
    }
}

fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    #[cfg(not(feature = "fuzz"))]
    {
        flexi_logger::Logger::try_with_env()
            .unwrap()
            .start()
            .unwrap();
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [17, 4, 0, 0, 0, 2, 0, 16, 0, 17];
            fuzz_send_receive_spdm_version(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_version(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_version(data);
    });
}
