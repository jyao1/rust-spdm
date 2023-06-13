// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{spdmlib::protocol::SpdmVersion, *};
use spdmlib::common::SpdmConnectionState;

fn fuzz_send_receive_spdm_algorithm(fuzzdata: &[u8]) {
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer);
    device_io_requester.set_rx(fuzzdata);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;

    let _ = requester.send_receive_spdm_algorithm().is_err();
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
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [
                0x1, 0x0, 0x1, 0x0, 0xf, 0x0, 0x0, 0x0, 0x11, 0x63, 0x4, 0x0, 0x34, 0x0, 0x1, 0x0,
                0x4, 0x0, 0x0, 0x0, 0x80, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x20, 0x10, 0x0,
                0x3, 0x20, 0x2, 0x0, 0x4, 0x20, 0x2, 0x0, 0x5, 0x20, 0x1, 0x0,
            ];
            fuzz_send_receive_spdm_algorithm(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_algorithm(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_algorithm(data);
    });
}
