// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{spdmlib::protocol::SpdmVersion, *};
use spdmlib::common::SpdmConnectionState;

fn fuzz_handle_spdm_capability(data: &[u8]) {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);

    context.handle_spdm_capability(data);
}

#[cfg(not(feature = "use_libfuzzer"))]
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
                0x10, 0x84, 00, 00, 0x11, 0xE1, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0x0C,
            ];
            fuzz_handle_spdm_capability(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_capability(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_capability(data);
    });
}
