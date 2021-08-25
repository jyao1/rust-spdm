// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_handle_spdm_psk_exchange(data: &[u8]) {

    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let mctp_transport_encap = &mut MctpTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        if USE_PCIDOE {
            pcidoe_transport_encap
        } else {
            mctp_transport_encap
        },
        config_info,
        provision_info,
    );
    context.handle_spdm_algorithm(&[
        17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
    ]);
    context.handle_spdm_digest(&[17, 129, 0, 0]);
    context.handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2]);
    context.handle_spdm_challenge(&[
        17, 131, 0, 0, 96, 98, 50, 80, 166, 189, 68, 2, 27, 142, 255, 200, 180, 230, 76, 45, 12,
        178, 253, 70, 242, 202, 83, 171, 115, 148, 32, 249, 52, 170, 141, 122,
    ]);
    context.handle_spdm_measurement(&[17, 224, 0, 0]);
    context.handle_spdm_key_exchange(&[
        17, 228, 0, 0, 254, 255, 0, 0, 227, 11, 91, 150, 99, 148, 85, 82, 35, 135, 88, 241, 249,
        244, 105, 233, 225, 89, 237, 166, 13, 142, 13, 115, 102, 29, 108, 90, 113, 211, 174, 92,
        16, 14, 136, 6, 200, 113, 5, 174, 212, 211, 70, 68, 204, 188, 78, 228, 190, 118, 132, 77,
        185, 118, 93, 140, 122, 16, 249, 41, 82, 143, 79, 77, 248, 113, 230, 73, 72, 135, 132, 15,
        32, 138, 130, 163, 95, 80, 59, 109, 65, 92, 6, 36, 29, 182, 124, 73, 92, 173, 125, 81, 95,
        136, 251, 177, 48, 95, 136, 77, 252, 72, 31, 208, 25, 145, 113, 245, 11, 229, 125, 252,
        154, 63, 97, 36, 64, 150, 86, 131, 90, 36, 64, 150, 86, 131, 90, 36, 93, 181, 85, 154, 164,
        34, 20, 0, 70, 84, 77, 68, 1, 1, 0, 0, 0, 0, 5, 0, 1, 1, 1, 0, 17, 0, 0, 0, 0, 0,
    ]);
    context.handle_spdm_psk_exchange(data);
    let mut req_buf = [0u8; 1024];
    socket_io_transport.receive(&mut req_buf).unwrap();
    println!("Received: {:?}", req_buf);
}
fn main() {

    #[cfg(feature = "fuzzlog")]
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
            let fuzzdata = [17,46,43];
            fuzz_handle_spdm_psk_exchange(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_psk_exchange(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_psk_exchange(data);
    });
}