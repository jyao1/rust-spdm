// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{*, spdmlib::session::SpdmSession};


fn fuzz_handle_spdm_finish(data: &[u8]) {
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

    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.session = [SpdmSession::new();4];
    context.common.session[0].setup(4294901758).unwrap();

    context.handle_spdm_finish(4294901758, data);
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
    // if cfg!(feature = "analysis") {
    //     let args: Vec<String> = std::env::args().collect();
    //     println!("{:?}", args);
    //     if args.len() < 2 {
    //         println!("Please enter the path of the crash file as the first parameter");
    //         return;
    //     }
    //     let path = &args[1];
    //     let data = std::fs::read(path).expect("read crash file fail");
    //     fuzz_handle_spdm_finish(data.as_slice());
    // } else {
    //     afl::fuzz!(|data: &[u8]| {
    //         fuzz_handle_spdm_finish(data);
    //     });
    // }
    let data = &[
        17, 229, 0, 0, 209, 20, 20, 139, 63, 30, 84, 205, 203, 67, 252, 50, 228, 122, 130, 117,
        236, 29, 238, 91, 100, 218, 242, 107, 37, 2, 243, 194, 10, 161, 209, 218, 121, 107, 18,
        248, 115, 253, 96, 11, 31, 26, 151, 41, 200, 167, 19, 33,
    ];
    fuzz_handle_spdm_finish(data);
}
