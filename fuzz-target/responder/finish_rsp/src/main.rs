// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{spdmlib::session::SpdmSession, *};

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

    // context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    // context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    // context.common.session = [SpdmSession::new(); 4];
    // context.common.session[0].setup(4294901758).unwrap();
    // context.common.session[0].set_crypto_param(
    //     SpdmBaseHashAlgo::TPM_ALG_SHA_384,
    //     SpdmDheAlgo::SECP_384_R1,
    //     SpdmAeadAlgo::AES_256_GCM,
    //     SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    // );
    context.handle_spdm_version(&[16, 132, 0, 0]);
    context.handle_spdm_capability(&[17, 225, 0, 0, 0, 0, 0, 0, 198, 118, 0, 0]);
    context.handle_spdm_algorithm(&[
        17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
    ]);
    context.handle_spdm_digest(&[17, 129, 0, 0]);
    context.handle_spdm_certificate(&[17, 130, 0, 0, 0, 0, 0, 2]);
    context.handle_spdm_certificate(&[17, 130, 0, 0, 0, 2, 0, 2]);
    context.handle_spdm_certificate(&[17, 130, 0, 0, 0, 4, 0, 2]);
    context.handle_spdm_certificate(&[17, 130, 0, 0, 0, 6, 8, 0]);
    context.handle_spdm_challenge(&[
        17, 131, 0, 0, 198, 247, 25, 118, 137, 77, 11, 164, 224, 40, 208, 61, 204, 104, 137, 63,
        225, 20, 183, 200, 121, 49, 105, 16, 17, 45, 31, 2, 102, 25, 173, 6,
    ]);
    context.handle_spdm_measurement(&[17, 224, 0, 0]);
    context.handle_spdm_key_exchange(&[
        17, 228, 0, 0, 254, 255, 0, 0, 159, 97, 79, 228, 255, 113, 48, 43, 124, 242, 132, 226, 149,
        127, 177, 173, 10, 221, 168, 234, 64, 154, 197, 242, 139, 6, 67, 190, 82, 100, 167, 5, 23,
        102, 246, 182, 154, 230, 67, 215, 51, 123, 127, 33, 0, 99, 147, 78, 250, 238, 223, 186,
        170, 72, 153, 152, 212, 177, 84, 6, 195, 103, 243, 140, 98, 61, 229, 44, 68, 181, 79, 50,
        238, 119, 117, 65, 113, 162, 168, 1, 189, 233, 173, 110, 60, 20, 187, 53, 237, 68, 176, 71,
        117, 209, 228, 66, 255, 26, 7, 6, 244, 40, 102, 135, 16, 86, 3, 154, 120, 95, 254, 180, 38,
        153, 139, 76, 66, 24, 205, 28, 237, 106, 52, 185, 28, 160, 219, 51, 20, 0, 70, 84, 77, 68,
        1, 1, 0, 0, 0, 0, 5, 0, 1, 1, 1, 0, 17, 0, 0, 0, 0, 0,
    ]);

    context.handle_spdm_finish(4294901758, data);
    let mut req_buf = [0u8; 1024];
    socket_io_transport.receive(&mut req_buf).unwrap();
    // println!("Received: {:?}", req_buf);
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
    if cfg!(feature = "analysis") {
        let args: Vec<String> = std::env::args().collect();
        println!("{:?}", args);
        if args.len() < 2 {
            println!("Please enter the path of the crash file as the first parameter");
            return;
        }
        let path = &args[1];
        let data = std::fs::read(path).expect("read crash file fail");
        fuzz_handle_spdm_finish(data.as_slice());
    } else {
        afl::fuzz!(|data: &[u8]| {
            fuzz_handle_spdm_finish(data);
        });
        // let data = std::fs::read("/home/tiano/rust-project/rust-spdm/fuzz-target/in/id:000012,sig:06,src:000028,time:58211,op:havoc,rep:16").expect("read crash file fail");
        // fuzz_handle_spdm_finish(data.as_slice());
        // fuzz_handle_spdm_finish(&[17, 229, 0, 0, 139, 161, 246, 59, 136, 207, 147, 214, 96, 218, 93, 94, 26, 94, 118, 149, 245, 246, 68, 165, 99, 14, 150, 164, 240, 120, 216, 232, 91, 183, 104, 242, 48, 61, 136, 165, 25, 71, 169, 27, 188, 105, 239, 81, 43, 118, 96, 57]);
    }
}
