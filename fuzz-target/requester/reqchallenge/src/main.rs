// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
// use rand::{distributions::Uniform, prelude::Distribution};

fn fuzz_send_receive_spdm_challenge(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    // version_rsp
    responder.common.reset_runtime_info();

    // algorithm_rsp
    responder
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
    responder.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
    responder.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
    responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    requester.common.reset_runtime_info();

    //algorithm_req
    requester
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

    requester.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
    requester.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

    requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;

    let _ = requester
        .send_receive_spdm_challenge(
            0,
            // SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        )
        .is_err();
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
        fuzz_send_receive_spdm_challenge(data.as_slice());
    } else {
        afl::fuzz!(|data: &[u8]| {
            fuzz_send_receive_spdm_challenge(data);
        });
    }

    // let _buffer: &[u8; 192] = &[
    //     0x1, 0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x11, 0x3, 0x0, 0x1, 0x28, 0xaf, 0x70, 0x27, 0xbc,
    //     0x2d, 0x95, 0xb5, 0xa0, 0xe4, 0x26, 0x4, 0xc5, 0x8c, 0x5c, 0x3c, 0xbf, 0xa2, 0xc8, 0x24,
    //     0xa6, 0x30, 0xca, 0x2f, 0xf, 0x4a, 0x79, 0x35, 0x57, 0xfb, 0x39, 0x3b, 0xdd, 0x8a, 0xc8,
    //     0x8a, 0x92, 0xd8, 0xa3, 0x70, 0x17, 0x12, 0x83, 0x9b, 0x66, 0xe1, 0x3a, 0x3a, 0xb8, 0xfb,
    //     0x45, 0x21, 0xfe, 0x4b, 0xf1, 0x13, 0xf9, 0x5, 0xab, 0x23, 0x87, 0x13, 0x81, 0xa4, 0x63,
    //     0x13, 0x45, 0x5e, 0x9f, 0xca, 0x14, 0xb9, 0x2f, 0x84, 0x90, 0xe5, 0x63, 0x9, 0x98, 0x66,
    //     0x0, 0x0, 0x98, 0x82, 0xb0, 0xa8, 0xe4, 0x3e, 0x9c, 0xcb, 0xb5, 0x76, 0x9c, 0x57, 0x16,
    //     0x61, 0xb7, 0x49, 0x49, 0x28, 0xc6, 0x1a, 0xf1, 0x42, 0xc9, 0x81, 0x63, 0xa7, 0x38, 0xb0,
    //     0x51, 0x71, 0x72, 0xde, 0x80, 0x4f, 0x84, 0x39, 0xe2, 0x5e, 0x41, 0x98, 0x6c, 0x5f, 0x38,
    //     0xc7, 0xf1, 0x13, 0x2a, 0x76, 0x90, 0x16, 0x7f, 0x84, 0x65, 0x67, 0xfa, 0x83, 0xba, 0x42,
    //     0x29, 0xa2, 0xd3, 0x29, 0x5f, 0x11, 0x58, 0xb3, 0x3a, 0x5, 0x1, 0x36, 0x33, 0x47, 0xc5,
    //     0x4e, 0x41, 0x68, 0xcf, 0x27, 0x98, 0xe, 0x1b, 0x4b, 0xe9, 0xc6, 0x9e, 0x4e, 0x2c, 0x68,
    //     0x32, 0x89, 0xe0, 0x8e, 0xd0, 0x4c, 0x8e, 0x4d, 0x0, 0x0,
    // ];

    // let buffer1 = &[
    //     1, 0, 1, 0, 60, 0, 0, 0, 17, 3, 0, 1, 40, 175, 112, 39, 188, 45, 149, 181, 160, 228, 38, 4,
    //     197, 140, 92, 60, 191, 162, 200, 36, 166, 48, 202, 47, 15, 74, 121, 53, 87, 251, 57, 59,
    //     221, 138, 200, 138, 146, 216, 163, 112, 23, 18, 131, 155, 102, 225, 58, 58, 229, 191, 68,
    //     75, 93, 70, 46, 90, 103, 249, 164, 23, 13, 197, 162, 221, 82, 1, 227, 202, 242, 137, 75,
    //     209, 218, 197, 87, 244, 36, 195, 222, 139, 170, 170, 170, 170, 170, 170, 170, 170, 170,
    //     170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
    //     170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170,
    //     170, 170, 170, 0, 0, 157, 93, 221, 23, 121, 63, 159, 190, 115, 49, 189, 176, 207, 210, 31,
    //     29, 117, 254, 174, 39, 144, 254, 112, 99, 250, 10, 140, 57, 24, 251, 166, 239, 62, 119, 42,
    //     115, 136, 75, 211, 114, 203, 169, 62, 249, 164, 40, 205, 180, 65, 153, 151, 108, 103, 193,
    //     170, 23, 72, 22, 167, 156, 127, 166, 100, 58, 104, 210, 235, 198, 141, 79, 26, 118, 43,
    //     118, 156, 134, 178, 249, 228, 216, 176, 149, 229, 211, 204, 168, 90, 83, 70, 237, 64, 254,
    //     219, 2, 123, 202, 0, 0,
    // ];

    // fuzz_send_receive_spdm_challenge(buffer1);
}
