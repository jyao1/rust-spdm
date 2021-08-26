// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_challenge(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);
    spdmlib::crypto::rand::register(FUZZ_RAND);

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
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            // SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
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

    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [
                0x1, 0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x11, 0x3, 0x0, 0x1, 0x28, 0xaf, 0x70,
                0x27, 0xbc, 0x2d, 0x95, 0xb5, 0xa0, 0xe4, 0x26, 0x4, 0xc5, 0x8c, 0x5c, 0x3c, 0xbf,
                0xa2, 0xc8, 0x24, 0xa6, 0x30, 0xca, 0x2f, 0xf, 0x4a, 0x79, 0x35, 0x57, 0xfb, 0x39,
                0x3b, 0xdd, 0x8a, 0xc8, 0x8a, 0x92, 0xd8, 0xa3, 0x70, 0x17, 0x12, 0x83, 0x9b, 0x66,
                0xe1, 0x3a, 0x3a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x3, 0x76, 0xd, 0x57, 0x9b,
                0xaf, 0xe9, 0x6f, 0xc2, 0x5c, 0x2f, 0x3a, 0xfb, 0x81, 0xb, 0x4f, 0xa4, 0x5a, 0x65,
                0x4a, 0xc8, 0x64, 0x38, 0x91, 0xb1, 0x89, 0x8d, 0x42, 0xe9, 0xff, 0x55, 0xb, 0xfd,
                0xb1, 0xe1, 0x3c, 0x19, 0x1f, 0x1e, 0x8, 0xa2, 0x78, 0xd, 0xf3, 0x6, 0x6a, 0xfa,
                0xe, 0xee, 0xde, 0x27, 0x9, 0xb3, 0x20, 0xa1, 0xf5, 0x8d, 0x6e, 0xfc, 0x8a, 0x30,
                0x91, 0x5, 0x80, 0xae, 0x89, 0xb4, 0xee, 0x38, 0xcc, 0x92, 0x8e, 0x5e, 0x5b, 0x25,
                0x10, 0xdb, 0xd8, 0x32, 0x11, 0xd7, 0xf8, 0x23, 0x76, 0x49, 0x3d, 0x96, 0x7e, 0xb3,
                0x22, 0x4c, 0x5d, 0x50, 0x79, 0x71, 0x98, 0x0, 0x0,
            ];
            fuzz_send_receive_spdm_challenge(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_challenge(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    {
        use rand::{distributions::Uniform, prelude::Distribution};
        afl::fuzz!(|data: &[u8]| {
            let buffer_ff: &[u8; 192] = &[
                0x1, 0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x11, 0x3, 0x0, 0x1, 0x28, 0xaf, 0x70,
                0x27, 0xbc, 0x2d, 0x95, 0xb5, 0xa0, 0xe4, 0x26, 0x4, 0xc5, 0x8c, 0x5c, 0x3c, 0xbf,
                0xa2, 0xc8, 0x24, 0xa6, 0x30, 0xca, 0x2f, 0xf, 0x4a, 0x79, 0x35, 0x57, 0xfb, 0x39,
                0x3b, 0xdd, 0x8a, 0xc8, 0x8a, 0x92, 0xd8, 0xa3, 0x70, 0x17, 0x12, 0x83, 0x9b, 0x66,
                0xe1, 0x3a, 0x3a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x3, 0x76, 0xd, 0x57, 0x9b,
                0xaf, 0xe9, 0x6f, 0xc2, 0x5c, 0x2f, 0x3a, 0xfb, 0x81, 0xb, 0x4f, 0xa4, 0x5a, 0x65,
                0x4a, 0xc8, 0x64, 0x38, 0x91, 0xb1, 0x89, 0x8d, 0x42, 0xe9, 0xff, 0x55, 0xb, 0xfd,
                0xb1, 0xe1, 0x3c, 0x19, 0x1f, 0x1e, 0x8, 0xa2, 0x78, 0xd, 0xf3, 0x6, 0x6a, 0xfa,
                0xe, 0xee, 0xde, 0x27, 0x9, 0xb3, 0x20, 0xa1, 0xf5, 0x8d, 0x6e, 0xfc, 0x8a, 0x30,
                0x91, 0x5, 0x80, 0xae, 0x89, 0xb4, 0xee, 0x38, 0xcc, 0x92, 0x8e, 0x5e, 0x5b, 0x25,
                0x10, 0xdb, 0xd8, 0x32, 0x11, 0xd7, 0xf8, 0x23, 0x76, 0x49, 0x3d, 0x96, 0x7e, 0xb3,
                0x22, 0x4c, 0x5d, 0x50, 0x79, 0x71, 0x98, 0x0, 0x0,
            ];

            let mut rng = rand::thread_rng();
            let die = Uniform::from(0..buffer_ff.len()).sample(&mut rng);
            let mut buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
            buffer[..die].copy_from_slice(&buffer_ff[..die]);
            let left = buffer.len() - die;
            let data_len = data.len();
            match data_len > left {
                true => buffer[die..].copy_from_slice(&data[..left]),
                false => buffer[die..data_len + die].copy_from_slice(data),
            }
            fuzz_send_receive_spdm_challenge(&buffer);
        });
    }
}
