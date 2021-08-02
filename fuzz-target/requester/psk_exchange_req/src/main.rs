// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_psk_exchange(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let message_m = &[
        0x11, 0xe0, 0x00, 0x00, 0x11, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    // -- rsp config --
    // capability_rsp
    responder.common.negotiate_info.req_ct_exponent_sel = 0;
    responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        //| SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
    responder.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        //| SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;

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

    responder.common.reset_runtime_info();
    responder
        .common
        .runtime_info
        .message_a
        .append_message(MESSAGE_A);
    responder
        .common
        .runtime_info
        .message_b
        .append_message(MESSAGE_B);
    responder
        .common
        .runtime_info
        .message_c
        .append_message(MESSAGE_C);
    responder
        .common
        .runtime_info
        .message_m
        .append_message(message_m);

    // -- end --

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    //  -- req config --
    requester.common.negotiate_info.req_ct_exponent_sel = 0;
    requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP
    | SpdmRequestCapabilityFlags::CHAL_CAP
    | SpdmRequestCapabilityFlags::ENCRYPT_CAP
    | SpdmRequestCapabilityFlags::MAC_CAP
    //| SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    | SpdmRequestCapabilityFlags::KEY_EX_CAP
    | SpdmRequestCapabilityFlags::PSK_CAP
    | SpdmRequestCapabilityFlags::ENCAP_CAP
    | SpdmRequestCapabilityFlags::HBEAT_CAP
    | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
    requester.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP
    | SpdmResponseCapabilityFlags::CHAL_CAP
    | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
    | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
    | SpdmResponseCapabilityFlags::ENCRYPT_CAP
    | SpdmResponseCapabilityFlags::MAC_CAP
    //| SpdmResponseCapabilityFlags::MUT_AUTH_CAP
    | SpdmResponseCapabilityFlags::KEY_EX_CAP
    | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
    | SpdmResponseCapabilityFlags::ENCAP_CAP
    | SpdmResponseCapabilityFlags::HBEAT_CAP
    | SpdmResponseCapabilityFlags::KEY_UPD_CAP;

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

    requester.common.reset_runtime_info();
    requester
        .common
        .runtime_info
        .message_a
        .append_message(MESSAGE_A);
    requester
        .common
        .runtime_info
        .message_b
        .append_message(MESSAGE_B);
    requester
        .common
        .runtime_info
        .message_c
        .append_message(MESSAGE_C);
    requester
        .common
        .runtime_info
        .message_m
        .append_message(message_m);
    requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;
    // -- end --

    requester
        .send_receive_spdm_key_exchange(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .unwrap();
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
        fuzz_send_receive_spdm_psk_exchange(data.as_slice());
    } else {
        afl::fuzz!(|data: &[u8]| {
            fuzz_send_receive_spdm_psk_exchange(data);
        });
    }
}
