// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_measurement(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();
    let (rsp_config_info1, rsp_provision_info1) = rsp_create_info();
    let (req_config_info1, req_provision_info1) = req_create_info();
    let (rsp_config_info2, rsp_provision_info2) = rsp_create_info();
    let (req_config_info2, req_provision_info2) = req_create_info();
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

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
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        responder.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        responder.common.reset_runtime_info();

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

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
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        requester.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;

        requester.common.reset_runtime_info();

        let _ = requester
            .send_receive_spdm_measurement(SpdmMeasurementOperation::SpdmMeasurementRequestAll, 0);
    }

    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info1,
            rsp_provision_info1,
        );

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
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        responder.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        responder.common.reset_runtime_info();

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info1,
            req_provision_info1,
        );

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
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        requester.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;

        requester.common.reset_runtime_info();

        let _ = requester.send_receive_spdm_measurement(
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            0,
        );
    }
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info2,
            rsp_provision_info2,
        );

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
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        responder.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        responder.common.reset_runtime_info();

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info2,
            req_provision_info2,
        );

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
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        requester.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;

        requester.common.reset_runtime_info();

        let _ = requester.send_receive_spdm_measurement(SpdmMeasurementOperation::Unknown(4), 0);
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
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [
                01, 00, 01, 00, 0x0c, 00, 00, 00, 11, 0xe0, 01, 04, 0x0a, 0xfc, 04, 0xa0, 63, 0x5c,
                0x2e, 0x6c, 0x4b, 0x62, 0xd6, 0xc0, 0x1c, 0xf5, 0xc5, 0xa1, 0xb0, 0x9f, 0xff, 0x5a,
                0x1a, 68, 0xab, 78, 0xb1, 0xea, 25, 0xa8, 94, 0x6b, 0xac, 0xf4, 00, 00, 00, 00,
            ];
            fuzz_send_receive_spdm_measurement(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_measurement(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_measurement(data);
    });
}
