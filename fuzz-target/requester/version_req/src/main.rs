// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_version(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();
    let (rsp_config_info1, rsp_provision_info1) = rsp_create_info();
    let (req_config_info1, req_provision_info1) = req_create_info();
    let (rsp_config_info2, rsp_provision_info2) = rsp_create_info();
    let (req_config_info2, req_provision_info2) = req_create_info();
    let (rsp_config_info3, rsp_provision_info3) = rsp_create_info();
    let (req_config_info3, req_provision_info3) = req_create_info();

    {
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

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let _ = requester.send_receive_spdm_version().is_err();
    }

    {
        // pass requester context
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info1,
            rsp_provision_info1,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info1,
            req_provision_info1,
        );
        if requester.init_connection().is_err() {
            return;
        }

        if requester.send_receive_spdm_digest().is_err() {
            return;
        }

        if requester.send_receive_spdm_certificate(0).is_err() {
            return;
        }

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        );
        if let Ok(session_id) = result {
            let session = requester.common.get_session_via_id(session_id).unwrap();
            let (_request_direction, _response_direction) = session.export_keys();

            if requester.send_receive_spdm_heartbeat(session_id).is_err() {
                return;
            }

            if requester
                .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
                .is_err()
            {
                return;
            }

            if requester.end_session(session_id).is_err() {
                return;
            }
        }
    }

    {
        // pass responder context
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info2,
            rsp_provision_info2,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info2,
            req_provision_info2,
        );

        // let _ = requester.send_message(&[]).is_err();
        let _ = requester.send_message(&[0xE, 0xE5]).is_err();
        let _ = requester.send_message(&[0xE, 0xE7]).is_err();
        let _ = requester.send_message(&[0xE, 0xE8]).is_err();
        let _ = requester.send_message(&[0xE, 0xE9]).is_err();
        let _ = requester.send_message(&[0xE, 0xEC]).is_err();
        let _ = requester.send_message(&[0xE, 0x01]).is_err();
        let _ = requester.send_message(&[0xE, 0x02]).is_err();
        let _ = requester.send_message(&[0xE, 0x03]).is_err();
        let _ = requester.send_message(&[0xE, 0x04]).is_err();
        let _ = requester.send_message(&[0xE, 0x60]).is_err();
        let _ = requester.send_message(&[0xE, 0x61]).is_err();
        let _ = requester.send_message(&[0xE, 0x63]).is_err();
        let _ = requester.send_message(&[0xE, 0x7F]).is_err();
        let _ = requester.send_message(&[0xE, 0x64]).is_err();
        let _ = requester.send_message(&[0xE, 0x65]).is_err();
        let _ = requester.send_message(&[0xE, 0x66]).is_err();
        let _ = requester.send_message(&[0xE, 0x67]).is_err();
        let _ = requester.send_message(&[0xE, 0x68]).is_err();
        let _ = requester.send_message(&[0xE, 0x69]).is_err();
        let _ = requester.send_message(&[0xE, 0x6C]).is_err();
        let _ = requester.send_message(&[0xE, 0xED]).is_err();
    }

    {
        // pass responder context
        let shared_buffer = SharedBuffer::new();
        // let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info3,
            rsp_provision_info3,
        );
        responder.common.session = [spdmlib::session::SpdmSession::new(); 4];
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(spdmlib::session::SpdmSessionState::SpdmSessionHandshaking);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info3,
            req_provision_info3,
        );

        requester.common.session = [spdmlib::session::SpdmSession::new(); 4];
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(spdmlib::session::SpdmSessionState::SpdmSessionHandshaking);

        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0xE1, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0xE3, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x81, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x82, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x83, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0xE0, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0xE4, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0xE6, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x01, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x02, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x03, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x04, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x60, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x61, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x63, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x64, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x65, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x66, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x67, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x68, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x69, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x6C, 0x2, 0x0])
            .is_err();
        let _ = requester
            .send_secured_message(4294901758, &[0x1, 0x7F, 0x2, 0x0])
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
