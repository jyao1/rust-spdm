// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
use spdmlib::protocol::*;

fn fuzz_send_receive_spdm_psk_exchange(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();
    let (rsp_config_info1, rsp_provision_info1) = rsp_create_info();
    let (req_config_info1, req_provision_info1) = req_create_info();
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.provision_info.my_cert_chain = [
            Some(RSP_CERT_CHAIN_BUFF),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        let _ = requester.send_receive_spdm_psk_exchange(
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        );
    }
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info1,
            rsp_provision_info1,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.provision_info.my_cert_chain = [
            Some(RSP_CERT_CHAIN_BUFF),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info1,
            req_provision_info1,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;

        let _ = requester.send_receive_spdm_psk_exchange(
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        );
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
                0x1, 0x0, 0x1, 0x0, 0x21, 0x0, 0x0, 0x0, 0x11, 0x66, 0x0, 0x0, 0xfd, 0xff, 0x0,
                0x0, 0x30, 0x0, 0x10, 0x0, 0xfc, 0xed, 0xa7, 0xd8, 0x7f, 0x87, 0xc1, 0x93, 0x3d,
                0x5c, 0x9c, 0x60, 0x65, 0xa0, 0xc5, 0xf7, 0xb7, 0x88, 0x98, 0x7c, 0x24, 0x83, 0xf,
                0xe5, 0x5e, 0xc7, 0x8, 0x73, 0xb7, 0xbe, 0x79, 0xd4, 0x30, 0x8e, 0x70, 0x19, 0x8c,
                0xa3, 0xa4, 0x6a, 0x52, 0xd5, 0x8e, 0xb8, 0x4, 0x88, 0x38, 0x66, 0x46, 0x54, 0x4d,
                0x44, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x11, 0x99, 0x97, 0x7,
                0xc5, 0x29, 0x1a, 0x16, 0x57, 0xff, 0x6c, 0xa3, 0x45, 0xef, 0xd7, 0xda, 0xdc, 0x95,
                0x3d, 0x36, 0x1d, 0xf4, 0x1b, 0xea, 0x22, 0x66, 0xeb, 0xfe, 0x76, 0x7f, 0x8e, 0x57,
                0x7c, 0x9f, 0x1e, 0xe2, 0xc1, 0x9d, 0x41, 0x38, 0x4d, 0xa1, 0xd, 0xdd, 0x7d, 0xaf,
                0xc9, 0xa2, 0xfa,
            ];
            fuzz_send_receive_spdm_psk_exchange(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_psk_exchange(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_psk_exchange(data);
    });
}
