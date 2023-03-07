// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
use spdmlib::protocol::*;

fn fuzz_send_receive_spdm_certificate(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();
    let (rsp_config_info1, rsp_provision_info1) = rsp_create_info();
    let (req_config_info1, req_provision_info1) = req_create_info();
    let (rsp_config_info2, rsp_provision_info2) = rsp_create_info();
    let (req_config_info2, req_provision_info2) = req_create_info();
    let (rsp_config_info3, rsp_provision_info3) = rsp_create_info();
    let (req_config_info3, req_provision_info3) = req_create_info();
    let (rsp_config_info4, rsp_provision_info4) = rsp_create_info();
    let (req_config_info4, req_provision_info4) = req_create_info();
    {
        // pass
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        #[cfg(feature = "hashed-transcript-data")]
        {
            responder.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = requester::RequesterContext::new(req_config_info, req_provision_info);

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        #[cfg(feature = "hashed-transcript-data")]
        {
            requester.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let _ = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_err();
    }
    {
        // error 151 lines
        let mut fuzzdata: [[u8; 528]; 4] = certificata_data();
        fuzzdata[0][20] = 0;
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzTmpSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata, 0);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(rsp_config_info1, rsp_provision_info1);
        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        #[cfg(feature = "hashed-transcript-data")]
        {
            responder.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = requester::RequesterContext::new(req_config_info1, req_provision_info1);

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        #[cfg(feature = "hashed-transcript-data")]
        {
            requester.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let _ = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_err();
    }
    {
        // error 155 lines
        let fuzzdata: [[u8; 528]; 4] = certificata_data();
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzTmpSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata, 0);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(rsp_config_info2, rsp_provision_info2);
        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        #[cfg(feature = "hashed-transcript-data")]
        {
            responder.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = requester::RequesterContext::new(req_config_info2, req_provision_info2);

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        let mut tmp = requester
            .common
            .provision_info
            .peer_cert_chain_data
            .unwrap();
        tmp.data_size += 1;
        requester.common.provision_info.peer_cert_chain_data = Some(tmp);

        #[cfg(feature = "hashed-transcript-data")]
        {
            requester.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let _ = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_err();
    }
    {
        // error 167 lines
        let fuzzdata: [[u8; 528]; 4] = certificata_data();
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzTmpSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata, 0);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(rsp_config_info3, rsp_provision_info3);

        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        #[cfg(feature = "hashed-transcript-data")]
        {
            responder.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        // digest_rsp

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = requester::RequesterContext::new(req_config_info3, req_provision_info3);
        let mut tmp = requester
            .common
            .provision_info
            .peer_cert_chain_data
            .unwrap();
        tmp.data[1490] = 0;
        requester.common.provision_info.peer_cert_chain_data = Some(tmp);
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        #[cfg(feature = "hashed-transcript-data")]
        {
            requester.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let _ = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_err();
    }
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(rsp_config_info4, rsp_provision_info4);

        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        #[cfg(feature = "hashed-transcript-data")]
        {
            responder.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = requester::RequesterContext::new(req_config_info4, req_provision_info4);
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        #[cfg(feature = "hashed-transcript-data")]
        {
            requester.common.runtime_info.digest_context_m1m2 =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }
        let _ = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
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
            let fuzzdata = [
                1, 0, 1, 0, 48, 0, 0, 0, 17, 2, 255, 1, 127, 0, 0, 0, 0, 17, 3, 0, 1, 40, 175, 112,
                39, 188, 132, 74, 57, 59, 221, 138, 200, 158, 146, 216, 163, 112, 23, 18, 131, 155,
                102, 225, 58, 58, 49, 11, 42, 205, 113, 132, 74, 251, 185, 250, 222, 111, 123, 34,
                132, 180, 134, 168, 183, 103, 238, 4, 45, 255, 255, 255, 127, 198, 199, 61, 112,
                123, 231, 0, 206, 47, 251, 131, 40, 175, 112, 39, 188, 132, 74, 190, 105, 0, 64,
                36, 157, 254, 244, 68, 221, 19, 51, 22, 40, 110, 235, 82, 62, 86, 193, 20, 43, 245,
                230, 18, 193, 240, 192, 137, 158, 145, 137, 119, 25, 53, 131, 79, 219, 238, 133,
                74, 194, 76, 145, 125, 17, 153, 210, 123, 49, 221, 151, 25, 130, 110, 134, 159,
                182, 154, 251, 94,
            ];
            fuzz_send_receive_spdm_certificate(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_certificate(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_certificate(data);
    });
}
