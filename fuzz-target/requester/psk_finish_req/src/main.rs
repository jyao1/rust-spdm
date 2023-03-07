// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    *,
};
use spdmlib::protocol::*;

fn fuzz_send_receive_spdm_psk_finish(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

    let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;

    responder.common.session[0].setup(4294901758).unwrap();
    responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    responder.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );

    #[cfg(feature = "hashed-transcript-data")]
    {
        let mut dhe_secret = SpdmDheFinalKeyStruct::default();
        dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
        responder.common.session[0]
            .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
            .unwrap();
        responder.common.session[0].runtime_info.digest_context_th =
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
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
    requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
    requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;

    requester.common.session[0] = SpdmSession::new();
    requester.common.session[0].setup(4294901758).unwrap();
    requester.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);

    #[cfg(feature = "hashed-transcript-data")]
    {
        let mut dhe_secret = SpdmDheFinalKeyStruct::default();
        dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
        requester.common.session[0]
            .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
            .unwrap();
        requester.common.session[0].runtime_info.digest_context_th =
            spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
    }

    let _ = requester.send_receive_spdm_psk_finish(
        4294901758,
        pcidoe_transport_encap2,
        &mut device_io_requester,
    );
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
                0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca,
                0xa7, 0x51, 0x5a, 0x4d, 0x60, 0xcf, 0x4e, 0xc3, 0x17, 0x14, 0xa7, 0x55, 0x6f, 0x77,
                0x56, 0xad, 0xa4, 0xd0, 0x7e, 0xc2, 0xd4,
            ];
            fuzz_send_receive_spdm_psk_finish(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_psk_finish(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_psk_finish(data);
    });
}
