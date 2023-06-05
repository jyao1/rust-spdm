// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    *,
};
use spdmlib::protocol::*;

fn fuzz_handle_spdm_psk_finish(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
    spdmlib::crypto::hmac::register(FAKE_HMAC.clone());
    spdmlib::crypto::hkdf::register(FAKE_HKDF.clone());

    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK finish request'
    // - description: '<p>Respond PSK finish rsp to complete the handshake.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0].set_use_psk(true);
        context.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct::default());

        #[cfg(feature = "hashed-transcript-data")]
        {
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.handle_spdm_psk_finish(4294836221, data);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK finish request'
    // - description: '<p>Respond PSK finish rsp to complete the handshake, with message_a set.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0].set_use_psk(true);
        context.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct::default());

        context
            .common
            .runtime_info
            .message_a
            .append_message(&[1u8; config::MAX_SPDM_MSG_SIZE]);

        #[cfg(feature = "hashed-transcript-data")]
        {
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.handle_spdm_psk_finish(4294836221, data);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK finish request'
    // - description: '<p>Respond PSK finish rsp to complete the handshake, with wrong base hash algo.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0].set_use_psk(true);
        context.common.session[0].runtime_info.psk_hint = Some(SpdmPskHintStruct::default());

        #[cfg(feature = "hashed-transcript-data")]
        {
            context.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        context.handle_spdm_psk_finish(4294836221, data);
    }
}

#[cfg(not(feature = "use_libfuzzer"))]
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
            let fuzzdata = [17, 46, 43];
            fuzz_handle_spdm_psk_finish(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_psk_finish(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_psk_finish(data);
    });
}
