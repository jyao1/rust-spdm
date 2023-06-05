// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::crypto_callback::*;
use crate::common::device_io::{FakeSpdmDeviceIo, SharedBuffer, SpdmDeviceIoReceve};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::session::{SpdmSession, SpdmSessionState};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{crypto, responder, secret};

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_send_receive_spdm_psk_finish() {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();
    let data = &mut [
        0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca, 0xa7,
        0x51, 0x5a, 0x4d, 0x60, 0xcf, 0x4e, 0xc3, 0x17, 0x14, 0xa7, 0x55, 0x6f, 0x77, 0x56, 0xad,
        0xa4, 0xd0, 0x7e, 0xc2, 0xd4,
    ];

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
    crypto::hmac::register(FAKE_HMAC.clone());

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

    // let rsp_session_id = 0x11u16;
    // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
    responder.common.session = gen_array_clone(SpdmSession::new(), 4);
    responder.common.session[0].setup(4294901758).unwrap();
    responder.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    responder.common.session[0].runtime_info.digest_context_th =
        Some(crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap());

    let dhe_secret = SpdmDheFinalKeyStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    let _ = responder.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

    // let rsp_session_id = 0x11u16;
    // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
    requester.common.session = gen_array_clone(SpdmSession::new(), 4);
    requester.common.session[0].setup(4294901758).unwrap();
    requester.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );
    requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionHandshaking);
    requester.common.session[0].runtime_info.digest_context_th =
        Some(crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap());

    let dhe_secret = SpdmDheFinalKeyStruct {
        data_size: 48,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    let _ = requester.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
    let status = requester.send_receive_spdm_psk_finish(4294901758).is_ok();
    assert!(status);
}
