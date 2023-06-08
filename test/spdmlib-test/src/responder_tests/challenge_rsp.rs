// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]

use crate::common::crypto_callback::FAKE_RAND;
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::*;
use spdmlib::message::SpdmChallengeRequestPayload;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, crypto, responder, secret};

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_challenge() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    crypto::rand::register(FAKE_RAND.clone());

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.common.provision_info.my_cert_chain = [
        Some(SpdmCertChainBuffer {
            data_size: (4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE) as u16,
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ];

    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.runtime_info.need_measurement_summary_hash = true;

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

    let spdm_message_header = &mut [0u8; 2];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
    };
    assert!(value.encode(&mut writer).is_ok());

    let challenge = &mut [0u8; 2 + SPDM_NONCE_SIZE];
    let mut writer = Writer::init(challenge);
    let value = SpdmChallengeRequestPayload {
        slot_id: 100,
        measurement_summary_hash_type:
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        nonce: SpdmNonceStruct {
            data: [100u8; SPDM_NONCE_SIZE],
        },
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

    let bytes = &mut [0u8; 4 + SPDM_NONCE_SIZE];
    bytes[0..2].copy_from_slice(&spdm_message_header[0..]);
    bytes[2..4 + SPDM_NONCE_SIZE].copy_from_slice(&challenge[0..2 + SPDM_NONCE_SIZE]);
    context.handle_spdm_challenge(bytes);

    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        let data = context.common.runtime_info.message_c.as_ref();
        let u8_slice = &mut [0u8; 4
            + SPDM_MAX_HASH_SIZE
            + SPDM_NONCE_SIZE
            + SPDM_MAX_HASH_SIZE
            + 2
            + MAX_SPDM_OPAQUE_SIZE
            + SPDM_MAX_ASYM_KEY_SIZE];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let spdm_challenge_request_payload =
            SpdmChallengeRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_challenge_request_payload.slot_id, 100);
        assert_eq!(
            spdm_challenge_request_payload.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
        );
        for i in 0..SPDM_NONCE_SIZE {
            assert_eq!(spdm_challenge_request_payload.nonce.data[i], 100u8);
        }

        let spdm_message_slice = &u8_slice[4 + SPDM_NONCE_SIZE..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseChallengeAuth
        );

        let cert_chain_hash = crypto::hash::hash_all(
            context.common.negotiate_info.base_hash_sel,
            context
                .common
                .provision_info
                .my_cert_chain
                .unwrap()
                .as_ref(),
        )
        .unwrap();

        if let SpdmMessagePayload::SpdmChallengeAuthResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 0x0);
            assert_eq!(payload.slot_mask, 0x1);
            assert_eq!(
                payload.challenge_auth_attribute,
                SpdmChallengeAuthAttribute::empty()
            );
            assert_eq!(
                payload.measurement_summary_hash.data_size,
                SHA384_DIGEST_SIZE
            );
            assert_eq!(payload.opaque.data_size, 0);
            assert_eq!(payload.signature.data_size, SECP_384_R1_KEY_SIZE);
            for i in 0..SHA384_DIGEST_SIZE {
                assert_eq!(payload.measurement_summary_hash.data[i], 0xaau8);
            }
            for (i, data) in cert_chain_hash.data.iter().enumerate() {
                assert_eq!(payload.cert_chain_hash.data[i], *data);
            }
        }
    }
}
