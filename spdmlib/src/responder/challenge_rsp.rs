// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
use crate::common::ManagedBufferM1M2;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::crypto;
use crate::error::SpdmResult;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
extern crate alloc;
use alloc::boxed::Box;

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::{SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR};

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_challenge(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_challenge_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_challenge_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return;
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let challenge = SpdmChallengeRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(challenge) = &challenge {
            debug!("!!! challenge : {:02x?}\n", challenge);

            if (challenge.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (challenge.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
            }
        } else {
            error!("!!! challenge : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let challenge = challenge.unwrap();
        let slot_id = challenge.slot_id as usize;
        if slot_id >= SPDM_MAX_SLOT_NUMBER {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        if self.common.provision_info.my_cert_chain[slot_id].is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        #[cfg(not(feature = "hashed-transcript-data"))]
        if self
            .common
            .runtime_info
            .message_c
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            &bytes[..reader.used()],
        )
        .unwrap();

        info!("send spdm challenge_auth\n");

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let _ = crypto::rand::get_random(&mut nonce);

        let my_cert_chain = self.common.provision_info.my_cert_chain[slot_id]
            .as_ref()
            .unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: slot_id as u8,
                    slot_mask: 0x1,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::empty(),
                    cert_chain_hash,
                    nonce: SpdmNonceStruct { data: nonce },
                    measurement_summary_hash: SpdmDigestStruct {
                        data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                        data: Box::new([0xaa; SPDM_MAX_HASH_SIZE]),
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                        data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        let _ = response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        // generat signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let temp_used = used - base_asym_size;
        #[cfg(not(feature = "hashed-transcript-data"))]
        self.common
            .runtime_info
            .message_c
            .append_message(&writer.used_slice()[..temp_used]);

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            &writer.used_slice()[..temp_used],
        )
        .unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        let signature = self.generate_challenge_auth_signature();
        #[cfg(feature = "hashed-transcript-data")]
        let digest_context_m1m2_clone = self
            .common
            .runtime_info
            .digest_context_m1m2
            .as_mut()
            .cloned()
            .unwrap();
        #[cfg(feature = "hashed-transcript-data")]
        let signature = self.generate_challenge_auth_signature(
            crypto::hash::hash_ctx_finalize(digest_context_m1m2_clone).unwrap(),
        );
        if signature.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let signature = signature.unwrap();
        // patch the message before send
        writer.mut_used_slice()[(used - base_asym_size)..used].copy_from_slice(signature.as_ref());
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_challenge_auth_signature(
        &self,
        message_hash: SpdmDigestStruct,
    ) -> SpdmResult<SpdmSignatureStruct> {
        use crate::error::{SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR};

        debug!("message_hash - {:02x?}", message_hash.as_ref());

        let mut message = ManagedBufferM1M2::default();
        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_4)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_CHALLENGE_AUTH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(message_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crypto::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_challenge_auth_signature(&mut self) -> SpdmResult<SpdmSignatureStruct> {
        let mut message = ManagedBufferM1M2::default();
        message
            .append_message(self.common.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        message
            .append_message(self.common.runtime_info.message_b.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        message
            .append_message(self.common.runtime_info.message_c.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_4)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_CHALLENGE_AUTH_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(message_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crypto::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }
}

#[cfg(all(test,))]
mod tests_responder {
    #[test]
    #[cfg(feature = "hashed-transcript-data")]
    fn test_case0_handle_spdm_challenge() {
        use super::*;
        use crate::message::SpdmMessageHeader;
        use crate::testlib::*;
        use crate::{crypto, responder};
        use codec::{Codec, Writer};

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::rand::register(DEFAULT_TEST.clone());

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

        context.common.runtime_info.digest_context_m1m2 =
            Some(crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384).unwrap());

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
}
