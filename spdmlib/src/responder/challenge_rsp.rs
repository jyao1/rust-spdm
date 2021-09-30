// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_challenge(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_challenge_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_challenge_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let challenge = SpdmChallengeRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(challenge) = challenge {
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

        info!("send spdm challenge_auth\n");

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let _ = crypto::rand::get_random(&mut nonce);

        let my_cert_chain = self.common.provision_info.my_cert_chain.unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseChallengeAuth,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: 0x0,
                    slot_mask: 0x1,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::empty(),
                    cert_chain_hash,
                    nonce: SpdmNonceStruct { data: nonce },
                    measurement_summary_hash: SpdmDigestStruct {
                        data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                        data: [0xaa; SPDM_MAX_HASH_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; config::MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                        data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        // generat signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let temp_used = used - base_asym_size;
        self.common
            .runtime_info
            .message_c
            .append_message(&writer.used_slice()[..temp_used]);

        let signature = self.common.generate_challenge_auth_signature();
        if signature.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let signature = signature.unwrap();
        // patch the message before send
        writer.mut_used_slice()[(used - base_asym_size)..used].copy_from_slice(signature.as_ref());
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_challenge() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        crypto::rand::register(DEFAULT_TEST);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.runtime_info.need_measurement_summary_hash = true;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let value = SpdmChallengeRequestPayload {
            slot_id: 100,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            nonce: SpdmNonceStruct { data: [100u8; 32] },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&challenge[0..1022]);
        context.handle_spdm_challenge(bytes);

        let data = context.common.runtime_info.message_c.as_ref();
        let u8_slice = &mut [0u8; 1024];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
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
        for i in 0..32 {
            assert_eq!(spdm_challenge_request_payload.nonce.data[i], 100u8);
        }

        let spdm_message_slice = &u8_slice[36..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseChallengeAuth
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
            assert_eq!(payload.measurement_summary_hash.data_size, 48);
            assert_eq!(payload.opaque.data_size, 0);
            assert_eq!(payload.signature.data_size, 96);
            for i in 0..32 {
                assert_eq!(payload.measurement_summary_hash.data[i], 0xaau8);
            }
            for (i, data) in cert_chain_hash.data.iter().enumerate() {
                assert_eq!(payload.cert_chain_hash.data[i], *data);
            }
        }
    }
}
