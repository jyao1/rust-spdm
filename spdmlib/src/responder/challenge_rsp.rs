// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_challenge(&mut self, bytes: &[u8]) {
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
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        if self
            .common
            .runtime_info
            .message_c
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        info!("send spdm challenge_auth\n");

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let _ = crypto::rand::get_random (&mut nonce);

        let my_cert_chain = self.common.provision_info.my_cert_chain.unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
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
                    nonce: SpdmNonceStruct {
                        data: nonce,
                    },
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
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        // generat signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let temp_used = used - base_asym_size;
        self.common
            .runtime_info
            .message_c
            .append_message(&send_buffer[..temp_used]);

        let signature = self.common.generate_challenge_auth_signature();
        if signature.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let signature = signature.unwrap();
        // patch the message before send
        send_buffer[(used - base_asym_size)..used].copy_from_slice(signature.as_ref());

        let _ = self.send_message(&send_buffer[0..used]);
    }
}
