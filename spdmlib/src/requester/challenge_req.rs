// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_LOCAL,
    SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult {
        info!("send spdm challenge\n");

        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used =
            self.encode_spdm_challenge(slot_id, measurement_summary_hash_type, &mut send_buffer)?;
        self.send_message(&send_buffer[..send_used])?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, true)?;
        self.handle_spdm_challenge_response(
            0, // NULL
            slot_id,
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        crypto::rand::get_random(&mut nonce)?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(SpdmChallengeRequestPayload {
                slot_id,
                measurement_summary_hash_type,
                nonce: SpdmNonceStruct { data: nonce },
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_challenge_response(
        &mut self,
        session_id: u32,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        if (measurement_summary_hash_type
            == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
            || (measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
        {
            self.common.runtime_info.need_measurement_summary_hash = true;
        } else {
            self.common.runtime_info.need_measurement_summary_hash = false;
        }

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseChallengeAuth => {
                        let challenge_auth = SpdmChallengeAuthResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(challenge_auth) = challenge_auth {
                            debug!("!!! challenge_auth : {:02x?}\n", challenge_auth);

                            // verify signature
                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used - base_asym_size;

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                let message_c = &mut self.common.runtime_info.message_c;
                                message_c
                                    .append_message(send_buffer)
                                    .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
                                message_c
                                    .append_message(&receive_buffer[..temp_used])
                                    .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
                            }

                            #[cfg(feature = "hashed-transcript-data")]
                            {
                                crypto::hash::hash_ctx_update(
                                    self.common
                                        .runtime_info
                                        .digest_context_m1m2
                                        .as_mut()
                                        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
                                    send_buffer,
                                )?;
                                crypto::hash::hash_ctx_update(
                                    self.common
                                        .runtime_info
                                        .digest_context_m1m2
                                        .as_mut()
                                        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
                                    &receive_buffer[..temp_used],
                                )?;
                            }

                            if self
                                .verify_challenge_auth_signature(slot_id, &challenge_auth.signature)
                                .is_err()
                            {
                                error!("verify_challenge_auth_signature fail");
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                info!("verify_challenge_auth_signature pass");
                            }

                            Ok(())
                        } else {
                            error!("!!! challenge_auth : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestChallenge,
                            SpdmRequestResponseCode::SpdmResponseChallengeAuth,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    pub fn verify_challenge_auth_signature(
        &mut self,
        slot_id: u8,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            message
                .append_message(self.common.runtime_info.message_a.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(self.common.runtime_info.message_b.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(self.common.runtime_info.message_c.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        #[cfg(feature = "hashed-transcript-data")]
        let message_hash;
        #[cfg(feature = "hashed-transcript-data")]
        {
            let digest = crypto::hash::hash_ctx_finalize(
                self.common
                    .runtime_info
                    .digest_context_m1m2
                    .as_mut()
                    .cloned()
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            );
            if let Some(digest) = digest {
                message_hash = digest;
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
        }
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        #[cfg(feature = "hashed-transcript-data")]
        let mut message = ManagedBuffer::default();

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

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message.as_ref(),
            signature,
        )
    }
}
#[cfg(all(test,))]
mod tests_requester {
    #[test]
    #[cfg(feature = "hashed-transcript-data")]
    fn test_case0_send_receive_spdm_challenge() {
        use super::*;
        use crate::message::*;
        use crate::protocol::*;
        use crate::testlib::*;
        use crate::{crypto, responder};

        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::rand::register(DEFAULT_TEST.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = [
            Some(SpdmCertChainBuffer {
                data_size: 512u16,
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
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.runtime_info.need_measurement_summary_hash = true;

        responder.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );
        requester.common.reset_runtime_info();

        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.runtime_info.need_measurement_summary_hash = true;

        requester.common.peer_info.peer_cert_chain[0] = Some(RSP_CERT_CHAIN_BUFF);
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        requester.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let status = requester
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .is_ok();
        assert!(status);
    }
}
