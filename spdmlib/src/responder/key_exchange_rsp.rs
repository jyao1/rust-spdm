// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::session::SpdmSession;
#[cfg(feature = "hashed-transcript-data")]
use crate::common::ManagedBuffer12Sign;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::common::SpdmOpaqueSupport;
use crate::crypto;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_STATE_LOCAL, SPDM_STATUS_INVALID_STATE_PEER,
};
use crate::protocol::*;
use crate::responder::*;
extern crate alloc;
use crate::common::opaque::SpdmOpaqueStruct;
use crate::message::*;
use crate::secret;
use alloc::boxed::Box;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_key_exchange(&mut self, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_key_exchange_response(bytes, &mut writer)?;
        self.send_message(writer.used_slice())
    }

    pub fn write_spdm_key_exchange_response(
        &mut self,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> SpdmResult {
        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_PEER);
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
            if message_header.version.get_u8() < SpdmVersion::SpdmVersion11.get_u8() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnsupportedRequest, 0, writer);
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestKeyExchange, None);

        let key_exchange_req =
            SpdmKeyExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);

        let mut return_opaque = SpdmOpaqueStruct::default();

        let measurement_summary_hash;
        if let Some(key_exchange_req) = &key_exchange_req {
            debug!("!!! key_exchange req : {:02x?}\n", key_exchange_req);

            if (key_exchange_req.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (key_exchange_req.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
                let measurement_summary_hash_res =
                    secret::measurement::generate_measurement_summary_hash(
                        self.common.negotiate_info.spdm_version_sel,
                        self.common.negotiate_info.base_hash_sel,
                        self.common.negotiate_info.measurement_specification_sel,
                        self.common.negotiate_info.measurement_hash_sel,
                        key_exchange_req.measurement_summary_hash_type,
                    );
                if measurement_summary_hash_res.is_none() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                measurement_summary_hash = measurement_summary_hash_res.unwrap();
                if measurement_summary_hash.data_size == 0 {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
                measurement_summary_hash = SpdmDigestStruct::default();
            }

            if key_exchange_req.session_policy
                & KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_MASK
                == KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_VALUE
            {
                self.common.negotiate_info.termination_policy_set = true;
            } else {
                self.common.negotiate_info.termination_policy_set = false;
            }

            if let Some(secured_message_version_list) = key_exchange_req
                .opaque
                .rsp_get_dmtf_supported_secure_spdm_version_list(&mut self.common)
            {
                if secured_message_version_list.version_count
                    > crate::common::opaque::MAX_SECURE_SPDM_VERSION_COUNT as u8
                {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                for index in 0..secured_message_version_list.version_count as usize {
                    for local_version in self.common.config_info.secure_spdm_version {
                        if secured_message_version_list.versions_list[index]
                            .get_secure_spdm_version()
                            == local_version
                        {
                            if self.common.negotiate_info.spdm_version_sel.get_u8()
                                < SpdmVersion::SpdmVersion12.get_u8()
                            {
                                return_opaque.data_size =
                                    crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0277
                                        .len() as u16;
                                return_opaque.data[..(return_opaque.data_size as usize)]
                                    .copy_from_slice(
                                    crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0277
                                        .as_ref(),
                                );
                                return_opaque.data[return_opaque.data_size as usize - 1] =
                                    local_version;
                            } else if self.common.negotiate_info.opaque_data_support
                                == SpdmOpaqueSupport::OPAQUE_DATA_FMT1
                            {
                                return_opaque.data_size =
                                    crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0274_FMT1
                                        .len() as u16;
                                return_opaque.data[..(return_opaque.data_size as usize)]
                                    .copy_from_slice(
                                    crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0274_FMT1
                                        .as_ref(),
                                );
                                return_opaque.data[return_opaque.data_size as usize - 1] =
                                    local_version;
                            } else {
                                self.write_spdm_error(
                                    SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                    0,
                                    writer,
                                );
                                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                            }
                        }
                    }
                }
            }
        } else {
            error!("!!! key_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let key_exchange_req = key_exchange_req.unwrap();
        let slot_id = key_exchange_req.slot_id as usize;
        if slot_id >= SPDM_MAX_SLOT_NUMBER {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        if self.common.provision_info.my_cert_chain[slot_id].is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        self.common
            .runtime_info
            .set_local_used_cert_chain_slot_id(key_exchange_req.slot_id);

        let (exchange, key_exchange_context) =
            crypto::dhe::generate_key_pair(self.common.negotiate_info.dhe_sel).unwrap();

        debug!("!!! exchange data : {:02x?}\n", exchange);

        debug!(
            "!!! exchange data (peer) : {:02x?}\n",
            &key_exchange_req.exchange
        );

        let final_key = key_exchange_context.compute_final_key(&key_exchange_req.exchange);

        if final_key.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        let final_key = final_key.unwrap();
        debug!("!!! final_key : {:02x?}\n", final_key.as_ref());

        let rsp_session_id = self.common.get_next_half_session_id(false);
        if rsp_session_id.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionLimitExceeded, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }
        let rsp_session_id = rsp_session_id.unwrap();

        // create session structure
        let hash_algo = self.common.negotiate_info.base_hash_sel;
        let dhe_algo = self.common.negotiate_info.dhe_sel;
        let aead_algo = self.common.negotiate_info.aead_sel;
        let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
        let sequence_number_count = self.common.transport_encap.get_sequence_number_count();
        let max_random_count = self.common.transport_encap.get_max_random_count();

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let message_a = self.common.runtime_info.message_a.clone();
        let cert_chain_hash = self.common.get_certchain_hash_local(false, slot_id);
        if cert_chain_hash.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let session = self.common.get_next_avaiable_session();
        if session.is_none() {
            error!("!!! too many sessions : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionLimitExceeded, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        #[cfg(feature = "mut-auth")]
        let mut_auth_req = SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS;
        #[cfg(not(feature = "mut-auth"))]
        let mut_auth_req = SpdmKeyExchangeMutAuthAttributes::empty();

        let session = session.unwrap();
        let session_id = ((rsp_session_id as u32) << 16) + key_exchange_req.req_session_id as u32;
        session.setup(session_id).unwrap();
        session.set_use_psk(false);
        session.set_slot_id(slot_id as u8);
        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_mut_auth_requested(mut_auth_req);
        session.set_transport_param(sequence_number_count, max_random_count);
        if session.set_dhe_secret(spdm_version_sel, final_key).is_err() {
            let _ = session.teardown(session_id);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        session.runtime_info.message_a = message_a;
        session.runtime_info.rsp_cert_hash = cert_chain_hash;
        session.runtime_info.req_cert_hash = None;

        let mut random = [0u8; SPDM_RANDOM_SIZE];
        let res = crypto::rand::get_random(&mut random);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }

        let in_clear_text = self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        info!("in_clear_text {:?}\n", in_clear_text);

        info!("send spdm key_exchange rsp\n");

        // prepare response
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeResponse(SpdmKeyExchangeResponsePayload {
                heartbeat_period: self.common.config_info.heartbeat_period,
                rsp_session_id,
                mut_auth_req,
                req_slot_id: 0x0,
                random: SpdmRandomStruct { data: random },
                exchange,
                measurement_summary_hash,
                opaque: return_opaque.clone(),
                signature: SpdmSignatureStruct {
                    data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                    data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                },
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }
        let used = writer.used();

        // generate signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = if in_clear_text {
            used - base_asym_size
        } else {
            used - base_asym_size - base_hash_size
        };

        if self
            .common
            .append_message_k(session_id, &bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        if self
            .common
            .append_message_k(session_id, &writer.used_slice()[..temp_used])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        let signature = self.generate_key_exchange_rsp_signature(slot_id as u8, session);
        if signature.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        let signature = signature.unwrap();

        if self
            .common
            .append_message_k(session_id, signature.as_ref())
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        // generate the handshake secret (including finished_key) before generate HMAC
        let th1 = self
            .common
            .calc_rsp_transcript_hash(false, slot_id as u8, false, session);
        if th1.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        let th1 = th1.unwrap();
        debug!("!!! th1 : {:02x?}\n", th1.as_ref());

        let session = self.common.get_session_via_id(session_id).unwrap();
        session.generate_handshake_secret(spdm_version_sel, &th1)?;

        if !in_clear_text {
            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            // generate HMAC with finished_key
            let transcript_hash =
                self.common
                    .calc_rsp_transcript_hash(false, slot_id as u8, false, session);
            if transcript_hash.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
            let transcript_hash = transcript_hash.unwrap();

            let session = self.common.get_session_via_id(session_id).unwrap();

            let hmac = session.generate_hmac_with_response_finished_key(transcript_hash.as_ref());
            if hmac.is_err() {
                let _ = session.teardown(session_id);
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
            let hmac = hmac.unwrap();

            // append verify_data after TH1
            if self
                .common
                .append_message_k(session_id, hmac.as_ref())
                .is_err()
            {
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }

            // patch the message before send
            writer.mut_used_slice()
                [(used - base_hash_size - base_asym_size)..(used - base_hash_size)]
                .copy_from_slice(signature.as_ref());
            writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        }

        let heartbeat_period = self.common.config_info.heartbeat_period;
        let session = self.common.get_session_via_id(session_id).unwrap();

        session.heartbeat_period = heartbeat_period;
        if return_opaque.data_size != 0 {
            session.secure_spdm_version_sel =
                return_opaque.data[return_opaque.data_size as usize - 1];
        }

        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        if in_clear_text {
            self.common
                .runtime_info
                .set_last_session_id(Some(session_id));
        }

        Ok(())
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_key_exchange_rsp_signature(
        &self,
        slot_id: u8,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let transcript_hash = self
            .common
            .calc_rsp_transcript_hash(false, slot_id, false, session)?;

        debug!("message_hash - {:02x?}", transcript_hash.as_ref());

        let mut message_sign = ManagedBuffer12Sign::default();
        if self.common.negotiate_info.spdm_version_sel.get_u8()
            >= SpdmVersion::SpdmVersion12.get_u8()
        {
            message_sign.reset_message();
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_2)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(transcript_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message_sign.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_key_exchange_rsp_signature(
        &self,
        slot_id: u8,
        session: &SpdmSession,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let message_hash = self
            .common
            .calc_rsp_transcript_hash(false, slot_id, false, session)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        let mut message = self.common.calc_rsp_transcript_data(
            false,
            slot_id,
            false,
            &session.runtime_info.message_k,
            None,
        )?;
        if self.common.negotiate_info.spdm_version_sel.get_u8()
            >= SpdmVersion::SpdmVersion12.get_u8()
        {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_2)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(message_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crate::secret::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }
}
