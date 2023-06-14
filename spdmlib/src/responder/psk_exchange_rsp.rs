// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::common::SpdmOpaqueSupport;
use crate::common::INVALID_SLOT;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::SPDM_STATUS_INVALID_STATE_PEER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use config::MAX_SPDM_PSK_CONTEXT_SIZE;
extern crate alloc;
use crate::secret;
use alloc::boxed::Box;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_exchange(&mut self, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_psk_exchange_response(bytes, &mut writer)?;
        self.send_message(writer.used_slice())
    }

    pub fn write_spdm_psk_exchange_response(
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
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestPskExchange, None);

        let psk_exchange_req =
            SpdmPskExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);

        let mut return_opaque = SpdmOpaqueStruct::default();

        let measurement_summary_hash;
        let psk_hint;
        if let Some(psk_exchange_req) = &psk_exchange_req {
            debug!("!!! psk_exchange req : {:02x?}\n", psk_exchange_req);

            if (psk_exchange_req.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (psk_exchange_req.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
                let measurement_summary_hash_res =
                    secret::measurement::generate_measurement_summary_hash(
                        self.common.negotiate_info.spdm_version_sel,
                        self.common.negotiate_info.base_hash_sel,
                        self.common.negotiate_info.measurement_specification_sel,
                        self.common.negotiate_info.measurement_hash_sel,
                        psk_exchange_req.measurement_summary_hash_type,
                    );
                if measurement_summary_hash_res.is_none() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return Err(SPDM_STATUS_CRYPTO_ERROR);
                }
                measurement_summary_hash = measurement_summary_hash_res.unwrap();
                if measurement_summary_hash.data_size == 0 {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return Err(SPDM_STATUS_CRYPTO_ERROR);
                }
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
                measurement_summary_hash = SpdmDigestStruct::default();
            }

            psk_hint = psk_exchange_req.psk_hint.clone();

            if let Some(secured_message_version_list) = psk_exchange_req
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
            error!("!!! psk_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let psk_without_context = self
            .common
            .negotiate_info
            .rsp_capabilities_sel
            .contains(SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT);
        let psk_context_size = if psk_without_context {
            0u16
        } else {
            MAX_SPDM_PSK_CONTEXT_SIZE as u16
        };
        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        if psk_without_context {
            let res = crypto::rand::get_random(&mut psk_context);
            if res.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
        }

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

        let session = self.common.get_next_avaiable_session();
        if session.is_none() {
            error!("!!! too many sessions : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorSessionLimitExceeded, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        let session = session.unwrap();
        let session_id =
            ((rsp_session_id as u32) << 16) + psk_exchange_req.unwrap().req_session_id as u32;
        session.setup(session_id).unwrap();
        session.set_use_psk(true);

        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_transport_param(sequence_number_count, max_random_count);

        session.runtime_info.psk_hint = Some(psk_hint);
        session.runtime_info.message_a = message_a;
        session.runtime_info.rsp_cert_hash = None;
        session.runtime_info.req_cert_hash = None;

        info!("send spdm psk_exchange rsp\n");

        // prepare response
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload {
                heartbeat_period: self.common.config_info.heartbeat_period,
                rsp_session_id,
                measurement_summary_hash,
                psk_context: SpdmPskContextStruct {
                    data_size: psk_context_size,
                    data: psk_context,
                },
                opaque: return_opaque.clone(),
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

        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = used - base_hash_size;

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

        // create session - generate the handshake secret (including finished_key)
        let th1 = self
            .common
            .calc_rsp_transcript_hash(true, INVALID_SLOT, false, session);
        if th1.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        let th1 = th1.unwrap();
        debug!("!!! th1 : {:02x?}\n", th1.as_ref());

        let session = self.common.get_session_via_id(session_id).unwrap();
        session.generate_handshake_secret(spdm_version_sel, &th1)?;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        // generate HMAC with finished_key
        let transcript_hash =
            self.common
                .calc_rsp_transcript_hash(true, INVALID_SLOT, false, session);
        if transcript_hash.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        let transcript_hash = transcript_hash.unwrap();

        let hmac = session.generate_hmac_with_response_finished_key(transcript_hash.as_ref());
        if hmac.is_err() {
            let session = self.common.get_session_via_id(session_id).unwrap();
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
        writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        let heartbeat_period = self.common.config_info.heartbeat_period;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        if psk_without_context {
            // generate the data secret directly to skip PSK_FINISH
            let th2 = self
                .common
                .calc_rsp_transcript_hash(true, 0, false, session);
            if th2.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
            let th2 = th2.unwrap();
            debug!("!!! th2 : {:02x?}\n", th2.as_ref());
            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
            let session = self.common.get_session_via_id(session_id).unwrap();
            session
                .generate_data_secret(spdm_version_sel, &th2)
                .unwrap();
            session.set_session_state(
                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
            );
        }

        let session = self.common.get_session_via_id(session_id).unwrap();
        session.heartbeat_period = heartbeat_period;
        if return_opaque.data_size != 0 {
            session.secure_spdm_version_sel =
                return_opaque.data[return_opaque.data_size as usize - 1];
        }

        Ok(())
    }
}
