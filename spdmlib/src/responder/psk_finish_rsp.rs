// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::INVALID_SLOT;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_finish(&mut self, session_id: u32, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_psk_finish_response(session_id, bytes, &mut writer)?;
        self.send_secured_message(session_id, writer.used_slice(), false)
    }

    // Return true on success, false otherwise
    pub fn write_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> SpdmResult {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            Some(session_id),
        );

        let psk_finish_req = SpdmPskFinishRequestPayload::spdm_read(&mut self.common, &mut reader);

        if let Some(psk_finish_req) = &psk_finish_req {
            debug!("!!! psk_finish req : {:02x?}\n", psk_finish_req);
        } else {
            error!("!!! psk_finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        // Safety to call unwrap()
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;

        let temp_used = read_used - base_hash_size;

        {
            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            if !session.get_use_psk() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }

            if self
                .common
                .append_message_f(false, session_id, &bytes[..temp_used])
                .is_err()
            {
                error!("message_f add the message error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }

            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            let transcript_hash =
                self.common
                    .calc_rsp_transcript_hash(true, INVALID_SLOT, false, session);
            if transcript_hash.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
            let transcript_hash = transcript_hash.as_ref().unwrap();

            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();
            let res = session.verify_hmac_with_request_finished_key(
                transcript_hash.as_ref(),
                &psk_finish_req.verify_data,
            );
            if res.is_err() {
                error!("verify_hmac_with_request_finished_key fail");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorDecryptError, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            } else {
                info!("verify_hmac_with_request_finished_key pass");
            }

            if self
                .common
                .append_message_f(false, session_id, psk_finish_req.verify_data.as_ref())
                .is_err()
            {
                error!("message_f add the message error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
        }

        info!("send spdm psk_finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        if self
            .common
            .append_message_f(false, session_id, writer.used_slice())
            .is_err()
        {
            error!("message_f add the message error");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        // generate the data secret
        let th2 = self
            .common
            .calc_rsp_transcript_hash(true, 0, false, session);
        if th2.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        }
        // Safely to call unwrap;
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.generate_data_secret(spdm_version_sel, &th2)
    }
}
