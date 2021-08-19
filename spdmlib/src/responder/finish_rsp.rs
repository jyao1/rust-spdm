// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

use crate::common::ManagedBuffer;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_finish(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let finish_req = SpdmFinishRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(finish_req) = finish_req {
            debug!("!!! finish req : {:02x?}\n", finish_req);
        } else {
            error!("!!! finish req : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let finish_req = finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        let mut message_f = ManagedBuffer::default();
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            panic!("message_f add the message error");
        }

        let session = self.common.get_session_via_id(session_id).unwrap();
        let message_k = session.runtime_info.message_k;

        let transcript_data =
            self.common
                .calc_rsp_transcript_data(false, &message_k, Some(&message_f));
        if transcript_data.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let transcript_data = transcript_data.unwrap();
        let session = self.common.get_session_via_id(session_id).unwrap();
        if session
            .verify_hmac_with_request_finished_key(
                transcript_data.as_ref(),
                &finish_req.verify_data,
            )
            .is_err()
        {
            error!("verify_hmac_with_request_finished_key fail");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        } else {
            info!("verify_hmac_with_request_finished_key pass");
        }
        if message_f
            .append_message(finish_req.verify_data.as_ref())
            .is_none()
        {
            panic!("message_f add the message error");
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

        info!("send spdm finish rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(SpdmFinishResponsePayload {
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: [0xcc; SPDM_MAX_HASH_SIZE],
                },
            }),
        };

        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        if in_clear_text {
            // generate HMAC with finished_key
            let temp_used = used - base_hash_size;
            if message_f
                .append_message(&send_buffer[..temp_used])
                .is_none()
            {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                return;
            }

            let transcript_data =
                self.common
                    .calc_rsp_transcript_data(false, &message_k, Some(&message_f));
            if transcript_data.is_err() {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                return;
            }
            let transcript_data = transcript_data.unwrap();

            let session = self.common.get_session_via_id(session_id).unwrap();
            let hmac = session.generate_hmac_with_response_finished_key(transcript_data.as_ref());
            if hmac.is_err() {
                let _ = session.teardown(session_id);
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
            let hmac = hmac.unwrap();
            if message_f.append_message(hmac.as_ref()).is_none() {
                let _ = session.teardown(session_id);
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
            session.runtime_info.message_f = message_f;

            // patch the message before send
            send_buffer[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        } else {
            if message_f.append_message(&send_buffer[..used]).is_none() {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                return;
            }
            let session = self.common.get_session_via_id(session_id).unwrap();
            session.runtime_info.message_f = message_f;
        }

        // generate the data secret
        let th2 = self
            .common
            .calc_rsp_transcript_hash(false, &message_k, Some(&message_f));
        if th2.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            let session = self.common.get_session_via_id(session_id).unwrap();
            let _ = session.teardown(session_id);
            return;
        }
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.generate_data_secret(&th2).unwrap();

        let _ = self.send_secured_message(session_id, &send_buffer[0..used]);
        let session = self.common.get_session_via_id(session_id).unwrap();
        // change state after message is sent.
        session.set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);
    }
}
