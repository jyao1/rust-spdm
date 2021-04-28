// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::responder::*;

use crate::common::ManagedBuffer;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_finish(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let psk_finish_req = SpdmPskFinishRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(psk_finish_req) = psk_finish_req {
            debug!("!!! psk_finish req : {:02x?}\n", psk_finish_req);
        } else {
            error!("!!! psk_finish req : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        let mut message_f = ManagedBuffer::default();
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        let session = self.common.get_session_via_id(session_id).unwrap();
        let message_k = session.runtime_info.message_k;

        let transcript_data =
            self.common
                .calc_rsp_transcript_data(true, &message_k, Some(&message_f));
        if transcript_data.is_err() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let transcript_data = transcript_data.unwrap();
        let session = self.common.get_session_via_id(session_id).unwrap();
        if session
            .verify_hmac_with_request_finished_key(
                transcript_data.as_ref(),
                &psk_finish_req.verify_data,
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
            .append_message(psk_finish_req.verify_data.as_ref())
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        info!("send spdm psk_finish rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        if message_f.append_message(&send_buffer[..used]).is_none() {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            let session = self.common.get_session_via_id(session_id).unwrap();
            let _ = session.teardown(session_id);
            return;
        }
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.runtime_info.message_f = message_f;

        // generate the data secret
        let th2 = self
            .common
            .calc_rsp_transcript_hash(true, &message_k, Some(&message_f));
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
