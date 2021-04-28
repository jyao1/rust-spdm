// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_end_session(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let end_session_req =
            SpdmEndSessionRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(end_session_req) = end_session_req {
            debug!("!!! end_session req : {:02x?}\n", end_session_req);
        } else {
            error!("!!! end_session req : fail !!!\n");
            return;
        }

        info!("send spdm end_session rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[0..used]);
    }
}
