// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_heartbeat(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let heartbeat_req = SpdmHeartbeatRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(heartbeat_req) = heartbeat_req {
            debug!("!!! heartbeat req : {:02x?}\n", heartbeat_req);
        } else {
            error!("!!! heartbeat req : fail !!!\n");
            return;
        }

        info!("send spdm heartbeat rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseHeartbeatAck,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload {}),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[0..used]);
    }
}
