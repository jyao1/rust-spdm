// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_heartbeat(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm heartbeat\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestHeartbeat,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_secured_message(session_id, &send_buffer[..used])?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_secured_message(session_id, &mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseHeartbeatAck => {
                    let heartbeat_rsp =
                        SpdmHeartbeatResponsePayload::spdm_read(&mut self.common, &mut reader);
                    if let Some(heartbeat_rsp) = heartbeat_rsp {
                        debug!("!!! heartbeat rsp : {:02x?}\n", heartbeat_rsp);
                        Ok(())
                    } else {
                        error!("!!! heartbeat : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
