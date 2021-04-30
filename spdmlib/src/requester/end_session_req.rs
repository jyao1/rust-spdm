// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_end_session(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm end_session\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
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
                SpdmResponseResponseCode::SpdmResponseEndSessionAck => {
                    let end_session_rsp =
                        SpdmEndSessionResponsePayload::spdm_read(&mut self.common, &mut reader);
                    if let Some(end_session_rsp) = end_session_rsp {
                        debug!("!!! end_session rsp : {:02x?}\n", end_session_rsp);

                        let session = self.common.get_session_via_id(session_id).unwrap();
                        session.teardown(session_id)?;

                        Ok(())
                    } else {
                        error!("!!! end_session : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
