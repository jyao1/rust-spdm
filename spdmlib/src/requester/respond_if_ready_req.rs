// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::*;
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn spdm_requester_respond_if_ready(
        &mut self,
        expected_response_code: SpdmRequestResponseCode,
        extend_error_data: SpdmErrorResponseNotReadyExtData,
    ) -> SpdmResult<ReceivedMessage> {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestResponseIfReady,
            },
            payload: SpdmMessagePayload::SpdmMessageGeneral(SpdmMessageGeneralPayload {
                param1: extend_error_data.request_code,
                param2: extend_error_data.token,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);

        let used = writer.used();
        self.send_message(&send_buffer[..used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;

        //Have a sanity check!
        let mut reader = Reader::init(&receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.request_response_code == expected_response_code {
                    Ok(ReceivedMessage {
                        receive_buffer,
                        used,
                    })
                } else {
                    spdm_result_err!(EDEV)
                }
            }
            None => {
                spdm_result_err!(EDEV)
            }
        }
    }
}
