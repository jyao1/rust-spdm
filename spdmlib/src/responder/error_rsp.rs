// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn write_spdm_error(
        &mut self,
        error_code: SpdmErrorCode,
        error_data: u8,
        writer: &mut Writer,
    ) {
        let error = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code,
                error_data,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                    SpdmErrorResponseNoneExtData {},
                ),
            }),
        };
        let _ = error.spdm_encode(&mut self.common, writer);
    }

    pub fn send_spdm_error(&mut self, error_code: SpdmErrorCode, error_data: u8) {
        info!("send spdm version\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_error(error_code, error_data, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }
}

impl<'a> ResponderContext<'a> {
    pub fn handle_error_request(
        &mut self,
        error_code: SpdmErrorCode,
        session_id: Option<u32>,
        bytes: &[u8],
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_error_response(error_code, bytes, &mut writer);
        if let Some(session_id) = session_id {
            self.send_secured_message(session_id, writer.used_slice(), false)
        } else {
            self.send_message(writer.used_slice())
        }
    }

    pub fn write_error_response(
        &mut self,
        error_code: SpdmErrorCode,
        bytes: &[u8],
        writer: &mut Writer,
    ) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
            let error_data = if error_code == SpdmErrorCode::SpdmErrorUnsupportedRequest {
                message_header.request_response_code.get_u8()
            } else {
                0u8
            };
            self.write_spdm_error(error_code, error_data, writer);
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
        }
    }
}
