// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_vendor_defined_request(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_vendor_defined_response(session_id, bytes, &mut writer);
        match session_id {
            Some(session_id) => self.send_secured_message(session_id, writer.used_slice(), false),
            None => self.send_message(writer.used_slice()),
        }
    }

    pub fn write_spdm_vendor_defined_response(
        &mut self,
        session_id: Option<u32>,
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
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            session_id,
        );

        let vendor_defined_request_payload =
            SpdmVendorDefinedRequestPayload::spdm_read(&mut self.common, &mut reader);
        if vendor_defined_request_payload.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let vendor_defined_request_payload = vendor_defined_request_payload.unwrap();

        let standard_id = vendor_defined_request_payload.standard_id;
        let vendor_id = vendor_defined_request_payload.vendor_id;
        let req_payload = vendor_defined_request_payload.req_payload;
        let rsp_payload =
            self.respond_to_vendor_defined_request(&req_payload, vendor_defined_request_handler);
        if rsp_payload.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        let rsp_payload = rsp_payload.unwrap();
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedResponse(
                SpdmVendorDefinedResponsePayload {
                    standard_id,
                    vendor_id,
                    rsp_payload,
                },
            ),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
        }
    }

    pub fn respond_to_vendor_defined_request<F>(
        &mut self,
        req: &VendorDefinedReqPayloadStruct,
        verdor_defined_func: F,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct>
    where
        F: Fn(&VendorDefinedReqPayloadStruct) -> SpdmResult<VendorDefinedRspPayloadStruct>,
    {
        verdor_defined_func(req)
    }
}
