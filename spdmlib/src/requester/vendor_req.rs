// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_spdm_vendor_defined_request(
        &mut self,
        session_id: u32,
        StandardID: RegistryOrStandardsBodyID,
        VendorIDStruct: VendorIDStruct,
        ReqPayloadStruct: ReqPayloadStruct,
    ) -> SpdmResult<ResPayloadStruct> {
        info!("send vendor defined request\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedRequest(
                SpdmVendorDefinedRequestPayload {
                    StandardID,
                    VendorIDStruct,
                    ReqPayloadStruct,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        self.send_secured_message(session_id, &send_buffer[..used])?;

        //receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let receive_used = self.receive_secured_message(session_id, &mut receive_buffer)?;
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestVendorDefinedResponse => {
                    let (standardID, VendorIDStruct, ResPayloadStruct) =
                        SpdmVendorDefinedResponsePayload::spdm_read(&mut self.common, &mut reader);
                    return Ok(ResPayloadStruct);
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
