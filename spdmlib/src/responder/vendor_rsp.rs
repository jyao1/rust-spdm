// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![allow(non_snake_case)]
use crate::common::error::{SpdmError, SpdmErrorNum, SpdmResult};
use crate::responder::*;
use crate::message::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_vendor_defined_request(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);
        let vendor_defined_request_payload =
            SpdmVendorDefinedRequestPayload::spdm_read(&mut self.common, &mut reader).unwrap();
        let StandardID = vendor_defined_request_payload.StandardID;
        let VendorID = vendor_defined_request_payload.VendorID;
        let ReqPayload = vendor_defined_request_payload.ReqPayload;
        let ResPayload = self.respond_to_vendor_defined_request(&ReqPayload).unwrap();
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedResponse(
                SpdmVendorDefinedResponsePayload {
                    StandardID,
                    VendorID,
                    ResPayload,
                },
            ),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[..used], true);
    }

    #[allow(dead_code)]
    pub fn respond_to_vendor_defined_request(
        &mut self,
        _req: &ReqPayloadStruct,
    ) -> SpdmResult<ResPayloadStruct> {
        //Vendor to define reponse to request by vendor defined protocol, which is unkown to us.
        Err(SpdmError::new(
            SpdmErrorNum::EUNDEF,
            "spdmlib/src/responder/vendor_rsp.rs",
            51,
            0,
            "Not Implemented yet!",
        ))
    }
}
