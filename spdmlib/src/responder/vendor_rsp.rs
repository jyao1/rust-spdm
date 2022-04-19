// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::{SpdmError, SpdmErrorNum, SpdmResult};
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_vendor_defined_request(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);
        let vendor_defined_request_payload =
            SpdmVendorDefinedRequestPayload::spdm_read(&mut self.common, &mut reader).unwrap();
        let standard_id = vendor_defined_request_payload.standard_id;
        let vendor_id = vendor_defined_request_payload.vendor_id;
        let req_payload = vendor_defined_request_payload.req_payload;
        let rsp_payload = self
            .respond_to_vendor_defined_request(&req_payload)
            .unwrap();
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

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
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[..used], true);
    }

    #[allow(dead_code)]
    pub fn respond_to_vendor_defined_request(
        &mut self,
        _req: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        //Vendor to define reponse to request by vendor defined protocol, which is unkown to us.
        Err(SpdmError::new(
            SpdmErrorNum::EUNDEF,
            "spdmlib/src/responder/vendor_rsp.rs",
            line!(),
            column!(),
            "Not Implemented yet!",
        ))
    }
}

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::crypto;
    use crate::testlib::*;

    #[test]
    #[should_panic(expected = "Not Implemented yet!")]
    fn test_case0_handle_spdm_vendor_defined_request() {
        let (rsp_config_info, rsp_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let session_id: u32 = 0xff;
        let bytes: [u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE] =
            [0u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];

        responder.handle_spdm_vendor_defined_request(session_id, &bytes); //since vendor defined response payload is not implemented, so panic is expected here.
    }
}
