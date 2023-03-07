// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
use crate::error::SpdmResult;
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_vendor_defined_request(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);
        let vendor_defined_request_payload =
            SpdmVendorDefinedRequestPayload::spdm_read(&mut self.common, &mut reader).unwrap();
        let standard_id = vendor_defined_request_payload.standard_id;
        let vendor_id = vendor_defined_request_payload.vendor_id;
        let req_payload = vendor_defined_request_payload.req_payload;
        let rsp_payload = self
            .respond_to_vendor_defined_request(&req_payload, vendor_defined_request_handler)
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
        let _ = self.send_secured_message(
            session_id,
            &send_buffer[..used],
            true,
            transport_encap,
            device_io,
        );
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

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::crypto;
    use crate::testlib::*;

    #[test]
    fn test_case0_handle_spdm_vendor_defined_request() {
        let (rsp_config_info, rsp_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = ResponderContext::new(rsp_config_info, rsp_provision_info);

        let req = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let vendor_defined_func: for<'r> fn(
            &'r vendor::VendorDefinedReqPayloadStruct,
        ) -> Result<_, _> =
            |_vendor_defined_req_payload_struct| -> SpdmResult<VendorDefinedRspPayloadStruct> {
                let mut vendor_defined_res_payload_struct = VendorDefinedRspPayloadStruct {
                    rsp_length: 0,
                    vendor_defined_rsp_payload: [0; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
                };
                vendor_defined_res_payload_struct.rsp_length = 8;
                vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0..8]
                    .clone_from_slice(b"deadbeef");
                Ok(vendor_defined_res_payload_struct)
            };

        register_vendor_defined_struct(VendorDefinedStruct {
            vendor_defined_request_handler: vendor_defined_func,
        });

        if let Ok(vendor_defined_res_payload_struct) =
            responder.respond_to_vendor_defined_request(&req, vendor_defined_request_handler)
        {
            assert_eq!(vendor_defined_res_payload_struct.rsp_length, 8);
            assert_eq!(
                vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0],
                b'd'
            );
        } else {
            assert!(false, "Not expected result!");
        }
    }
}
