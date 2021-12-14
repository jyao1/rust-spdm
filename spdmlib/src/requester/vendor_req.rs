// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::*;
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_spdm_vendor_defined_request(
        &mut self,
        session_id: u32,
        standard_id: RegistryOrStandardsBodyID,
        vendor_idstruct: VendorIDStruct,
        req_payload_struct: ReqPayloadStruct,
    ) -> SpdmResult<ResPayloadStruct> {
        info!("send vendor defined request\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedRequest(
                SpdmVendorDefinedRequestPayload {
                    standard_id,
                    vendor_id: vendor_idstruct,
                    req_payload: req_payload_struct,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        self.send_secured_message(session_id, &send_buffer[..used], true)?;

        //receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let _receive_used = self.receive_secured_message(session_id, &mut receive_buffer)?;
        let mut reader = Reader::init(&receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse => {
                    match SpdmVendorDefinedResponsePayload::spdm_read(&mut self.common, &mut reader)
                    {
                        Some(SpdmVendorDefinedResponsePayload {
                            standard_id: _,
                            vendor_id: _,
                            res_payload,
                        }) => Ok(res_payload),
                        None => spdm_result_err!(EFAULT),
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::crypto;
    use crate::responder::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_send_spdm_vendor_defined_request() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let session_id: u32 = 0xff;
        let standard_id: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::DMTF;
        let vendor_idstruct: VendorIDStruct = VendorIDStruct {
            len: 0,
            vendor_id: [0u8; config::MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
        };
        let req_payload_struct: ReqPayloadStruct = ReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let status = requester
            .send_spdm_vendor_defined_request(
                session_id,
                standard_id,
                vendor_idstruct,
                req_payload_struct,
            )
            .is_ok();
        assert_eq!(status, false); //since vendor defined response payload is not implemented, so false is expected here.
    }
}
