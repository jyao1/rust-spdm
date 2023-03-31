// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_spdm_vendor_defined_request(
        &mut self,
        session_id: Option<u32>,
        standard_id: RegistryOrStandardsBodyID,
        vendor_id_struct: VendorIDStruct,
        req_payload_struct: VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        info!("send vendor defined request\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
            },
            payload: SpdmMessagePayload::SpdmVendorDefinedRequest(
                SpdmVendorDefinedRequestPayload {
                    standard_id,
                    vendor_id: vendor_id_struct,
                    req_payload: req_payload_struct,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        match session_id {
            Some(session_id) => {
                self.send_secured_message(session_id, &send_buffer[..used], false)?;
            }
            None => {
                self.send_message(&send_buffer[..used])?;
            }
        }

        //receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let receive_used = match session_id {
            Some(session_id) => {
                self.receive_secured_message(session_id, &mut receive_buffer, false)?
            }
            None => self.receive_message(&mut receive_buffer, false)?,
        };

        self.handle_spdm_vendor_defined_respond(session_id, &receive_buffer[..receive_used])
    }

    pub fn handle_spdm_vendor_defined_respond(
        &mut self,
        session_id: Option<u32>,
        receive_buffer: &[u8],
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse => {
                        match SpdmVendorDefinedResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        ) {
                            Some(spdm_vendor_defined_response_payload) => {
                                Ok(spdm_vendor_defined_response_payload.rsp_payload)
                            }
                            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let rm = self.spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest,
                            SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse,
                        )?;
                        let receive_buffer = rm.receive_buffer;
                        let used = rm.used;
                        self.handle_spdm_vendor_defined_respond(session_id, &receive_buffer[..used])
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}

#[cfg(all(test,))]
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

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

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
        let req_payload_struct: VendorDefinedReqPayloadStruct = VendorDefinedReqPayloadStruct {
            req_length: 0,
            vendor_defined_req_payload: [0u8; MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
        };

        let status = requester
            .send_spdm_vendor_defined_request(
                Some(session_id),
                standard_id,
                vendor_idstruct,
                req_payload_struct,
            )
            .is_ok();
        assert_eq!(status, false); //since vendor defined response payload is not implemented, so false is expected here.
    }
}
