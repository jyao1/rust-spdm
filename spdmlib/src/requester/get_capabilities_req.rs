// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_capability(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestGetCapabilities,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: self.common.config_info.req_ct_exponent,
                    flags: self.common.config_info.req_capabilities,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        if self
            .common
            .runtime_info
            .message_a
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseCapabilities => {
                    let capabilities =
                        SpdmCapabilitiesResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(capabilities) = capabilities {
                        debug!("!!! capabilities : {:02x?}\n", capabilities);
                        self.common.negotiate_info.req_ct_exponent_sel =
                            self.common.config_info.req_ct_exponent;
                        self.common.negotiate_info.req_capabilities_sel =
                            self.common.config_info.req_capabilities;
                        self.common.negotiate_info.rsp_ct_exponent_sel = capabilities.ct_exponent;
                        self.common.negotiate_info.rsp_capabilities_sel = capabilities.flags;

                        if self
                            .common
                            .runtime_info
                            .message_a
                            .append_message(&receive_buffer[..used])
                            .is_none()
                        {
                            return spdm_result_err!(ENOMEM);
                        }

                        Ok(())
                    } else {
                        error!("!!! capabilities : fail !!!\n");
                        spdm_result_err!(EFAULT)
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
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_handle_spdm_algorithm() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let data = &mut [17,46,43];
        let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let message_a = [
            0x10, 0x84, 0x00, 0x00, 0x11, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x11,
        ];
        
        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .message_a
            .append_message(&message_a);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.reset_runtime_info();
        requester
            .common
            .runtime_info
            .message_a
            .append_message(&message_a);

        let _ = requester.send_receive_spdm_capability();
    }
}
