// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_capability(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_capability_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_capability_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_capabilities =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_capabilities) = get_capabilities {
            debug!("!!! get_capabilities : {:02x?}\n", get_capabilities);
            self.common.negotiate_info.req_ct_exponent_sel = get_capabilities.ct_exponent;
            self.common.negotiate_info.req_capabilities_sel = get_capabilities.flags;
            self.common.negotiate_info.rsp_ct_exponent_sel =
                self.common.config_info.rsp_ct_exponent;
            self.common.negotiate_info.rsp_capabilities_sel =
                self.common.config_info.rsp_capabilities;
        } else {
            error!("!!! get_capabilities : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        if self
            .common
            .runtime_info
            .message_a
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        info!("send spdm capability\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseCapabilities,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: self.common.config_info.rsp_ct_exponent,
                    flags: self.common.config_info.rsp_capabilities,
                },
            ),
        };
        response.spdm_encode(&mut self.common, writer);

        self.common
            .runtime_info
            .message_a
            .append_message(writer.used_slice());
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};
    #[test]
    fn test_case0_handle_spdm_capability() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);
        let capabilities = &mut [0u8; 1024];
        let mut writer = Writer::init(capabilities);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 100,
            flags: SpdmRequestCapabilityFlags::CERT_CAP,
        };
        value.spdm_encode(&mut context.common, &mut writer);
        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&capabilities[0..1022]);
        context.handle_spdm_capability(bytes);

        let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
            | SpdmResponseCapabilityFlags::ENCAP_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }
        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );
        let capabilities_slice = &u8_slice[2..];
        let mut reader = Reader::init(capabilities_slice);
        let capabilities_request =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(capabilities_request.ct_exponent, 100);
        assert_eq!(
            capabilities_request.flags,
            SpdmRequestCapabilityFlags::CERT_CAP
        );
        let spdm_message_slice = &u8_slice[12..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseCapabilities
        );
        if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0);
            assert_eq!(payload.flags, rsp_capabilities);
        }
    }
}
