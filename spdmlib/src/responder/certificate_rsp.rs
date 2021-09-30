// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_certificate(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_certificate_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_certificate_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_certificate =
            SpdmGetCertificateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_certificate) = get_certificate {
            debug!("!!! get_certificate : {:02x?}\n", get_certificate);
        } else {
            error!("!!! get_certificate : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        if self
            .common
            .runtime_info
            .message_b
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let get_certificate = get_certificate.unwrap();
        let slot_id = get_certificate.slot_id;

        let my_cert_chain = self.common.provision_info.my_cert_chain.unwrap();

        let mut length = get_certificate.length;
        if length > config::MAX_SPDM_CERT_PORTION_LEN as u16 {
            length = config::MAX_SPDM_CERT_PORTION_LEN as u16;
        }

        let offset = get_certificate.offset;
        if offset > my_cert_chain.data_size {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        if length > my_cert_chain.data_size - offset {
            length = my_cert_chain.data_size - offset;
        }

        let portion_length = length as u16;
        let remainder_length = my_cert_chain.data_size - (length + offset);

        let cert_chain_data =
            &my_cert_chain.data[(offset as usize)..(offset as usize + length as usize)];

        info!("send spdm certificate\n");
        let mut cert_chain = [0u8; config::MAX_SPDM_CERT_PORTION_LEN];
        cert_chain[..cert_chain_data.len()].copy_from_slice(cert_chain_data);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id,
                portion_length,
                remainder_length,
                cert_chain,
            }),
        };
        response.spdm_encode(&mut self.common, writer);

        self.common
            .runtime_info
            .message_b
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
    fn test_case0_handle_spdm_certificate() {
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
        context.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);
        let capabilities = &mut [0u8; 1024];
        let mut writer = Writer::init(capabilities);
        let value = SpdmGetCertificateRequestPayload {
            slot_id: 100,
            offset: 100,
            length: 600,
        };
        value.spdm_encode(&mut context.common, &mut writer);
        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&capabilities[0..1022]);
        context.handle_spdm_certificate(bytes);

        let data = context.common.runtime_info.message_b.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let spdm_get_certificate_request_payload =
            SpdmGetCertificateRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 100);
        assert_eq!(spdm_get_certificate_request_payload.offset, 100);
        assert_eq!(spdm_get_certificate_request_payload.length, 600);

        let spdm_message_slice = &u8_slice[8..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseCertificate
        );
        if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.portion_length, 412);
            assert_eq!(payload.remainder_length, 0);
            for i in 0..412 {
                assert_eq!(payload.cert_chain[i], 0u8);
            }
        }
    }
}
