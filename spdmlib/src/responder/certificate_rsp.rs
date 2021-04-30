// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_certificate(&mut self, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_certificate =
            SpdmGetCertificateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_certificate) = get_certificate {
            debug!("!!! get_certificate : {:02x?}\n", get_certificate);
        } else {
            error!("!!! get_certificate : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        if self
            .common
            .runtime_info
            .message_b
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
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
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
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
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

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
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_message(&send_buffer[0..used]);

        self.common
            .runtime_info
            .message_b
            .append_message(&send_buffer[..used]);
    }
}
