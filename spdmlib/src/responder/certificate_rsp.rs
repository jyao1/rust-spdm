// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::error::SpdmResult;
use crate::message::*;
use crate::protocol::SPDM_MAX_SLOT_NUMBER;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_certificate(&mut self, bytes: &[u8], session_id: Option<u32>) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_certificate_response(session_id, bytes, &mut writer);

        if let Some(session_id) = session_id {
            self.send_secured_message(session_id, writer.used_slice(), false)
        } else {
            self.send_message(writer.used_slice())
        }
    }

    fn write_spdm_certificate_response(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &mut Writer,
    ) {
        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionNegotiated.get_u8()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return;
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            session_id,
        );

        let get_certificate =
            SpdmGetCertificateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_certificate) = &get_certificate {
            debug!("!!! get_certificate : {:02x?}\n", get_certificate);
            if get_certificate.slot_id != 0 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return;
            }
        } else {
            error!("!!! get_certificate : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        match session_id {
            None => {
                if self
                    .common
                    .append_message_b(&bytes[..reader.used()])
                    .is_err()
                {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return;
                }
            }
            Some(_session_id) => {}
        }

        let get_certificate = get_certificate.unwrap();
        let slot_id = get_certificate.slot_id as usize;
        if slot_id >= SPDM_MAX_SLOT_NUMBER {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        if self.common.provision_info.my_cert_chain[slot_id].is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let my_cert_chain = self.common.provision_info.my_cert_chain[slot_id]
            .as_ref()
            .unwrap();

        let mut length = get_certificate.length;
        if length > MAX_SPDM_CERT_PORTION_LEN as u16 {
            length = MAX_SPDM_CERT_PORTION_LEN as u16;
        }

        let offset = get_certificate.offset;
        if offset > my_cert_chain.data_size {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        if length > my_cert_chain.data_size - offset {
            length = my_cert_chain.data_size - offset;
        }

        let portion_length = length;
        let remainder_length = my_cert_chain.data_size - (length + offset);

        let cert_chain_data =
            &my_cert_chain.data[(offset as usize)..(offset as usize + length as usize)];
        let mut cert_chain = [0u8; MAX_SPDM_CERT_PORTION_LEN];
        cert_chain[..cert_chain_data.len()].copy_from_slice(cert_chain_data);

        info!("send spdm certificate\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id: slot_id as u8,
                portion_length,
                remainder_length,
                cert_chain,
            }),
        };
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        match session_id {
            None => {
                if self.common.append_message_b(writer.used_slice()).is_err() {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                }
            }
            Some(_session_id) => {}
        }
    }
}
