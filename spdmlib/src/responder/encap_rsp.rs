// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::{Codec, Reader, Writer};

use crate::{
    common::{SpdmCodec, SpdmConnectionState},
    config,
    error::{SpdmResult, SPDM_STATUS_NOT_READY_PEER, SPDM_STATUS_UNSUPPORTED_CAP},
    message::{
        SpdmDeliverEncapsulatedResponsePayload, SpdmEncapsulatedRequestPayload,
        SpdmEncapsulatedResponseAckPayload, SpdmEncapsulatedResponseAckPayloadType, SpdmErrorCode,
        SpdmMessage, SpdmMessageHeader, SpdmMessagePayload, SpdmRequestResponseCode,
    },
    protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmVersion},
};

use super::ResponderContext;

impl<'a> ResponderContext<'a> {
    pub fn handle_get_encapsulated_request(&mut self, session_id: u32, bytes: &[u8]) -> SpdmResult {
        self.encap_check_version_cap_state(
            SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest.get_u8(),
        );

        let mut reader = Reader::init(bytes);
        if let Some(request_header) = SpdmMessageHeader::read(&mut reader) {
            if request_header.version != self.common.negotiate_info.spdm_version_sel {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0);
                return Ok(());
            }
        } else {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return Ok(());
        };

        let encapsulated_request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedRequest,
            },
            payload: SpdmMessagePayload::SpdmEncapsulatedRequestPayload(
                SpdmEncapsulatedRequestPayload {
                    request_id: self.common.encap_context.request_id,
                },
            ),
        };

        let mut response = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response);
        let _ = encapsulated_request.spdm_encode(&mut self.common, &mut writer)?;

        self.encode_encap_request_get_digest(&mut writer)?;
        self.send_secured_message(session_id, writer.used_slice(), false)
    }

    pub fn handle_deliver_encapsulated_reponse(
        &mut self,
        session_id: u32,
        bytes: &[u8],
    ) -> SpdmResult {
        self.encap_check_version_cap_state(
            SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest.get_u8(),
        );

        let mut reader = Reader::init(bytes);
        if let Some(request_header) = SpdmMessageHeader::read(&mut reader) {
            if request_header.version != self.common.negotiate_info.spdm_version_sel {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0);
                return Ok(());
            }
        } else {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return Ok(());
        };

        let encap_response_payload = if let Some(encap_response_payload) =
            SpdmDeliverEncapsulatedResponsePayload::spdm_read(&mut self.common, &mut reader)
        {
            encap_response_payload
        } else {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return Ok(());
        };

        let mut encap_response_ack = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut encap_response_ack);
        self.process_encapsulated_response(
            &encap_response_payload,
            &bytes[reader.used()..],
            &mut writer,
        );
        self.send_secured_message(session_id, writer.used_slice(), false)
    }

    fn encap_check_version_cap_state(&mut self, request_response_code: u8) {
        if self.common.negotiate_info.spdm_version_sel.get_u8()
            < SpdmVersion::SpdmVersion11.get_u8()
        {
            self.send_spdm_error(
                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                request_response_code,
            )
        }

        if !self
            .common
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::ENCAP_CAP)
            || !self
                .common
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::ENCAP_CAP)
        {
            self.send_spdm_error(
                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                request_response_code,
            );
            return;
        }

        if self.common.runtime_info.get_connection_state().get_u8()
            < SpdmConnectionState::SpdmConnectionAfterCertificate.get_u8()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0);
        }
    }

    fn process_encapsulated_response(
        &mut self,
        encap_response_payload: &SpdmDeliverEncapsulatedResponsePayload,
        encap_response: &[u8],
        encap_response_ack: &mut Writer,
    ) {
        let mut reader = Reader::init(encap_response);
        let deliver_encap_response = if let Some(header) = SpdmMessageHeader::read(&mut reader) {
            if header.version != self.common.negotiate_info.spdm_version_sel {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0);
                return;
            }
            header
        } else {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        };

        let header = SpdmMessageHeader {
            version: self.common.negotiate_info.spdm_version_sel,
            request_response_code: SpdmRequestResponseCode::SpdmResponseEncapsulatedResponseAck,
        };
        let _ = header.encode(encap_response_ack);

        let mut ack_params = SpdmEncapsulatedResponseAckPayload {
            request_id: self.common.encap_context.request_id,
            payload_type: SpdmEncapsulatedResponseAckPayloadType::Present,
            ack_request_id: encap_response_payload.request_id,
        };

        match deliver_encap_response.request_response_code {
            SpdmRequestResponseCode::SpdmResponseDigests => {
                if self.handle_encap_response_digest(encap_response).is_err() {
                    self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                    return;
                }

                let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack);
                if self
                    .encode_encap_requst_get_certificate(encap_response_ack)
                    .is_err()
                {
                    self.send_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0);
                }
            }
            SpdmRequestResponseCode::SpdmResponseCertificate => {
                match self.handle_encap_response_certificate(encap_response) {
                    Ok(need_continue) => {
                        if need_continue {
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack);
                            if self
                                .encode_encap_requst_get_certificate(encap_response_ack)
                                .is_err()
                            {
                                self.send_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0);
                            }
                        } else {
                            ack_params.payload_type =
                                SpdmEncapsulatedResponseAckPayloadType::ReqSlotNumber;
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack);
                            let _ = self
                                .common
                                .encap_context
                                .req_slot_id
                                .encode(encap_response_ack);
                        }
                    }
                    Err(e) => {
                        if e == SPDM_STATUS_NOT_READY_PEER {
                            ack_params.payload_type =
                                SpdmEncapsulatedResponseAckPayloadType::Absent;
                            let _ = ack_params.spdm_encode(&mut self.common, encap_response_ack);
                        }
                        self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidResponseCode, 0);
                    }
                }
            }
            _ => {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidResponseCode, 0);
            }
        };
    }

    pub fn handle_encap_error_response_main(&self, error_code: u8) -> SpdmResult {
        if error_code == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() {
            return Err(SPDM_STATUS_NOT_READY_PEER);
        }

        Err(SPDM_STATUS_UNSUPPORTED_CAP)
    }
}
