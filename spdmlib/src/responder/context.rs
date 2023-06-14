// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::app_message_handler::dispatch_secured_app_message_cb;
use crate::common::SpdmConnectionState;
use crate::common::{session::SpdmSessionState, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::{SpdmResult, SPDM_STATUS_UNSUPPORTED_CAP};
use crate::message::*;
use crate::protocol::{SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags};
use codec::{Codec, Reader, Writer};

pub struct ResponderContext<'a> {
    pub common: crate::common::SpdmContext<'a>,
}

impl<'a> ResponderContext<'a> {
    pub fn new(
        device_io: &'a mut dyn SpdmDeviceIo,
        transport_encap: &'a mut dyn SpdmTransportEncap,
        config_info: crate::common::SpdmConfigInfo,
        provision_info: crate::common::SpdmProvisionInfo,
    ) -> Self {
        ResponderContext {
            common: crate::common::SpdmContext::new(
                device_io,
                transport_encap,
                config_info,
                provision_info,
            ),
        }
    }

    pub fn send_message(&mut self, send_buffer: &[u8]) -> SpdmResult {
        if self.common.negotiate_info.req_data_transfer_size_sel != 0
            && (send_buffer.len() > self.common.negotiate_info.req_data_transfer_size_sel as usize)
        {
            let mut err_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
            let mut writer = Writer::init(&mut err_buffer);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, &mut writer);
            return self.send_message(writer.used_slice());
        }
        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = self.common.encap(send_buffer, &mut transport_buffer)?;
        let result = self.common.device_io.send(&transport_buffer[..used]);
        if result.is_ok() {
            let opcode = send_buffer[1];
            if opcode == SpdmRequestResponseCode::SpdmResponseVersion.get_u8() {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);
            } else if opcode == SpdmRequestResponseCode::SpdmResponseCapabilities.get_u8() {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);
            } else if opcode == SpdmRequestResponseCode::SpdmResponseAlgorithms.get_u8() {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);
            } else if opcode == SpdmRequestResponseCode::SpdmResponseDigests.get_u8() {
                if self.common.runtime_info.get_connection_state().get_u8()
                    < SpdmConnectionState::SpdmConnectionAfterDigest.get_u8()
                {
                    self.common
                        .runtime_info
                        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterDigest);
                }
            } else if opcode == SpdmRequestResponseCode::SpdmResponseCertificate.get_u8() {
                if self.common.runtime_info.get_connection_state().get_u8()
                    < SpdmConnectionState::SpdmConnectionAfterCertificate.get_u8()
                {
                    self.common
                        .runtime_info
                        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCertificate);
                }
            } else if opcode == SpdmRequestResponseCode::SpdmResponseChallengeAuth.get_u8() {
                self.common
                    .runtime_info
                    .set_connection_state(SpdmConnectionState::SpdmConnectionAuthenticated);
            } else if opcode == SpdmRequestResponseCode::SpdmResponseFinishRsp.get_u8() {
                let session = self
                    .common
                    .get_session_via_id(self.common.runtime_info.get_last_session_id().unwrap())
                    .unwrap();
                session.set_session_state(
                    crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                );
                self.common.runtime_info.set_last_session_id(None);
            }
        }
        result
    }

    pub fn send_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        is_app_message: bool,
    ) -> SpdmResult {
        if !is_app_message
            && self.common.negotiate_info.req_data_transfer_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.req_data_transfer_size_sel as usize
        {
            let mut err_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
            let mut writer = Writer::init(&mut err_buffer);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorResponseTooLarge, 0, &mut writer);
            return self.send_secured_message(session_id, writer.used_slice(), is_app_message);
        }

        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = self.common.encode_secured_message(
            session_id,
            send_buffer,
            &mut transport_buffer,
            false,
            is_app_message,
        )?;
        let result = self.common.device_io.send(&transport_buffer[..used]);
        if result.is_ok() {
            let opcode = send_buffer[1];
            // change state after message is sent.
            if opcode == SpdmRequestResponseCode::SpdmResponseEndSessionAck.get_u8() {
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
            }
            if opcode == SpdmRequestResponseCode::SpdmResponseFinishRsp.get_u8()
                || opcode == SpdmRequestResponseCode::SpdmResponsePskFinishRsp.get_u8()
            {
                let session = self.common.get_session_via_id(session_id).unwrap();
                session.set_session_state(
                    crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                );
            }
        }
        result
    }

    pub fn process_message(
        &mut self,
        timeout: usize,
        auxiliary_app_data: &[u8],
    ) -> Result<bool, (usize, [u8; config::RECEIVER_BUFFER_SIZE])> {
        let mut receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        match self.receive_message(&mut receive_buffer[..], timeout) {
            Ok((used, secured_message)) => {
                if secured_message {
                    let mut read = Reader::init(&receive_buffer[0..used]);
                    let session_id = u32::read(&mut read).ok_or((used, receive_buffer))?;

                    let spdm_session = self
                        .common
                        .get_session_via_id(session_id)
                        .ok_or((used, receive_buffer))?;

                    let mut app_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

                    let decode_size = spdm_session.decode_spdm_secured_message(
                        &receive_buffer[..used],
                        &mut app_buffer,
                        true,
                    );
                    if decode_size.is_err() {
                        return Err((used, receive_buffer));
                    }
                    let decode_size = decode_size.unwrap();

                    let mut spdm_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
                    let decap_result = self
                        .common
                        .transport_encap
                        .decap_app(&app_buffer[0..decode_size], &mut spdm_buffer);
                    match decap_result {
                        Err(_) => Err((used, receive_buffer)),
                        Ok((decode_size, is_app_message)) => {
                            if !is_app_message {
                                Ok(self
                                    .dispatch_secured_message(
                                        session_id,
                                        &spdm_buffer[0..decode_size],
                                    )
                                    .is_ok())
                            } else {
                                Ok(self
                                    .dispatch_secured_app_message(
                                        session_id,
                                        &spdm_buffer[..decode_size],
                                        auxiliary_app_data,
                                    )
                                    .is_ok())
                            }
                        }
                    }
                } else {
                    Ok(self.dispatch_message(&receive_buffer[0..used]).is_ok())
                }
            }
            Err(used) => Err((used, receive_buffer)),
        }
    }

    // Debug note: receive_buffer is used as return value, when receive got a command
    // whose value is not normal, will return Err to caller to handle the raw packet,
    // So can't swap transport_buffer and receive_buffer, even though it should be by
    // their name suggestion. (03.01.2022)
    fn receive_message(
        &mut self,
        receive_buffer: &mut [u8],
        timeout: usize,
    ) -> Result<(usize, bool), usize> {
        info!("receive_message!\n");

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let used = self.common.device_io.receive(receive_buffer, timeout)?;

        let (used, secured_message) = self
            .common
            .transport_encap
            .decap(&receive_buffer[..used], &mut transport_buffer)
            .map_err(|_| used)?;

        receive_buffer[..used].copy_from_slice(&transport_buffer[..used]);
        Ok((used, secured_message))
    }

    fn dispatch_secured_message(&mut self, session_id: u32, bytes: &[u8]) -> SpdmResult {
        let mut reader = Reader::init(bytes);

        let session = self.common.get_immutable_session_via_id(session_id);
        if session.is_none() {
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }
        let session = session.unwrap();

        match session.get_session_state() {
            SpdmSessionState::SpdmSessionHandshaking => {
                let in_clear_text = self
                    .common
                    .negotiate_info
                    .req_capabilities_sel
                    .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                    && self
                        .common
                        .negotiate_info
                        .rsp_capabilities_sel
                        .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
                if in_clear_text {
                    return Err(SPDM_STATUS_UNSUPPORTED_CAP);
                }

                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        #[cfg(feature = "mut-auth")]
                        SpdmRequestResponseCode::SpdmRequestGetEncapsulatedRequest => {
                            self.handle_get_encapsulated_request(session_id, bytes)
                        }
                        #[cfg(feature = "mut-auth")]
                        SpdmRequestResponseCode::SpdmRequestDeliverEncapsulatedResponse => {
                            self.handle_deliver_encapsulated_reponse(session_id, bytes)
                        }
                        SpdmRequestResponseCode::SpdmRequestFinish => {
                            self.handle_spdm_finish(session_id, bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestPskFinish => {
                            self.handle_spdm_psk_finish(session_id, bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestGetVersion
                        | SpdmRequestResponseCode::SpdmRequestGetCapabilities
                        | SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
                        | SpdmRequestResponseCode::SpdmRequestGetDigests
                        | SpdmRequestResponseCode::SpdmRequestGetCertificate
                        | SpdmRequestResponseCode::SpdmRequestChallenge
                        | SpdmRequestResponseCode::SpdmRequestGetMeasurements
                        | SpdmRequestResponseCode::SpdmRequestKeyExchange
                        | SpdmRequestResponseCode::SpdmRequestPskExchange
                        | SpdmRequestResponseCode::SpdmRequestHeartbeat
                        | SpdmRequestResponseCode::SpdmRequestKeyUpdate
                        | SpdmRequestResponseCode::SpdmRequestEndSession => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                Some(session_id),
                                bytes,
                            ),

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                Some(session_id),
                                bytes,
                            ),

                        _ => Err(SPDM_STATUS_UNSUPPORTED_CAP),
                    },
                    None => Err(SPDM_STATUS_UNSUPPORTED_CAP),
                }
            }
            SpdmSessionState::SpdmSessionEstablished => {
                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        SpdmRequestResponseCode::SpdmRequestGetDigests => {
                            self.handle_spdm_digest(bytes, Some(session_id))
                        }
                        SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                            self.handle_spdm_certificate(bytes, Some(session_id))
                        }
                        SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                            self.handle_spdm_measurement(Some(session_id), bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                            self.handle_spdm_heartbeat(session_id, bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                            self.handle_spdm_key_update(session_id, bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestEndSession => {
                            self.handle_spdm_end_session(session_id, bytes)
                        }
                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes)
                        }

                        SpdmRequestResponseCode::SpdmRequestGetVersion
                        | SpdmRequestResponseCode::SpdmRequestGetCapabilities
                        | SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
                        | SpdmRequestResponseCode::SpdmRequestChallenge
                        | SpdmRequestResponseCode::SpdmRequestKeyExchange
                        | SpdmRequestResponseCode::SpdmRequestPskExchange
                        | SpdmRequestResponseCode::SpdmRequestFinish
                        | SpdmRequestResponseCode::SpdmRequestPskFinish => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                Some(session_id),
                                bytes,
                            ),

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => self
                            .handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                Some(session_id),
                                bytes,
                            ),

                        _ => Err(SPDM_STATUS_UNSUPPORTED_CAP),
                    },
                    None => Err(SPDM_STATUS_UNSUPPORTED_CAP),
                }
            }
            SpdmSessionState::SpdmSessionNotStarted => Err(SPDM_STATUS_UNSUPPORTED_CAP),
            SpdmSessionState::Unknown(_) => Err(SPDM_STATUS_UNSUPPORTED_CAP),
        }
    }

    fn dispatch_secured_app_message(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        auxiliary_app_data: &[u8],
    ) -> SpdmResult {
        debug!("dispatching secured app message\n");

        let (rsp_app_buffer, size) =
            dispatch_secured_app_message_cb(self, session_id, bytes, auxiliary_app_data).unwrap();
        self.send_secured_message(session_id, &rsp_app_buffer[..size], true)
    }
    pub fn dispatch_message(&mut self, bytes: &[u8]) -> SpdmResult {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestGetVersion => self.handle_spdm_version(bytes),
                SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                    self.handle_spdm_capability(bytes)
                }
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                    self.handle_spdm_algorithm(bytes)
                }
                SpdmRequestResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes, None)
                }
                SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(bytes, None)
                }
                SpdmRequestResponseCode::SpdmRequestChallenge => self.handle_spdm_challenge(bytes),
                SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(None, bytes)
                }

                SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                    self.handle_spdm_key_exchange(bytes)
                }

                SpdmRequestResponseCode::SpdmRequestPskExchange => {
                    self.handle_spdm_psk_exchange(bytes)
                }

                SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                    self.handle_spdm_vendor_defined_request(None, bytes)
                }

                SpdmRequestResponseCode::SpdmRequestFinish => {
                    let in_clear_text = self
                        .common
                        .negotiate_info
                        .req_capabilities_sel
                        .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
                        && self
                            .common
                            .negotiate_info
                            .rsp_capabilities_sel
                            .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
                    if in_clear_text {
                        if let Some(session_id) = self.common.runtime_info.get_last_session_id() {
                            if let Some(session) =
                                self.common.get_immutable_session_via_id(session_id)
                            {
                                if session.get_session_state()
                                    == SpdmSessionState::SpdmSessionHandshaking
                                {
                                    return self.handle_spdm_finish(session_id, bytes);
                                }
                            }
                        }
                    }

                    self.handle_error_request(
                        SpdmErrorCode::SpdmErrorUnexpectedRequest,
                        None,
                        bytes,
                    )
                }

                SpdmRequestResponseCode::SpdmRequestPskFinish
                | SpdmRequestResponseCode::SpdmRequestHeartbeat
                | SpdmRequestResponseCode::SpdmRequestKeyUpdate
                | SpdmRequestResponseCode::SpdmRequestEndSession => self.handle_error_request(
                    SpdmErrorCode::SpdmErrorUnexpectedRequest,
                    None,
                    bytes,
                ),

                SpdmRequestResponseCode::SpdmRequestResponseIfReady => self.handle_error_request(
                    SpdmErrorCode::SpdmErrorUnsupportedRequest,
                    None,
                    bytes,
                ),

                _ => Err(SPDM_STATUS_UNSUPPORTED_CAP),
            },
            None => Err(SPDM_STATUS_UNSUPPORTED_CAP),
        }
    }
}
