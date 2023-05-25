// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::app_message_handler::dispatch_secured_app_message_cb;
use crate::common::SpdmConnectionState;
use crate::common::{session::SpdmSessionState, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::SpdmResult;
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
                                Ok(self.dispatch_secured_message(
                                    session_id,
                                    &spdm_buffer[0..decode_size],
                                ))
                            } else {
                                Ok(self.dispatch_secured_app_message(
                                    session_id,
                                    &spdm_buffer[..decode_size],
                                    auxiliary_app_data,
                                ))
                            }
                        }
                    }
                } else {
                    Ok(self.dispatch_message(&receive_buffer[0..used]))
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

    fn dispatch_secured_message(&mut self, session_id: u32, bytes: &[u8]) -> bool {
        let mut reader = Reader::init(bytes);

        let session = self.common.get_immutable_session_via_id(session_id);
        if session.is_none() {
            return false;
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
                    return false;
                }

                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        SpdmRequestResponseCode::SpdmRequestFinish => {
                            self.handle_spdm_finish(session_id, bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestPskFinish => {
                            self.handle_spdm_psk_finish(session_id, bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes);
                            true
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
                        | SpdmRequestResponseCode::SpdmRequestEndSession => {
                            self.handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                Some(session_id),
                                bytes,
                            );
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => {
                            self.handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                Some(session_id),
                                bytes,
                            );
                            true
                        }

                        _ => false,
                    },
                    None => false,
                }
            }
            SpdmSessionState::SpdmSessionEstablished => {
                match SpdmMessageHeader::read(&mut reader) {
                    Some(message_header) => match message_header.request_response_code {
                        SpdmRequestResponseCode::SpdmRequestGetDigests => {
                            self.handle_spdm_digest(bytes, Some(session_id));
                            true
                        }
                        SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                            self.handle_spdm_certificate(bytes, Some(session_id));
                            true
                        }
                        SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                            self.handle_spdm_measurement(Some(session_id), bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                            self.handle_spdm_heartbeat(session_id, bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                            self.handle_spdm_key_update(session_id, bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestEndSession => {
                            self.handle_spdm_end_session(session_id, bytes);
                            true
                        }
                        SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                            self.handle_spdm_vendor_defined_request(Some(session_id), bytes);
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestGetVersion
                        | SpdmRequestResponseCode::SpdmRequestGetCapabilities
                        | SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
                        | SpdmRequestResponseCode::SpdmRequestChallenge
                        | SpdmRequestResponseCode::SpdmRequestKeyExchange
                        | SpdmRequestResponseCode::SpdmRequestPskExchange
                        | SpdmRequestResponseCode::SpdmRequestFinish
                        | SpdmRequestResponseCode::SpdmRequestPskFinish => {
                            self.handle_error_request(
                                SpdmErrorCode::SpdmErrorUnexpectedRequest,
                                Some(session_id),
                                bytes,
                            );
                            true
                        }

                        SpdmRequestResponseCode::SpdmRequestResponseIfReady => {
                            self.handle_error_request(
                                SpdmErrorCode::SpdmErrorUnsupportedRequest,
                                Some(session_id),
                                bytes,
                            );
                            true
                        }

                        _ => false,
                    },
                    None => false,
                }
            }
            SpdmSessionState::SpdmSessionNotStarted => false,
            SpdmSessionState::Unknown(_) => false,
        }
    }

    fn dispatch_secured_app_message(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        auxiliary_app_data: &[u8],
    ) -> bool {
        debug!("dispatching secured app message\n");

        let (rsp_app_buffer, size) =
            dispatch_secured_app_message_cb(self, session_id, bytes, auxiliary_app_data).unwrap();
        let _ = self.send_secured_message(session_id, &rsp_app_buffer[..size], true);
        true
    }
    pub fn dispatch_message(&mut self, bytes: &[u8]) -> bool {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestGetVersion => {
                    self.handle_spdm_version(bytes);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                    self.handle_spdm_capability(bytes);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                    self.handle_spdm_algorithm(bytes);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes, None);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(bytes, None);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestChallenge => {
                    self.handle_spdm_challenge(bytes);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(None, bytes);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                    self.handle_spdm_key_exchange(bytes);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestPskExchange => {
                    self.handle_spdm_psk_exchange(bytes);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                    self.handle_spdm_vendor_defined_request(None, bytes);
                    true
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
                                    self.handle_spdm_finish(session_id, bytes);
                                    return true;
                                }
                            }
                        }
                    }

                    self.handle_error_request(
                        SpdmErrorCode::SpdmErrorUnexpectedRequest,
                        None,
                        bytes,
                    );
                    true
                }

                SpdmRequestResponseCode::SpdmRequestPskFinish
                | SpdmRequestResponseCode::SpdmRequestHeartbeat
                | SpdmRequestResponseCode::SpdmRequestKeyUpdate
                | SpdmRequestResponseCode::SpdmRequestEndSession => {
                    self.handle_error_request(
                        SpdmErrorCode::SpdmErrorUnexpectedRequest,
                        None,
                        bytes,
                    );
                    true
                }

                SpdmRequestResponseCode::SpdmRequestResponseIfReady => {
                    self.handle_error_request(
                        SpdmErrorCode::SpdmErrorUnsupportedRequest,
                        None,
                        bytes,
                    );
                    true
                }

                _ => false,
            },
            None => false,
        }
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::common::spdm_codec::SpdmCodec;
    use crate::common::ST1;
    use crate::common::{session::*, SpdmContext};
    use crate::message::SpdmMessageHeader;
    use crate::protocol::gen_array_clone;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::Writer;

    #[test]
    fn test_case0_send_secured_message() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crate::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
        let used = writer.used();
        let status = context
            .send_secured_message(session_id, &send_buffer[0..used], false)
            .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case1_send_secured_message() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crate::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let value = SpdmMessage {
            header: SpdmMessageHeader::default(),
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(
                SpdmKeyUpdateResponsePayload::default(),
            ),
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
        let used = writer.used();
        let status = context
            .send_secured_message(session_id, &send_buffer[0..used], false)
            .is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_receive_message() {
        let receive_buffer = &mut [0u8; config::RECEIVER_BUFFER_SIZE];
        let mut writer = Writer::init(receive_buffer);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm,
            payload_length: 100,
        };
        assert!(value.encode(&mut writer).is_ok());

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        shared_buffer.set_buffer(receive_buffer);

        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crate::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let mut receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        let status = context
            .receive_message(&mut receive_buffer[..], ST1)
            .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case0_process_message() {
        let receive_buffer = &mut [0u8; 1024];
        let mut writer = Writer::init(receive_buffer);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm,
            payload_length: 100,
        };
        assert!(value.encode(&mut writer).is_ok());

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        shared_buffer.set_buffer(receive_buffer);

        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let rsp_session_id = 0xFFFEu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        let status = context.process_message(ST1, &[0]).is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_dispatch_secured_message() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        crate::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crate::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

        let rsp_session_id = 0xFFFEu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        let patch_context = |context: &mut SpdmContext| {
            context.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
            context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            context.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
            context.negotiate_info.measurement_specification_sel =
                SpdmMeasurementSpecification::DMTF;

            context.session = gen_array_clone(SpdmSession::new(), 4);
            context.session[0].setup(session_id).unwrap();
            context.session[0].set_crypto_param(
                SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmDheAlgo::SECP_384_R1,
                SpdmAeadAlgo::AES_256_GCM,
                SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
            );
            context.provision_info.my_cert_chain = [
                Some(SpdmCertChainBuffer {
                    data_size: 512u16,
                    data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
                }),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ];
        };

        let mut i = 0;
        loop {
            let (request_response_code, connection_state) = dispatch_data(i, true);
            if request_response_code == SpdmRequestResponseCode::Unknown(0) {
                break;
            }
            context
                .common
                .runtime_info
                .set_connection_state(connection_state);
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code,
            };
            // version request will reset spdm context.
            // negotiate need be done successfully before sending some request(digest).
            // patch spdm context for it.
            patch_context(&mut context.common);
            assert!(value.encode(&mut writer).is_ok());
            let status = context.dispatch_message(bytes);
            assert!(status);
            i += 1;
        }
        let mut i = 0;
        loop {
            let (request_response_code, connection_state) = dispatch_data(i, false);
            if request_response_code == SpdmRequestResponseCode::Unknown(0) {
                break;
            }
            context
                .common
                .runtime_info
                .set_connection_state(connection_state);
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code,
            };
            assert!(value.encode(&mut writer).is_ok());
            let status = context.dispatch_message(bytes);
            assert!(status);
            // TBD: check if error message is turned.
            i += 1;
        }

        let mut i = 0;
        loop {
            let (request_response_code, connection_state, session_state) =
                dispatch_secured_data(i, true);
            if request_response_code == SpdmRequestResponseCode::Unknown(0) {
                break;
            }
            context
                .common
                .runtime_info
                .set_connection_state(connection_state);
            context.common.session[0].set_session_state(session_state);
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code,
            };
            assert!(value.encode(&mut writer).is_ok());
            let status_secured = context.dispatch_secured_message(session_id, bytes);
            assert!(status_secured);
            i += 1;
        }
        let mut i = 0;
        loop {
            let (request_response_code, connection_state, session_state) =
                dispatch_secured_data(i, false);
            if request_response_code == SpdmRequestResponseCode::Unknown(0) {
                break;
            }
            context
                .common
                .runtime_info
                .set_connection_state(connection_state);
            context.common.session[0].set_session_state(session_state);
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code,
            };
            assert!(value.encode(&mut writer).is_ok());
            let status_secured = context.dispatch_secured_message(session_id, bytes);
            assert!(!status_secured);
            i += 1;
        }
    }

    fn dispatch_secured_data(
        num: usize,
        status: bool,
    ) -> (
        SpdmRequestResponseCode,
        SpdmConnectionState,
        SpdmSessionState,
    ) {
        let response_true = [
            (
                SpdmRequestResponseCode::SpdmRequestFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetDigests,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCertificate,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetMeasurements,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestHeartbeat,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestEndSession,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::Unknown(0),
                SpdmConnectionState::SpdmConnectionNotStarted,
                SpdmSessionState::SpdmSessionNotStarted,
            ),
        ];
        let response_flase = [
            (
                SpdmRequestResponseCode::SpdmRequestGetVersion,
                SpdmConnectionState::SpdmConnectionNotStarted,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                SpdmConnectionState::SpdmConnectionAfterVersion,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                SpdmConnectionState::SpdmConnectionAfterCapabilities,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestChallenge,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetDigests,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCertificate,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetMeasurements,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestHeartbeat,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestEndSession,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionHandshaking,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetVersion,
                SpdmConnectionState::SpdmConnectionNotStarted,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                SpdmConnectionState::SpdmConnectionAfterVersion,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                SpdmConnectionState::SpdmConnectionAfterCapabilities,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestChallenge,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
                SpdmSessionState::SpdmSessionEstablished,
            ),
            (
                SpdmRequestResponseCode::Unknown(0),
                SpdmConnectionState::SpdmConnectionNotStarted,
                SpdmSessionState::SpdmSessionNotStarted,
            ),
        ];
        if status {
            response_true[num]
        } else {
            response_flase[num]
        }
    }
    fn dispatch_data(num: usize, status: bool) -> (SpdmRequestResponseCode, SpdmConnectionState) {
        let response_true = [
            (
                SpdmRequestResponseCode::SpdmRequestGetVersion,
                SpdmConnectionState::SpdmConnectionNotStarted,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCapabilities,
                SpdmConnectionState::SpdmConnectionAfterVersion,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                SpdmConnectionState::SpdmConnectionAfterCapabilities,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetDigests,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetCertificate,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestChallenge,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestGetMeasurements,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskExchange,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::Unknown(0),
                SpdmConnectionState::SpdmConnectionNotStarted,
            ),
        ];
        let response_flase = [
            (
                SpdmRequestResponseCode::SpdmRequestFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestPskFinish,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestHeartbeat,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::SpdmRequestEndSession,
                SpdmConnectionState::SpdmConnectionNegotiated,
            ),
            (
                SpdmRequestResponseCode::Unknown(0),
                SpdmConnectionState::SpdmConnectionNotStarted,
            ),
        ];
        if status {
            response_true[num]
        } else {
            response_flase[num]
        }
    }
}
