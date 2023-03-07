// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::app_message_handler::dispatch_secured_app_message_cb;
use crate::common::{SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::SpdmResult;
use crate::message::*;
use codec::{Codec, Reader};

pub struct ResponderContext {
    pub common: crate::common::SpdmContext,
}

impl ResponderContext {
    pub fn new(
        // device_io: &'a mut dyn SpdmDeviceIo,
        // transport_encap: &'a mut dyn SpdmTransportEncap,
        config_info: crate::common::SpdmConfigInfo,
        provision_info: crate::common::SpdmProvisionInfo,
    ) -> Self {
        ResponderContext {
            common: crate::common::SpdmContext::new(
                // device_io,
                // transport_encap,
                config_info,
                provision_info,
            ),
        }
    }

    pub fn send_message(
        &mut self,
        send_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let used = self
            .common
            .encap(send_buffer, &mut transport_buffer, transport_encap)?;
        device_io.send(&transport_buffer[..used])
    }

    pub fn send_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        is_app_message: bool,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let used = self.common.encode_secured_message(
            session_id,
            send_buffer,
            &mut transport_buffer,
            false,
            is_app_message,
            transport_encap,
        )?;
        device_io.send(&transport_buffer[..used])
    }

    pub fn process_message(
        &mut self,
        timeout: usize,
        auxiliary_app_data: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> Result<bool, (usize, [u8; config::DATA_TRANSFER_SIZE])> {
        let mut receive_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        match self.receive_message(&mut receive_buffer[..], timeout, transport_encap, device_io) {
            Ok((used, secured_message)) => {
                if used == 0 {
                    return Err((0, receive_buffer));
                }
                if secured_message {
                    let mut read = Reader::init(&receive_buffer[0..used]);
                    let session_id = u32::read(&mut read).ok_or((used, receive_buffer))?;

                    let spdm_session = self
                        .common
                        .get_session_via_id(session_id)
                        .ok_or((used, receive_buffer))?;

                    let mut app_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];

                    let decode_size = spdm_session.decode_spdm_secured_message(
                        &receive_buffer[..used],
                        &mut app_buffer,
                        true,
                    );
                    if decode_size.is_err() {
                        return Err((used, receive_buffer));
                    }
                    let decode_size = decode_size.unwrap();

                    let mut spdm_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
                    let decap_result =
                        transport_encap.decap_app(&app_buffer[0..decode_size], &mut spdm_buffer);
                    match decap_result {
                        Err(_) => Err((used, receive_buffer)),
                        Ok((decode_size, is_app_message)) => {
                            if !is_app_message {
                                Ok(self.dispatch_secured_message(
                                    session_id,
                                    &spdm_buffer[0..decode_size],
                                    transport_encap,
                                    device_io,
                                ))
                            } else {
                                Ok(self.dispatch_secured_app_message(
                                    session_id,
                                    &receive_buffer[0..used],
                                    auxiliary_app_data,
                                    transport_encap,
                                    device_io,
                                ))
                            }
                        }
                    }
                } else {
                    Ok(self.dispatch_message(&receive_buffer[0..used], transport_encap, device_io))
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
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> Result<(usize, bool), usize> {
        info!("receive_message!\n");

        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];

        let used = device_io.receive(receive_buffer, timeout)?;
        if used == 0 {
            return Ok((0, true));
        }

        let (used, secured_message) = transport_encap
            .decap(&receive_buffer[..used], &mut transport_buffer)
            .map_err(|_| used)?;

        receive_buffer[..used].copy_from_slice(&transport_buffer[..used]);
        Ok((used, secured_message))
    }

    fn dispatch_secured_message(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> bool {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestResponseIfReady => {
                    self.handle_spdm_respond_if_ready(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetVersion => false,
                SpdmRequestResponseCode::SpdmRequestGetCapabilities => false,
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => false,
                SpdmRequestResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes, Some(session_id), transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(
                        bytes,
                        Some(session_id),
                        transport_encap,
                        device_io,
                    );
                    true
                }
                SpdmRequestResponseCode::SpdmRequestChallenge => false,
                SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(
                        Some(session_id),
                        bytes,
                        transport_encap,
                        device_io,
                    );
                    true
                }

                SpdmRequestResponseCode::SpdmRequestKeyExchange => false,

                SpdmRequestResponseCode::SpdmRequestFinish => {
                    self.handle_spdm_finish(session_id, bytes, transport_encap, device_io);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestPskExchange => false,

                SpdmRequestResponseCode::SpdmRequestPskFinish => {
                    self.handle_spdm_psk_finish(session_id, bytes, transport_encap, device_io)
                        .unwrap();
                    true
                }

                SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                    self.handle_spdm_heartbeat(session_id, bytes, transport_encap, device_io);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                    self.handle_spdm_key_update(session_id, bytes, transport_encap, device_io);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestEndSession => {
                    let _ =
                        self.handle_spdm_end_session(session_id, bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => {
                    self.handle_spdm_vendor_defined_request(
                        session_id,
                        bytes,
                        transport_encap,
                        device_io,
                    );
                    true
                }
                SpdmRequestResponseCode::SpdmResponseDigests => false,
                SpdmRequestResponseCode::SpdmResponseCertificate => false,
                SpdmRequestResponseCode::SpdmResponseChallengeAuth => false,
                SpdmRequestResponseCode::SpdmResponseVersion => false,
                SpdmRequestResponseCode::SpdmResponseMeasurements => false,
                SpdmRequestResponseCode::SpdmResponseCapabilities => false,
                SpdmRequestResponseCode::SpdmResponseAlgorithms => false,
                SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp => false,
                SpdmRequestResponseCode::SpdmResponseFinishRsp => false,
                SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => false,
                SpdmRequestResponseCode::SpdmResponsePskFinishRsp => false,
                SpdmRequestResponseCode::SpdmResponseHeartbeatAck => false,
                SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => false,
                SpdmRequestResponseCode::SpdmResponseEndSessionAck => false,
                SpdmRequestResponseCode::SpdmResponseError => false,
                SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse => false,
                SpdmRequestResponseCode::Unknown(_) => false,
            },
            None => false,
        }
    }

    fn dispatch_secured_app_message(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        auxiliary_app_data: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> bool {
        debug!("dispatching secured app message\n");
        let rsp_app_buffer =
            dispatch_secured_app_message_cb(self, session_id, bytes, auxiliary_app_data);
        let _ = self.send_secured_message(
            session_id,
            &rsp_app_buffer,
            true,
            transport_encap,
            device_io,
        );
        true
    }
    pub fn dispatch_message(
        &mut self,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> bool {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmRequestResponseIfReady => {
                    self.handle_spdm_respond_if_ready(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetVersion => {
                    self.handle_spdm_version(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                    self.handle_spdm_capability(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                    self.handle_spdm_algorithm(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes, None, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(bytes, None, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestChallenge => {
                    self.handle_spdm_challenge(bytes, transport_encap, device_io);
                    true
                }
                SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(None, bytes, transport_encap, device_io);
                    true
                }

                SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                    matches!(
                        self.handle_spdm_key_exchange(bytes, transport_encap, device_io),
                        Ok(_)
                    )
                }

                SpdmRequestResponseCode::SpdmRequestFinish => false,

                SpdmRequestResponseCode::SpdmRequestPskExchange => {
                    matches!(
                        self.handle_spdm_psk_exchange(bytes, transport_encap, device_io),
                        Ok(_)
                    )
                }

                SpdmRequestResponseCode::SpdmRequestPskFinish => false,

                SpdmRequestResponseCode::SpdmRequestHeartbeat => false,

                SpdmRequestResponseCode::SpdmRequestKeyUpdate => false,

                SpdmRequestResponseCode::SpdmRequestEndSession => false,
                SpdmRequestResponseCode::SpdmRequestVendorDefinedRequest => false,
                SpdmRequestResponseCode::SpdmResponseDigests => false,
                SpdmRequestResponseCode::SpdmResponseCertificate => false,
                SpdmRequestResponseCode::SpdmResponseChallengeAuth => false,
                SpdmRequestResponseCode::SpdmResponseVersion => false,
                SpdmRequestResponseCode::SpdmResponseMeasurements => false,
                SpdmRequestResponseCode::SpdmResponseCapabilities => false,
                SpdmRequestResponseCode::SpdmResponseAlgorithms => false,
                SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp => false,
                SpdmRequestResponseCode::SpdmResponseFinishRsp => false,
                SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => false,
                SpdmRequestResponseCode::SpdmResponsePskFinishRsp => false,
                SpdmRequestResponseCode::SpdmResponseHeartbeatAck => false,
                SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => false,
                SpdmRequestResponseCode::SpdmResponseEndSessionAck => false,
                SpdmRequestResponseCode::SpdmResponseError => false,
                SpdmRequestResponseCode::SpdmResponseVendorDefinedResponse => false,
                SpdmRequestResponseCode::Unknown(_) => false,
            },
            None => false,
        }
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::common::session::*;
    use crate::common::spdm_codec::SpdmCodec;
    use crate::common::ST1;
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
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut context = responder::ResponderContext::new(config_info, provision_info);

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

        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
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
        value.spdm_encode(&mut context.common, &mut writer);
        let used = writer.used();
        let status = context
            .send_secured_message(
                session_id,
                &send_buffer[0..used],
                false,
                pcidoe_transport_encap,
                &mut socket_io_transport,
            )
            .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case1_send_secured_message() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;

        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let value = SpdmMessage {
            header: SpdmMessageHeader::default(),
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(
                SpdmKeyUpdateResponsePayload::default(),
            ),
        };
        value.spdm_encode(&mut context.common, &mut writer);
        let used = writer.used();
        let status = context
            .send_secured_message(
                session_id,
                &send_buffer[0..used],
                false,
                pcidoe_transport_encap,
                &mut socket_io_transport,
            )
            .is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_receive_message() {
        let receive_buffer = &mut [0u8; config::DATA_TRANSFER_SIZE];
        let mut writer = Writer::init(receive_buffer);
        let value = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm,
            payload_length: 100,
        };
        value.encode(&mut writer);

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        shared_buffer.set_buffer(receive_buffer);

        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        let mut receive_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let status = context
            .receive_message(
                &mut receive_buffer[..],
                ST1,
                pcidoe_transport_encap,
                &mut socket_io_transport,
            )
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
        value.encode(&mut writer);

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        shared_buffer.set_buffer(receive_buffer);

        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(config_info, provision_info);

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

        let status = context
            .process_message(ST1, &[0], pcidoe_transport_encap, &mut socket_io_transport)
            .is_err();
        assert!(status);
    }
    #[test]
    #[should_panic(expected = "not implemented")]
    fn test_case0_dispatch_secured_message() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(config_info, provision_info);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        let rsp_session_id = 0xFFFEu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        for i in 0..5 {
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: dispatch_secured_data(i, true),
            };
            value.encode(&mut writer);
            let status_secured = context.dispatch_secured_message(
                session_id,
                bytes,
                pcidoe_transport_encap,
                &mut socket_io_transport,
            );
            assert!(status_secured);
        }
        for i in 0..24 {
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: dispatch_secured_data(i, false),
            };
            value.encode(&mut writer);
            let status_secured = context.dispatch_secured_message(
                session_id,
                bytes,
                pcidoe_transport_encap,
                &mut socket_io_transport,
            );
            assert!(!status_secured);
        }
        for i in 0..9 {
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: dispatc_data(i, true),
            };
            value.encode(&mut writer);
            let status =
                context.dispatch_message(bytes, pcidoe_transport_encap, &mut socket_io_transport);
            assert!(status);
        }
        for i in 0..21 {
            let bytes = &mut [0u8; 4];
            let mut writer = Writer::init(bytes);
            let value = SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: dispatc_data(i, false),
            };
            value.encode(&mut writer);
            let status =
                context.dispatch_message(bytes, pcidoe_transport_encap, &mut socket_io_transport);
            assert!(!status);
        }
    }

    fn dispatch_secured_data(num: usize, status: bool) -> SpdmRequestResponseCode {
        let response_flase = [
            SpdmRequestResponseCode::SpdmRequestGetVersion,
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            SpdmRequestResponseCode::SpdmRequestChallenge,
            SpdmRequestResponseCode::SpdmRequestKeyExchange,
            SpdmRequestResponseCode::SpdmResponseDigests,
            SpdmRequestResponseCode::SpdmResponseCertificate,
            SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            SpdmRequestResponseCode::SpdmResponseVersion,
            SpdmRequestResponseCode::SpdmResponseMeasurements,
            SpdmRequestResponseCode::SpdmResponseCapabilities,
            SpdmRequestResponseCode::SpdmResponseAlgorithms,
            SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp,
            SpdmRequestResponseCode::SpdmResponseFinishRsp,
            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            SpdmRequestResponseCode::SpdmResponseError,
            SpdmRequestResponseCode::SpdmRequestPskExchange,
            SpdmRequestResponseCode::Unknown(0),
        ];
        let response_true = [
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            SpdmRequestResponseCode::SpdmRequestFinish,
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            SpdmRequestResponseCode::SpdmRequestEndSession,
        ];
        if status {
            response_true[num]
        } else {
            response_flase[num]
        }
    }
    fn dispatc_data(num: usize, status: bool) -> SpdmRequestResponseCode {
        let response_true = [
            SpdmRequestResponseCode::SpdmRequestGetVersion,
            SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            SpdmRequestResponseCode::SpdmRequestGetDigests,
            SpdmRequestResponseCode::SpdmRequestGetCertificate,
            SpdmRequestResponseCode::SpdmRequestChallenge,
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            SpdmRequestResponseCode::SpdmRequestKeyExchange,
            SpdmRequestResponseCode::SpdmRequestPskExchange,
        ];
        let response_flase = [
            SpdmRequestResponseCode::SpdmRequestFinish,
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            SpdmRequestResponseCode::SpdmRequestEndSession,
            SpdmRequestResponseCode::SpdmResponseDigests,
            SpdmRequestResponseCode::SpdmResponseCertificate,
            SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            SpdmRequestResponseCode::SpdmResponseVersion,
            SpdmRequestResponseCode::SpdmResponseMeasurements,
            SpdmRequestResponseCode::SpdmResponseCapabilities,
            SpdmRequestResponseCode::SpdmResponseAlgorithms,
            SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp,
            SpdmRequestResponseCode::SpdmResponseFinishRsp,
            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            SpdmRequestResponseCode::SpdmResponseError,
            SpdmRequestResponseCode::Unknown(0),
        ];
        if status {
            response_true[num]
        } else {
            response_flase[num]
        }
    }
}
