// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::SpdmResult;
use crate::msgs::*;
use codec::{Codec, Reader};

pub struct ResponderContext<'a> {
    pub common: common::SpdmContext<'a>,
}

impl<'a> ResponderContext<'a> {
    pub fn new(
        device_io: &'a mut dyn SpdmDeviceIo,
        transport_encap: &'a mut dyn SpdmTransportEncap,
        config_info: common::SpdmConfigInfo,
        provision_info: common::SpdmProvisionInfo,
    ) -> Self {
        ResponderContext {
            common: common::SpdmContext::new(
                device_io,
                transport_encap,
                config_info,
                provision_info,
            ),
        }
    }

    pub fn send_message(&mut self, send_buffer: &[u8]) -> SpdmResult {
        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self
            .common
            .transport_encap
            .encap(send_buffer, &mut transport_buffer, false)?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn send_secured_message(&mut self, session_id: u32, send_buffer: &[u8]) -> SpdmResult {
        let mut app_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self
            .common
            .transport_encap
            .encap_app(send_buffer, &mut app_buffer)?;

        let spdm_session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

        let mut encoded_send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let encode_size = spdm_session.encode_spdm_secured_message(
            &app_buffer[0..used],
            &mut encoded_send_buffer,
            false,
        )?;

        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.common.transport_encap.encap(
            &encoded_send_buffer[..encode_size],
            &mut transport_buffer,
            true,
        )?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn process_message(&mut self) -> Result<bool, (usize, [u8; 1024])> {
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        match self.receive_message(&mut receive_buffer[..]) {
            Ok((used, secured_message)) => {
                if secured_message {
                    let mut read = Reader::init(&receive_buffer[0..used]);
                    let session_id = u32::read(&mut read).ok_or((used, receive_buffer))?;

                    let spdm_session = self
                        .common
                        .get_session_via_id(session_id)
                        .ok_or((used, receive_buffer))?;

                    let mut app_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];

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
                    let decode_size = self
                        .common
                        .transport_encap
                        .decap_app(&app_buffer[0..decode_size], &mut spdm_buffer);
                    if decode_size.is_err() {
                        return Err((used, receive_buffer));
                    }
                    let decode_size = decode_size.unwrap();

                    Ok(self.dispatch_secured_message(session_id, &spdm_buffer[0..decode_size]))
                } else {
                    Ok(self.dispatch_message(&receive_buffer[0..used]))
                }
            }
            Err(used) => Err((used, receive_buffer)),
        }
    }

    fn receive_message(&mut self, receive_buffer: &mut [u8]) -> Result<(usize, bool), usize> {
        info!("receive_message!\n");

        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.common.device_io.receive(receive_buffer)?;

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
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmRequestGetVersion => false,
                SpdmResponseResponseCode::SpdmRequestGetCapabilities => false,
                SpdmResponseResponseCode::SpdmRequestNegotiateAlgorithms => false,
                SpdmResponseResponseCode::SpdmRequestGetDigests => false,
                SpdmResponseResponseCode::SpdmRequestGetCertificate => false,
                SpdmResponseResponseCode::SpdmRequestChallenge => false,
                SpdmResponseResponseCode::SpdmRequestGetMeasurements => false,

                SpdmResponseResponseCode::SpdmRequestKeyExchange => false,

                SpdmResponseResponseCode::SpdmRequestFinish => {
                    self.handle_spdm_finish(session_id, bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestPskExchange => false,

                SpdmResponseResponseCode::SpdmRequestPskFinish => {
                    self.handle_spdm_psk_finish(session_id, bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestHeartbeat => {
                    self.handle_spdm_heartbeat(session_id, bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestKeyUpdate => {
                    self.handle_spdm_key_update(session_id, bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestEndSession => {
                    self.handle_spdm_end_session(session_id, bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmResponseDigests => false,
                SpdmResponseResponseCode::SpdmResponseCertificate => false,
                SpdmResponseResponseCode::SpdmResponseChallengeAuth => false,
                SpdmResponseResponseCode::SpdmResponseVersion => false,
                SpdmResponseResponseCode::SpdmResponseMeasurements => false,
                SpdmResponseResponseCode::SpdmResponseCapabilities => false,
                SpdmResponseResponseCode::SpdmResponseAlgorithms => false,
                SpdmResponseResponseCode::SpdmResponseKeyExchangeRsp => false,
                SpdmResponseResponseCode::SpdmResponseFinishRsp => false,
                SpdmResponseResponseCode::SpdmResponsePskExchangeRsp => false,
                SpdmResponseResponseCode::SpdmResponsePskFinishRsp => false,
                SpdmResponseResponseCode::SpdmResponseHeartbeatAck => false,
                SpdmResponseResponseCode::SpdmResponseKeyUpdateAck => false,
                SpdmResponseResponseCode::SpdmResponseEndSessionAck => false,
                SpdmResponseResponseCode::SpdmResponseError => false,
                SpdmResponseResponseCode::Unknown(_) => false,
            },
            None => false,
        }
    }

    pub fn dispatch_message(&mut self, bytes: &[u8]) -> bool {
        let mut reader = Reader::init(bytes);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmRequestGetVersion => {
                    self.handle_spdm_version(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestGetCapabilities => {
                    self.handle_spdm_capability(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestNegotiateAlgorithms => {
                    self.handle_spdm_algorithm(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestGetDigests => {
                    self.handle_spdm_digest(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestGetCertificate => {
                    self.handle_spdm_certificate(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestChallenge => {
                    self.handle_spdm_challenge(bytes);
                    true
                }
                SpdmResponseResponseCode::SpdmRequestGetMeasurements => {
                    self.handle_spdm_measurement(bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestKeyExchange => {
                    self.handle_spdm_key_exchange(bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestFinish => false,

                SpdmResponseResponseCode::SpdmRequestPskExchange => {
                    self.handle_spdm_psk_exchange(bytes);
                    true
                }

                SpdmResponseResponseCode::SpdmRequestPskFinish => false,

                SpdmResponseResponseCode::SpdmRequestHeartbeat => false,

                SpdmResponseResponseCode::SpdmRequestKeyUpdate => false,

                SpdmResponseResponseCode::SpdmRequestEndSession => false,

                SpdmResponseResponseCode::SpdmResponseDigests => false,
                SpdmResponseResponseCode::SpdmResponseCertificate => false,
                SpdmResponseResponseCode::SpdmResponseChallengeAuth => false,
                SpdmResponseResponseCode::SpdmResponseVersion => false,
                SpdmResponseResponseCode::SpdmResponseMeasurements => false,
                SpdmResponseResponseCode::SpdmResponseCapabilities => false,
                SpdmResponseResponseCode::SpdmResponseAlgorithms => false,
                SpdmResponseResponseCode::SpdmResponseKeyExchangeRsp => false,
                SpdmResponseResponseCode::SpdmResponseFinishRsp => false,
                SpdmResponseResponseCode::SpdmResponsePskExchangeRsp => false,
                SpdmResponseResponseCode::SpdmResponsePskFinishRsp => false,
                SpdmResponseResponseCode::SpdmResponseHeartbeatAck => false,
                SpdmResponseResponseCode::SpdmResponseKeyUpdateAck => false,
                SpdmResponseResponseCode::SpdmResponseEndSessionAck => false,
                SpdmResponseResponseCode::SpdmResponseError => false,
                SpdmResponseResponseCode::Unknown(_) => false,
            },
            None => false,
        }
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::Writer;

    #[test]
    fn test_case0_send_secured_message() {
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

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.session = [SpdmSession::new(); 4];
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        value.spdm_encode(&mut context.common, &mut writer);
        let used = writer.used();
        let status = context
            .send_secured_message(session_id, &send_buffer[0..used])
            .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case1_send_secured_message() {
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

        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
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
            .send_secured_message(session_id, &send_buffer[0..used])
            .is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_receive_message() {
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

        let receive_buffer = &mut [0u8; 8];
        let mut writer = Writer::init(receive_buffer);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm ,
            payload_length : 100,
        };
        value.encode(&mut writer);
        let status = context.receive_message(receive_buffer).is_err();
        assert!(status);
    }
    #[test]
    fn test_case0_process_message() {
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
        let status = context.process_message().is_err();
        assert!(status);
    }
}
