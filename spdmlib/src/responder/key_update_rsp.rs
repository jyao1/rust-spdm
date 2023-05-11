// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_key_update(&mut self, session_id: u32, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self.write_spdm_key_update_response(session_id, bytes, &mut writer) {
            let _ = self.send_secured_message(session_id, writer.used_slice(), false);
        } else {
            let _ = self.send_message(writer.used_slice());
        }
    }

    pub fn write_spdm_key_update_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> bool {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return true;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return true;
        }

        let key_update_req = SpdmKeyUpdateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(key_update_req) = &key_update_req {
            debug!("!!! key_update req : {:02x?}\n", key_update_req);
        } else {
            error!("!!! key_update req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        }
        let key_update_req = key_update_req.unwrap();

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        match key_update_req.key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey => {
                let _ = session.create_data_secret_update(spdm_version_sel, true, false);
            }
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys => {
                let _ = session.create_data_secret_update(spdm_version_sel, true, true);
                let _ = session.activate_data_secret_update(spdm_version_sel, true, true, true);
            }
            SpdmKeyUpdateOperation::SpdmVerifyNewKey => {
                let _ = session.activate_data_secret_update(spdm_version_sel, true, false, true);
            }
            _ => {
                error!("!!! key_update req : fail !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return false;
            }
        }

        info!("send spdm key_update rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: key_update_req.key_update_operation,
                tag: key_update_req.tag,
            }),
        };
        response.spdm_encode(&mut self.common, writer).is_ok()
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::message::SpdmMessageHeader;
    use crate::protocol::gen_array_clone;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_key_update() {
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

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

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
        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = context.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret);
        let _ = context.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let _ = context.common.session[0].generate_data_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let key_exchange: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(key_exchange);
        let value = SpdmKeyUpdateRequestPayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateSingleKey,
            tag: 100u8,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        context.handle_spdm_key_update(session_id, bytes);
    }

    #[test]
    fn test_case1_handle_spdm_key_update() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let (config_info, provision_info) = create_info();
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let shared_buffer = SharedBuffer::new();
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
        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = context.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret);
        let _ = context.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let _ = context.common.session[0].generate_data_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let key_exchange: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(key_exchange);
        let value = SpdmKeyUpdateRequestPayload {
            key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
            tag: 100u8,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        context.handle_spdm_key_update(session_id, bytes);
    }
}
