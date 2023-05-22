// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER,
};
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_key_update_op(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
    ) -> SpdmResult {
        info!("send spdm key_update\n");

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.encode_spdm_key_update_op(key_update_operation, tag, &mut send_buffer);
        self.send_secured_message(session_id, &send_buffer[..used], false)?;

        // update key
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
            s
        } else {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        };
        let update_requester = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            || key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        let update_responder = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        session.create_data_secret_update(spdm_version_sel, update_requester, update_responder)?;
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.receive_secured_message(session_id, &mut receive_buffer, false)?;

        self.handle_spdm_key_update_op_response(
            session_id,
            update_requester,
            update_responder,
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_key_update_op(
        &mut self,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
        buf: &mut [u8],
    ) -> usize {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation,
                tag,
            }),
        };
        if let Ok(sz) = request.spdm_encode(&mut self.common, &mut writer) {
            sz
        } else {
            0
        }
    }

    pub fn handle_spdm_key_update_op_response(
        &mut self,
        session_id: u32,
        update_requester: bool,
        update_responder: bool,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => {
                        let key_update_rsp =
                            SpdmKeyUpdateResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return Err(SPDM_STATUS_INVALID_PARAMETER);
                        };
                        if let Some(key_update_rsp) = key_update_rsp {
                            debug!("!!! key_update rsp : {:02x?}\n", key_update_rsp);
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                true,
                            )?;
                            Ok(())
                        } else {
                            error!("!!! key_update : fail !!!\n");
                            session.activate_data_secret_update(
                                spdm_version_sel,
                                update_requester,
                                update_responder,
                                false,
                            )?;
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
                            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    pub fn send_receive_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
    ) -> SpdmResult {
        if key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            && key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateSingleKey
        {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        self.send_receive_spdm_key_update_op(session_id, key_update_operation, 1)?;
        self.send_receive_spdm_key_update_op(
            session_id,
            SpdmKeyUpdateOperation::SpdmVerifyNewKey,
            2,
        )
    }
}

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};
    #[test]
    fn test_case0_send_receive_spdm_key_update() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let rsp_session_id = 0xFFFEu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = responder.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret);
        let _ = responder.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let _ = responder.common.session[0].generate_data_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let rsp_session_id = 0xFFFEu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = requester.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret);
        let _ = requester.common.session[0].generate_handshake_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let _ = requester.common.session[0].generate_data_secret(
            SpdmVersion::SpdmVersion12,
            &SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0; SPDM_MAX_HASH_SIZE]),
            },
        );
        let measurement_summary_hash_type = SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        let status = requester
            .send_receive_spdm_key_update(session_id, measurement_summary_hash_type)
            .is_ok();
        assert!(status);

        let measurement_summary_hash_type = SpdmKeyUpdateOperation::Unknown(0);
        let status = requester
            .send_receive_spdm_key_update(session_id, measurement_summary_hash_type)
            .is_err();
        assert!(status);
    }
}
