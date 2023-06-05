// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_INVALID_STATE_LOCAL, SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_finish(
        &mut self,
        req_slot_id: Option<u8>,
        session_id: u32,
    ) -> SpdmResult {
        info!("send spdm finish\n");
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
        info!("in_clear_text {:?}\n", in_clear_text);

        let req_slot_id = if let Some(req_slot_id) = req_slot_id {
            if req_slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
            if self.common.provision_info.my_cert_chain[req_slot_id as usize].is_none() {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
            req_slot_id
        } else {
            0
        };

        if self.common.get_session_via_id(session_id).is_none() {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestFinish,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self.encode_spdm_finish(session_id, req_slot_id, &mut send_buffer);
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return Err(res.err().unwrap());
        }
        let send_used = res.unwrap();
        let res = if in_clear_text {
            self.send_message(&send_buffer[..send_used])
        } else {
            self.send_secured_message(session_id, &send_buffer[..send_used], false)
        };
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return res;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = if in_clear_text {
            self.receive_message(&mut receive_buffer, false)
        } else {
            self.receive_secured_message(session_id, &mut receive_buffer, false)
        };
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return Err(res.err().unwrap());
        }
        let receive_used = res.unwrap();
        let res = self.handle_spdm_finish_response(
            session_id,
            req_slot_id,
            &receive_buffer[..receive_used],
        );
        if res.is_err() {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                let _ = session.teardown(session_id);
            }
        }
        res
    }

    pub fn encode_spdm_finish(
        &mut self,
        session_id: u32,
        req_slot_id: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(SpdmFinishRequestPayload {
                finish_request_attributes: SpdmFinishRequestAttributes::empty(),
                req_slot_id,
                signature: SpdmSignatureStruct::default(),
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        let send_used = request.spdm_encode(&mut self.common, &mut writer)?;

        // generate HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = send_used - base_hash_size;

        self.common
            .append_message_f(session_id, &buf[..temp_used])?;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();

        let transcript_hash = self
            .common
            .calc_req_transcript_hash(false, req_slot_id, session)?;

        let session = self.common.get_session_via_id(session_id).unwrap();

        let hmac = session.generate_hmac_with_request_finished_key(transcript_hash.as_ref())?;

        self.common.append_message_f(session_id, hmac.as_ref())?;

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
        Ok(send_used)
    }

    pub fn handle_spdm_finish_response(
        &mut self,
        session_id: u32,
        req_slot_id: u8,
        receive_buffer: &[u8],
    ) -> SpdmResult {
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

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseFinishRsp => {
                    let finish_rsp =
                        SpdmFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let receive_used = reader.used();
                    if let Some(finish_rsp) = finish_rsp {
                        debug!("!!! finish rsp : {:02x?}\n", finish_rsp);

                        let base_hash_size =
                            self.common.negotiate_info.base_hash_sel.get_size() as usize;

                        if in_clear_text {
                            // verify HMAC with finished_key
                            let temp_used = receive_used - base_hash_size;
                            self.common
                                .append_message_f(session_id, &receive_buffer[..temp_used])?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            let transcript_hash = self.common.calc_req_transcript_hash(
                                false,
                                req_slot_id,
                                session,
                            )?;

                            if session
                                .verify_hmac_with_response_finished_key(
                                    transcript_hash.as_ref(),
                                    &finish_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }

                            self.common
                                .append_message_f(session_id, finish_rsp.verify_data.as_ref())?;
                        } else {
                            self.common
                                .append_message_f(session_id, &receive_buffer[..receive_used])?;
                        }

                        let session = self
                            .common
                            .get_immutable_session_via_id(session_id)
                            .unwrap();

                        // generate the data secret
                        let th2 =
                            self.common
                                .calc_req_transcript_hash(false, req_slot_id, session)?;

                        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = self.common.get_session_via_id(session_id).unwrap();
                        match session.generate_data_secret(spdm_version_sel, &th2) {
                            Ok(_) => {}
                            Err(e) => {
                                return Err(e);
                            }
                        }
                        session.set_session_state(
                            crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                        );

                        self.common.runtime_info.set_last_session_id(None);

                        Ok(())
                    } else {
                        error!("!!! finish : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => self.spdm_handle_error_response_main(
                    Some(session_id),
                    receive_buffer,
                    SpdmRequestResponseCode::SpdmRequestFinish,
                    SpdmRequestResponseCode::SpdmResponseFinishRsp,
                ),
                _ => Err(SPDM_STATUS_ERROR_PEER),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}

#[cfg(all(test,))]
mod tests_requester {
    #[test]
    #[cfg(feature = "hashed-transcript-data")]
    fn test_case0_send_receive_spdm_finish() {
        use super::*;
        use crate::common::session::SpdmSession;
        use crate::testlib::*;
        use crate::{crypto, responder};

        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        responder.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];

        responder.common.reset_runtime_info();

        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);
        responder
            .common
            .runtime_info
            .set_last_session_id(Some(4294901758));
        responder.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

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

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());

        requester.common.reset_runtime_info();

        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

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
        let status = requester.send_receive_spdm_finish(None, 4294901758).is_ok();
        assert!(status);
    }
}
