// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

use crate::common::ManagedBuffer;

impl RequesterContext {
    pub fn send_receive_spdm_finish(
        &mut self,
        slot_id: u8,
        session_id: u32,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        info!("send spdm finish\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let (send_used, base_hash_size, message_f) =
            self.encode_spdm_finish(session_id, slot_id, &mut send_buffer)?;
        self.send_secured_message(
            session_id,
            &send_buffer[..send_used],
            false,
            transport_encap,
            device_io,
        )?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let receive_used = self.receive_secured_message(
            session_id,
            &mut receive_buffer,
            false,
            transport_encap,
            device_io,
        )?;
        self.handle_spdm_finish_response(
            session_id,
            slot_id,
            base_hash_size,
            message_f,
            &receive_buffer[..receive_used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_finish(
        &mut self,
        session_id: u32,
        slot_id: u8,
        buf: &mut [u8],
    ) -> SpdmResult<(usize, usize, ManagedBuffer)> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(SpdmFinishRequestPayload {
                finish_request_attributes: SpdmFinishRequestAttributes::empty(),
                req_slot_id: slot_id,
                signature: SpdmSignatureStruct::default(),
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let send_used = writer.used();

        // generate HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = send_used - base_hash_size;

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let mut message_f = ManagedBuffer::default();
            message_f
                .append_message(&buf[..temp_used])
                .ok_or(spdm_err!(ENOMEM))?;

            let session = if let Some(s) = self.common.get_immutable_session_via_id(session_id) {
                s
            } else {
                return spdm_result_err!(EFAULT);
            };
            let message_k = &session.runtime_info.message_k;

            let transcript_data = self.common.calc_req_transcript_data(
                slot_id,
                false,
                message_k,
                Some(&message_f),
            )?;
            let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                s
            } else {
                return spdm_result_err!(EFAULT);
            };

            let hmac = session.generate_hmac_with_request_finished_key(transcript_data.as_ref())?;
            message_f
                .append_message(hmac.as_ref())
                .ok_or(spdm_err!(ENOMEM))?;

            // patch the message before send
            buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
            Ok((send_used, base_hash_size, message_f))
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                s
            } else {
                return spdm_result_err!(EFAULT);
            };
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                &buf[..temp_used],
            );
            let message_hash = crypto::hash::hash_ctx_finalize(
                session
                    .runtime_info
                    .digest_context_th
                    .as_mut()
                    .cloned()
                    .unwrap(),
            );
            let hmac =
                session.generate_hmac_with_request_finished_key(message_hash.unwrap().as_ref())?;
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                hmac.as_ref(),
            );
            // patch the message before send
            buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
            Ok((send_used, base_hash_size, ManagedBuffer::default()))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_finish_response(
        &mut self,
        session_id: u32,
        slot_id: u8,
        base_hash_size: usize,
        #[cfg(not(feature = "hashed-transcript-data"))] mut message_f: ManagedBuffer,
        #[cfg(feature = "hashed-transcript-data")] message_f: ManagedBuffer, // never use message_f for hashed-transcript-data, use session.runtime_info.message_f
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
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

                        if in_clear_text {
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let session = if let Some(s) =
                                self.common.get_immutable_session_via_id(session_id)
                            {
                                s
                            } else {
                                return spdm_result_err!(EFAULT);
                            };
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let message_k = &session.runtime_info.message_k;

                            // verify HMAC with finished_key
                            let temp_used = receive_used - base_hash_size;
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            message_f
                                .append_message(&receive_buffer[..temp_used])
                                .ok_or(spdm_err!(ENOMEM))?;

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let transcript_data = self.common.calc_req_transcript_data(
                                slot_id,
                                false,
                                message_k,
                                Some(&message_f),
                            )?;

                            let session =
                                if let Some(s) = self.common.get_session_via_id(session_id) {
                                    s
                                } else {
                                    return spdm_result_err!(EFAULT);
                                };

                            #[cfg(feature = "hashed-transcript-data")]
                            crypto::hash::hash_ctx_update(
                                session.runtime_info.digest_context_th.as_mut().unwrap(),
                                &receive_buffer[..temp_used],
                            );

                            #[cfg(feature = "hashed-transcript-data")]
                            let ctx_cloned = session
                                .runtime_info
                                .digest_context_th
                                .as_mut()
                                .cloned()
                                .unwrap();
                            if session
                                .verify_hmac_with_response_finished_key(
                                    #[cfg(not(feature = "hashed-transcript-data"))]
                                    transcript_data.as_ref(),
                                    #[cfg(feature = "hashed-transcript-data")]
                                    crypto::hash::hash_ctx_finalize(ctx_cloned)
                                        .unwrap()
                                        .as_ref(),
                                    &finish_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                let _ = session.teardown(session_id);
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            message_f
                                .append_message(finish_rsp.verify_data.as_ref())
                                .ok_or(spdm_err!(ENOMEM))?;
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                session.runtime_info.message_f = message_f.clone();
                            }
                            #[cfg(feature = "hashed-transcript-data")]
                            crypto::hash::hash_ctx_update(
                                session.runtime_info.digest_context_th.as_mut().unwrap(),
                                finish_rsp.verify_data.as_ref(),
                            );
                        } else {
                            let session =
                                if let Some(s) = self.common.get_session_via_id(session_id) {
                                    s
                                } else {
                                    return spdm_result_err!(EFAULT);
                                };
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            message_f
                                .append_message(&receive_buffer[..receive_used])
                                .ok_or(spdm_err!(ENOMEM))?;
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                session.runtime_info.message_f = message_f.clone();
                            }
                            #[cfg(feature = "hashed-transcript-data")]
                            crypto::hash::hash_ctx_update(
                                session.runtime_info.digest_context_th.as_mut().unwrap(),
                                &receive_buffer[..receive_used],
                            );
                        }

                        #[cfg(not(feature = "hashed-transcript-data"))]
                        let session =
                            if let Some(s) = self.common.get_immutable_session_via_id(session_id) {
                                s
                            } else {
                                return spdm_result_err!(EFAULT);
                            };
                        #[cfg(not(feature = "hashed-transcript-data"))]
                        let message_k = &session.runtime_info.message_k;
                        // generate the data secret
                        #[cfg(not(feature = "hashed-transcript-data"))]
                        let th2 = self.common.calc_req_transcript_hash(
                            slot_id,
                            false,
                            message_k,
                            Some(&message_f),
                        )?;

                        #[cfg(feature = "hashed-transcript-data")]
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return spdm_result_err!(EFAULT);
                        };

                        #[cfg(feature = "hashed-transcript-data")]
                        let th2 = crypto::hash::hash_ctx_finalize(
                            session
                                .runtime_info
                                .digest_context_th
                                .as_mut()
                                .cloned()
                                .unwrap(),
                        )
                        .unwrap();
                        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
                        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                            s
                        } else {
                            return spdm_result_err!(EFAULT);
                        };
                        match session.generate_data_secret(spdm_version_sel, &th2) {
                            Ok(_) => {}
                            Err(e) => {
                                return Err(e);
                            }
                        }
                        session.set_session_state(
                            crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                        );

                        Ok(())
                    } else {
                        error!("!!! finish : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let erm = self.spdm_handle_error_response_main(
                        Some(session_id),
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestFinish,
                        SpdmRequestResponseCode::SpdmResponseFinishRsp,
                        transport_encap,
                        device_io,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_finish_response(
                                session_id,
                                slot_id,
                                base_hash_size,
                                message_f,
                                &receive_buffer[..used],
                                transport_encap,
                                device_io,
                            )
                        }
                        _ => spdm_result_err!(EINVAL),
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_finish() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

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
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        requester.common.peer_info.peer_cert_chain[0] = Some(SpdmCertChain::default());
        requester.common.peer_info.peer_cert_chain[0]
            .as_mut()
            .unwrap()
            .cert_chain = REQ_CERT_CHAIN_DATA;

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
        // let _ = requester.send_receive_spdm_finish(4294901758);
        let status = requester
            .send_receive_spdm_finish(
                0,
                4294901758,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
