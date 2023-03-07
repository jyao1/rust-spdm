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
use crate::common::ManagedBuffer;
use alloc::boxed::Box;

impl RequesterContext {
    pub fn send_receive_spdm_psk_finish(
        &mut self,
        session_id: u32,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        info!("send spdm psk_finish\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let (send_used, message_f) = self.encode_spdm_psk_finish(session_id, &mut send_buffer)?;
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
        self.handle_spdm_psk_finish_response(
            session_id,
            message_f,
            &receive_buffer[..receive_used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_psk_finish(
        &mut self,
        session_id: u32,
        buf: &mut [u8],
    ) -> SpdmResult<(usize, ManagedBuffer)> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskFinish,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(SpdmPskFinishRequestPayload {
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
        let mut message_f = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        message_f
            .append_message(&buf[..temp_used])
            .ok_or(spdm_err!(ENOMEM))?;

        #[cfg(not(feature = "hashed-transcript-data"))]
        let session = if let Some(s) = self.common.get_immutable_session_via_id(session_id) {
            s
        } else {
            return spdm_result_err!(EFAULT);
        };
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_k = &session.runtime_info.message_k;
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = self.common.calc_req_transcript_data(
            INVALID_SLOT,
            true,
            message_k,
            Some(&message_f),
        )?;
        let session = if let Some(s) = self.common.get_session_via_id(session_id) {
            s
        } else {
            return spdm_result_err!(EFAULT);
        };

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session.runtime_info.digest_context_th.as_mut().unwrap(),
            &buf[..temp_used],
        );
        #[cfg(feature = "hashed-transcript-data")]
        let message_hash = crypto::hash::hash_ctx_finalize(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .cloned()
                .unwrap(),
        );
        let hmac = session.generate_hmac_with_request_finished_key(
            #[cfg(feature = "hashed-transcript-data")]
            message_hash.unwrap().as_ref(),
            #[cfg(not(feature = "hashed-transcript-data"))]
            transcript_data.as_ref(),
        )?;

        #[cfg(not(feature = "hashed-transcript-data"))]
        message_f
            .append_message(hmac.as_ref())
            .ok_or(spdm_err!(ENOMEM))?;

        #[cfg(feature = "hashed-transcript-data")]
        {
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                hmac.as_ref(),
            );
        }

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());

        #[cfg(not(feature = "hashed-transcript-data"))]
        return Ok((send_used, message_f));
        #[cfg(feature = "hashed-transcript-data")]
        Ok((send_used, ManagedBuffer::default()))
    }

    pub fn handle_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        #[cfg(not(feature = "hashed-transcript-data"))] mut message_f: ManagedBuffer,
        #[cfg(feature = "hashed-transcript-data")] message_f: ManagedBuffer, // never use message_f for hashed-transcript-data, use session.runtime_info.message_f
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return spdm_result_err!(EFAULT);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponsePskFinishRsp => {
                        let psk_finish_rsp =
                            SpdmPskFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let receive_used = reader.used();
                        if let Some(psk_finish_rsp) = psk_finish_rsp {
                            debug!("!!! psk_finish rsp : {:02x?}\n", psk_finish_rsp);
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                let session =
                                    if let Some(s) = self.common.get_session_via_id(session_id) {
                                        s
                                    } else {
                                        return spdm_result_err!(EFAULT);
                                    };

                                message_f
                                    .append_message(&receive_buffer[..receive_used])
                                    .ok_or(spdm_err!(ENOMEM))?;

                                session.runtime_info.message_f = message_f;
                            }

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let session = if let Some(s) =
                                self.common.get_immutable_session_via_id(session_id)
                            {
                                s
                            } else {
                                return spdm_result_err!(EFAULT);
                            };
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let message_k = &session.runtime_info.message_k; // generate the data secret
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let th2 = self.common.calc_req_transcript_hash(
                                INVALID_SLOT,
                                true,
                                message_k,
                                Some(&session.runtime_info.message_f),
                            )?;

                            #[cfg(feature = "hashed-transcript-data")]
                            let session =
                                if let Some(s) = self.common.get_session_via_id(session_id) {
                                    s
                                } else {
                                    return spdm_result_err!(EFAULT);
                                };
                            #[cfg(feature = "hashed-transcript-data")]
                            crypto::hash::hash_ctx_update(
                                session.runtime_info.digest_context_th.as_mut().unwrap(),
                                &receive_buffer[..receive_used],
                            );

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
                            let session =
                                if let Some(s) = self.common.get_session_via_id(session_id) {
                                    s
                                } else {
                                    return spdm_result_err!(EFAULT);
                                };
                            session.generate_data_secret(spdm_version_sel, &th2)?;
                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                            );

                            Ok(())
                        } else {
                            error!("!!! psk_finish : fail !!!\n");
                            spdm_result_err!(EFAULT)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let erm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskFinish,
                            SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
                            transport_encap,
                            device_io,
                        );
                        match erm {
                            Ok(rm) => {
                                let receive_buffer = rm.receive_buffer;
                                let used = rm.used;
                                self.handle_spdm_psk_finish_response(
                                    session_id,
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
                }
            }
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
    fn test_case0_send_receive_spdm_psk_finish() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();
        let data = &mut [
            0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca, 0xa7,
            0x51, 0x5a, 0x4d, 0x60, 0xcf, 0x4e, 0xc3, 0x17, 0x14, 0xa7, 0x55, 0x6f, 0x77, 0x56,
            0xad, 0xa4, 0xd0, 0x7e, 0xc2, 0xd4,
        ];

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);

        // let shared_buffer = SharedBuffer::new();
        // let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::hmac::register(HMAC_TEST.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        responder.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = responder.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        requester.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = requester.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
        let status = requester
            .send_receive_spdm_psk_finish(
                4294901758,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
