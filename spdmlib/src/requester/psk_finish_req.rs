// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_psk_finish(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm psk_finish\n");

        if self.common.get_session_via_id(session_id).is_none() {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestPskFinish,
            Some(session_id),
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self.encode_spdm_psk_finish(session_id, &mut send_buffer);
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return Err(res.err().unwrap());
        }
        let send_used = res.unwrap();
        let res = self.send_secured_message(session_id, &send_buffer[..send_used], false);
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return res;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let res = self.receive_secured_message(session_id, &mut receive_buffer, false);
        if res.is_err() {
            let _ = self
                .common
                .get_session_via_id(session_id)
                .unwrap()
                .teardown(session_id);
            return Err(res.err().unwrap());
        }
        let receive_used = res.unwrap();
        let res = self.handle_spdm_psk_finish_response(session_id, &receive_buffer[..receive_used]);
        if res.is_err() {
            if let Some(session) = self.common.get_session_via_id(session_id) {
                let _ = session.teardown(session_id);
            }
        }
        res
    }

    pub fn encode_spdm_psk_finish(&mut self, session_id: u32, buf: &mut [u8]) -> SpdmResult<usize> {
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
            .calc_req_transcript_hash(true, INVALID_SLOT, session)?;

        let session = self.common.get_session_via_id(session_id).unwrap();
        let hmac = session.generate_hmac_with_request_finished_key(transcript_hash.as_ref())?;

        self.common.append_message_f(session_id, hmac.as_ref())?;

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());
        Ok(send_used)
    }

    pub fn handle_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponsePskFinishRsp => {
                        let psk_finish_rsp =
                            SpdmPskFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let receive_used = reader.used();
                        if let Some(psk_finish_rsp) = psk_finish_rsp {
                            debug!("!!! psk_finish rsp : {:02x?}\n", psk_finish_rsp);
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;

                            self.common
                                .append_message_f(session_id, &receive_buffer[..receive_used])?;

                            let session = self
                                .common
                                .get_immutable_session_via_id(session_id)
                                .unwrap();

                            let th2 = self.common.calc_req_transcript_hash(
                                true,
                                INVALID_SLOT,
                                session,
                            )?;

                            debug!("!!! th2 : {:02x?}\n", th2.as_ref());

                            let session = self.common.get_session_via_id(session_id).unwrap();
                            session.generate_data_secret(spdm_version_sel, &th2)?;
                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
                            );

                            Ok(())
                        } else {
                            error!("!!! psk_finish : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskFinish,
                            SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}

#[cfg(all(test,))]
mod tests_requester {
    #[test]
    #[cfg(feature = "hashed-transcript-data")]
    fn test_case0_send_receive_spdm_psk_finish() {
        use super::*;
        use crate::common::session::SpdmSession;
        use crate::testlib::*;
        use crate::{crypto, responder};

        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();
        let data = &mut [
            0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca, 0xa7,
            0x51, 0x5a, 0x4d, 0x60, 0xcf, 0x4e, 0xc3, 0x17, 0x14, 0xa7, 0x55, 0x6f, 0x77, 0x56,
            0xad, 0xa4, 0xd0, 0x7e, 0xc2, 0xd4,
        ];

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
        crypto::hmac::register(HMAC_TEST.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

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
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);
        responder.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = responder.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

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
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);
        requester.common.session[0].runtime_info.digest_context_th = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let dhe_secret = SpdmDheFinalKeyStruct {
            data_size: 48,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        let _ = requester.common.session[0].set_dhe_secret(SpdmVersion::SpdmVersion11, dhe_secret);
        let status = requester.send_receive_spdm_psk_finish(4294901758).is_ok();
        assert!(status);
    }
}
