// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
use crate::protocol::*;
use crate::responder::*;

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBuffer;
use crate::message::*;
extern crate alloc;
use alloc::boxed::Box;

impl ResponderContext {
    pub fn handle_spdm_finish(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self.write_spdm_finish_response(session_id, bytes, &mut writer) {
            let _ = self.send_secured_message(
                session_id,
                writer.used_slice(),
                false,
                transport_encap,
                device_io,
            );
            // change state after message is sent.
            let session = self.common.get_session_via_id(session_id).unwrap();
            session.set_session_state(
                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
            );
        } else {
            let _ = self.send_message(writer.used_slice(), transport_encap, device_io);
        }
    }

    // Return true on success, false otherwise.
    pub fn write_spdm_finish_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> bool {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let finish_req = SpdmFinishRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(finish_req) = &finish_req {
            debug!("!!! finish req : {:02x?}\n", finish_req);
        } else {
            error!("!!! finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        }
        let finish_req = finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message_f = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            panic!("message_f add the message error");
        }

        #[cfg(not(feature = "hashed-transcript-data"))]
        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_k = &session.runtime_info.message_k.clone();
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data =
            &self
                .common
                .calc_rsp_transcript_data(false, message_k, Some(&message_f));
        #[cfg(not(feature = "hashed-transcript-data"))]
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = transcript_data.as_ref().unwrap();

        {
            let session = self.common.get_session_via_id(session_id).unwrap();

            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                &bytes[..temp_used],
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

            if session
                .verify_hmac_with_request_finished_key(
                    #[cfg(not(feature = "hashed-transcript-data"))]
                    transcript_data.as_ref(),
                    #[cfg(feature = "hashed-transcript-data")]
                    message_hash.unwrap().as_ref(),
                    &finish_req.verify_data,
                )
                .is_err()
            {
                error!("verify_hmac_with_request_finished_key fail");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return false;
            } else {
                info!("verify_hmac_with_request_finished_key pass");
            }

            #[cfg(not(feature = "hashed-transcript-data"))]
            if message_f
                .append_message(finish_req.verify_data.as_ref())
                .is_none()
            {
                panic!("message_f add the message error");
            }

            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                finish_req.verify_data.as_ref(),
            );
        }

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

        info!("send spdm finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(SpdmFinishResponsePayload {
                verify_data: SpdmDigestStruct {
                    data_size: (self as &ResponderContext)
                        .common
                        .negotiate_info
                        .base_hash_sel
                        .get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        #[cfg(feature = "hashed-transcript-data")]
        let session = self.common.get_session_via_id(session_id).unwrap();

        if in_clear_text {
            // generate HMAC with finished_key
            let temp_used = used - base_hash_size;
            #[cfg(not(feature = "hashed-transcript-data"))]
            if message_f
                .append_message(&writer.used_slice()[..temp_used])
                .is_none()
            {
                panic!("message_f add the message error");
            }

            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                &writer.used_slice()[..temp_used],
            );

            #[cfg(not(feature = "hashed-transcript-data"))]
            let transcript_data =
                self.common
                    .calc_rsp_transcript_data(false, message_k, Some(&message_f));
            #[cfg(not(feature = "hashed-transcript-data"))]
            if transcript_data.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                return false;
            }
            #[cfg(not(feature = "hashed-transcript-data"))]
            let transcript_data = transcript_data.unwrap();

            #[cfg(not(feature = "hashed-transcript-data"))]
            let session = self.common.get_session_via_id(session_id).unwrap();

            #[cfg(not(feature = "hashed-transcript-data"))]
            let hmac = session.generate_hmac_with_response_finished_key(transcript_data.as_ref());

            #[cfg(feature = "hashed-transcript-data")]
            let message_hash = crypto::hash::hash_ctx_finalize(
                session
                    .runtime_info
                    .digest_context_th
                    .as_mut()
                    .cloned()
                    .unwrap(),
            );

            #[cfg(feature = "hashed-transcript-data")]
            let hmac =
                session.generate_hmac_with_response_finished_key(message_hash.unwrap().as_ref());
            if hmac.is_err() {
                let _ = session.teardown(session_id);
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return false;
            }
            let hmac = hmac.unwrap();
            #[cfg(not(feature = "hashed-transcript-data"))]
            if message_f.append_message(hmac.as_ref()).is_none() {
                let _ = session.teardown(session_id);
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return false;
            } else {
                session.runtime_info.message_f = message_f.clone();
            }

            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                hmac.as_ref(),
            );

            // patch the message before send
            writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
        } else {
            #[cfg(not(feature = "hashed-transcript-data"))]
            if message_f.append_message(writer.used_slice()).is_none() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                let session = self.common.get_session_via_id(session_id).unwrap();
                let _ = session.teardown(session_id);
                return false;
            } else {
                let session = self.common.get_session_via_id(session_id).unwrap();
                session.runtime_info.message_f = message_f.clone();
            }
            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                session.runtime_info.digest_context_th.as_mut().unwrap(),
                writer.used_slice(),
            );
        }

        // generate the data secret
        #[cfg(not(feature = "hashed-transcript-data"))]
        let th2 = self
            .common
            .calc_rsp_transcript_hash(false, message_k, Some(&message_f));
        #[cfg(feature = "hashed-transcript-data")]
        let th2 = crypto::hash::hash_ctx_finalize(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .cloned()
                .unwrap(),
        );
        #[cfg(feature = "hashed-transcript-data")]
        if th2.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            let session = self.common.get_session_via_id(session_id).unwrap();
            let _ = session.teardown(session_id);
            return false;
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        if th2.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            let session = self.common.get_session_via_id(session_id).unwrap();
            let _ = session.teardown(session_id);
            return false;
        }
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session
            .generate_data_secret(spdm_version_sel, &th2)
            .unwrap();

        true
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
    #[cfg(not(feature = "hashed-transcript-data"))]
    fn test_case0_handle_spdm_finish() {
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
        crypto::hmac::register(HMAC_TEST.clone());

        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(4294901758).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        context.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let value = SpdmChallengeRequestPayload {
            slot_id: 100,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            nonce: SpdmNonceStruct { data: [100u8; 32] },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let finish_slic: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(finish_slic);
        let value = SpdmFinishRequestPayload {
            finish_request_attributes: SpdmFinishRequestAttributes::empty(),
            req_slot_id: 100,
            signature: SpdmSignatureStruct {
                data_size: 512,
                data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
            },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&finish_slic[0..1022]);
        context.handle_spdm_finish(4294901758, bytes);
    }
    #[test]
    fn test_case1_handle_spdm_finish() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::hmac::register(HMAC_TEST.clone());

        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
        context.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(4294901758).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        context.common.session[0].runtime_info.digest_context_th =
            Some(crypto::hash::hash_ctx_init(context.common.negotiate_info.base_hash_sel).unwrap());

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let value = SpdmChallengeRequestPayload {
            slot_id: 100,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            nonce: SpdmNonceStruct { data: [100u8; 32] },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let finish_slic: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(finish_slic);
        let value = SpdmFinishRequestPayload {
            finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
            req_slot_id: 100,
            signature: SpdmSignatureStruct {
                data_size: 96,
                data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 48,
                data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
            },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&finish_slic[0..1022]);
        context.handle_spdm_finish(
            4294901758,
            bytes,
            pcidoe_transport_encap,
            &mut socket_io_transport,
        );
    }
}
