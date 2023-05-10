// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBuffer;
use crate::common::SpdmCodec;
#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
use crate::error::SpdmResult;
#[cfg(feature = "hashed-transcript-data")]
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_INVALID_MSG_FIELD;
use crate::error::SPDM_STATUS_INVALID_PARAMETER;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::{SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_INVALID_STATE_LOCAL};
use crate::responder::*;

use crate::message::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_finish(&mut self, session_id: u32, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self
            .write_spdm_psk_finish_response(session_id, bytes, &mut writer)
            .is_ok()
        {
            self.send_secured_message(session_id, writer.used_slice(), false)?;
            // change state after message is sent.
            let session = self
                .common
                .get_session_via_id(session_id)
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
            session.set_session_state(
                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
            );
            Ok(())
        } else {
            self.send_message(writer.used_slice())
        }
    }

    // Return true on success, false otherwise
    pub fn write_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> SpdmResult {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let psk_finish_req = SpdmPskFinishRequestPayload::spdm_read(&mut self.common, &mut reader);

        if let Some(psk_finish_req) = &psk_finish_req {
            debug!("!!! psk_finish req : {:02x?}\n", psk_finish_req);
        } else {
            error!("!!! psk_finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }
        // Safety to call unwrap()
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        if !session.get_use_psk() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message_f = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            return Err(SPDM_STATUS_BUFFER_FULL);
        }

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            &bytes[..temp_used],
        )
        .unwrap();

        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_k = &session.runtime_info.message_k.clone();

        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data =
            self.common
                .calc_rsp_transcript_data(true, message_k, Some(&message_f));
        #[cfg(not(feature = "hashed-transcript-data"))]
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = transcript_data.unwrap();

        #[cfg(feature = "hashed-transcript-data")]
        let message_hash = crypto::hash::hash_ctx_finalize(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .cloned()
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
        );

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
        let res = session.verify_hmac_with_request_finished_key(
            #[cfg(not(feature = "hashed-transcript-data"))]
            transcript_data.as_ref(),
            #[cfg(feature = "hashed-transcript-data")]
            message_hash.unwrap().as_ref(),
            &psk_finish_req.verify_data,
        );
        if res.is_err() {
            error!("verify_hmac_with_request_finished_key fail");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return res;
        } else {
            info!("verify_hmac_with_request_finished_key pass");
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_f
            .append_message(psk_finish_req.verify_data.as_ref())
            .is_none()
        {
            error!("message_f add the message error");
            return Err(SPDM_STATUS_BUFFER_FULL);
        }

        #[cfg(feature = "hashed-transcript-data")]
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            psk_finish_req.verify_data.as_ref(),
        )
        .unwrap();

        info!("send spdm psk_finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        response.spdm_encode(&mut self.common, writer)?;

        #[cfg(feature = "hashed-transcript-data")]
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_f.append_message(writer.used_slice()).is_none() {
            panic!("message_f add the message error");
        }

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            writer.used_slice(),
        )
        .unwrap();

        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
        // generate the data secret
        let th2;
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            session.runtime_info.message_f = message_f.clone();
            th2 = self
                .common
                .calc_rsp_transcript_hash(true, message_k, Some(&message_f));
            if th2.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                let session = self
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
                let _ = session.teardown(session_id);
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }
        }
        #[cfg(feature = "hashed-transcript-data")]
        {
            th2 = crypto::hash::hash_ctx_finalize(
                session
                    .runtime_info
                    .digest_context_th
                    .as_mut()
                    .cloned()
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?,
            );
            if th2.is_none() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                let session = self
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
                let _ = session.teardown(session_id);
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            }
        }
        // Safely to call unwrap;
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;
        session.generate_data_secret(spdm_version_sel, &th2)
    }
}

#[cfg(all(test,))]
mod tests_responder {
    #[test]
    #[cfg(not(feature = "hashed-transcript-data"))]
    fn test_case0_handle_spdm_psk_finish() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::hmac::register(HMAC_TEST.clone());

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
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

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let psk_finish = &mut [0u8; 1024];
        let mut writer = Writer::init(psk_finish);
        let value = SpdmPskFinishRequestPayload {
            verify_data: SpdmDigestStruct {
                data_size: 48,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&psk_finish[0..1022]);
        context.handle_spdm_psk_finish(4294901758, bytes);
    }
}
