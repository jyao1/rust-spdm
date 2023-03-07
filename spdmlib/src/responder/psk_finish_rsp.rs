// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBuffer;
use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
use crate::error::SpdmResult;
use crate::responder::*;

use crate::message::*;

impl ResponderContext {
    pub fn handle_spdm_psk_finish(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self
            .write_spdm_psk_finish_response(session_id, bytes, &mut writer)
            .is_ok()
        {
            self.send_secured_message(
                session_id,
                writer.used_slice(),
                false,
                transport_encap,
                device_io,
            )?;
            // change state after message is sent.
            let session = self
                .common
                .get_session_via_id(session_id)
                .ok_or(spdm_err!(EINVAL))?;
            session.set_session_state(
                crate::common::session::SpdmSessionState::SpdmSessionEstablished,
            );
            Ok(())
        } else {
            self.send_message(writer.used_slice(), transport_encap, device_io)
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
            return spdm_result_err!(EINVAL);
        }
        // Safety to call unwrap()
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message_f = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            return spdm_result_err!(EINVAL);
        }

        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .ok_or(spdm_err!(EINVAL))?,
            &bytes[..temp_used],
        );

        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_k = &session.runtime_info.message_k.clone();

        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data =
            self.common
                .calc_rsp_transcript_data(true, message_k, Some(&message_f));
        #[cfg(not(feature = "hashed-transcript-data"))]
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EINVAL);
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
                .ok_or(spdm_err!(EINVAL))?,
        );

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;
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
            return spdm_result_err!(EINVAL);
        }

        #[cfg(feature = "hashed-transcript-data")]
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            session
                .runtime_info
                .digest_context_th
                .as_mut()
                .ok_or(spdm_err!(EINVAL))?,
            psk_finish_req.verify_data.as_ref(),
        );

        info!("send spdm psk_finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        response.spdm_encode(&mut self.common, writer);

        #[cfg(feature = "hashed-transcript-data")]
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

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
                .ok_or(spdm_err!(EINVAL))?,
            writer.used_slice(),
        );

        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;
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
                    .ok_or(spdm_err!(EINVAL))?;
                let _ = session.teardown(session_id);
                return spdm_result_err!(EINVAL);
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
                    .ok_or(spdm_err!(EINVAL))?,
            );
            if th2.is_none() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                let session = self
                    .common
                    .get_session_via_id(session_id)
                    .ok_or(spdm_err!(EINVAL))?;
                let _ = session.teardown(session_id);
                return spdm_result_err!(EINVAL);
            }
        }
        // Safely to call unwrap;
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;
        session.generate_data_secret(spdm_version_sel, &th2)
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
