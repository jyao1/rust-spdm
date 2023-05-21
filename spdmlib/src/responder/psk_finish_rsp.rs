// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::INVALID_SLOT;
use crate::responder::*;

use crate::message::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_finish(&mut self, session_id: u32, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_psk_finish_response(session_id, bytes, &mut writer);
        let _ = self.send_secured_message(session_id, writer.used_slice(), false);
    }

    // Return true on success, false otherwise
    pub fn write_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let psk_finish_req = SpdmPskFinishRequestPayload::spdm_read(&mut self.common, &mut reader);

        if let Some(psk_finish_req) = &psk_finish_req {
            debug!("!!! psk_finish req : {:02x?}\n", psk_finish_req);
        } else {
            error!("!!! psk_finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        // Safety to call unwrap()
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;

        let temp_used = read_used - base_hash_size;

        {
            let session = self.common.get_session_via_id(session_id).unwrap();

            if !session.get_use_psk() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return;
            }

            if session.append_message_f(&bytes[..temp_used]).is_err() {
                error!("message_f add the message error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return;
            }

            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();

            let transcript_hash = self
                .common
                .calc_rsp_transcript_hash(true, INVALID_SLOT, session);
            if transcript_hash.is_err() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return;
            }
            let transcript_hash = transcript_hash.as_ref().unwrap();

            let session = self
                .common
                .get_immutable_session_via_id(session_id)
                .unwrap();
            let res = session.verify_hmac_with_request_finished_key(
                transcript_hash.as_ref(),
                &psk_finish_req.verify_data,
            );
            if res.is_err() {
                error!("verify_hmac_with_request_finished_key fail");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorDecryptError, 0, writer);
                return;
            } else {
                info!("verify_hmac_with_request_finished_key pass");
            }

            let session = self.common.get_session_via_id(session_id).unwrap();

            if session
                .append_message_f(psk_finish_req.verify_data.as_ref())
                .is_err()
            {
                error!("message_f add the message error");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                return;
            }
        }

        info!("send spdm psk_finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        response.spdm_encode(&mut self.common, writer).unwrap();

        let session = self.common.get_session_via_id(session_id).unwrap();

        if session.append_message_f(writer.used_slice()).is_err() {
            error!("message_f add the message error");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        // generate the data secret
        let th2 = self.common.calc_rsp_transcript_hash(true, 0, session);
        if th2.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }
        // Safely to call unwrap;
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session
            .generate_data_secret(spdm_version_sel, &th2)
            .unwrap();
    }
}

#[cfg(all(test,))]
mod tests_responder {
    #[test]
    #[cfg(not(feature = "hashed-transcript-data"))]
    fn test_case0_handle_spdm_psk_finish() {
        use super::*;
        use crate::common::session::*;
        use crate::crypto;
        use crate::message::*;
        use crate::protocol::*;
        use crate::responder;
        use crate::testlib::*;

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
        let _ = value.encode(&mut writer);

        let psk_finish = &mut [0u8; 1024];
        let mut writer = Writer::init(psk_finish);
        let value = SpdmPskFinishRequestPayload {
            verify_data: SpdmDigestStruct {
                data_size: 48,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };
        let _ = value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&psk_finish[0..1022]);
        context.handle_spdm_psk_finish(4294901758, bytes);
    }
}
