// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

use crate::common::ManagedBuffer;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_psk_finish(&mut self, session_id: u32, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self.write_spdm_psk_finish_response(session_id, bytes, &mut writer) {
            let _ = self.send_secured_message(session_id, writer.used_slice());
            // change state after message is sent.
            let session = self.common.get_session_via_id(session_id).unwrap();
            session.set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);
        } else {
            let _ = self.send_message(writer.used_slice());
        }
    }

    // Return true on success, false otherwise
    pub fn write_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) -> bool {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let psk_finish_req = SpdmPskFinishRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(psk_finish_req) = psk_finish_req {
            debug!("!!! psk_finish req : {:02x?}\n", psk_finish_req);
        } else {
            error!("!!! psk_finish req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        }
        let psk_finish_req = psk_finish_req.unwrap();
        let read_used = reader.used();

        // verify HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = read_used - base_hash_size;

        let mut message_f = ManagedBuffer::default();
        if message_f.append_message(&bytes[..temp_used]).is_none() {
            panic!("message_f add the message error");
        }

        let session = self.common.get_session_via_id(session_id).unwrap();
        let message_k = session.runtime_info.message_k;

        let transcript_data =
            self.common
                .calc_rsp_transcript_data(true, &message_k, Some(&message_f));
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        }
        let transcript_data = transcript_data.unwrap();
        let session = self.common.get_session_via_id(session_id).unwrap();
        if session
            .verify_hmac_with_request_finished_key(
                transcript_data.as_ref(),
                &psk_finish_req.verify_data,
            )
            .is_err()
        {
            error!("verify_hmac_with_request_finished_key fail");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return false;
        } else {
            info!("verify_hmac_with_request_finished_key pass");
        }
        if message_f
            .append_message(psk_finish_req.verify_data.as_ref())
            .is_none()
        {
            panic!("message_f add the message error");
        }

        info!("send spdm psk_finish rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };

        response.spdm_encode(&mut self.common, writer);

        if message_f.append_message(writer.used_slice()).is_none() {
            panic!("message_f add the message error");
        }
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.runtime_info.message_f = message_f;

        // generate the data secret
        let th2 = self
            .common
            .calc_rsp_transcript_hash(true, &message_k, Some(&message_f));
        if th2.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            let session = self.common.get_session_via_id(session_id).unwrap();
            let _ = session.teardown(session_id);
            return false;
        }
        let th2 = th2.unwrap();
        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.generate_data_secret(&th2).unwrap();

        true
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_psk_finish() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        crypto::hmac::register(HMAC_TEST);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        context.common.session = [SpdmSession::new(); 4];
        context.common.session[0].setup(4294901758).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let psk_finish = &mut [0u8; 1024];
        let mut writer = Writer::init(psk_finish);
        let value = SpdmPskFinishRequestPayload {
            verify_data: SpdmDigestStruct {
                data_size: 48,
                data: [100u8; SPDM_MAX_HASH_SIZE],
            },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&psk_finish[0..1022]);
        context.handle_spdm_psk_finish(4294901758, bytes);
    }
}
