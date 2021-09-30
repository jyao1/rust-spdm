// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_end_session(&mut self, session_id: u32, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self.write_spdm_end_session_response(bytes, &mut writer) {
            let _ = self.send_secured_message(session_id, writer.used_slice());
        } else {
            let _ = self.send_message(writer.used_slice());
        }
    }

    pub fn write_spdm_end_session_response(&mut self, bytes: &[u8], writer: &mut Writer) -> bool {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let end_session_req =
            SpdmEndSessionRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(end_session_req) = end_session_req {
            debug!("!!! end_session req : {:02x?}\n", end_session_req);
        } else {
            error!("!!! end_session req : fail !!!\n");
            return false;
        }

        info!("send spdm end_session rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        response.spdm_encode(&mut self.common, writer);
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
    fn test_case0_handle_spdm_end_session() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let session_request = &mut [0u8; 1024];
        let mut writer = Writer::init(session_request);
        let value = SpdmEndSessionRequestPayload {
            end_session_request_attributes:
                SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
        };
        value.spdm_encode(&mut context.common, &mut writer);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.session = [SpdmSession::new(); 4];
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&session_request[0..1022]);
        context.handle_spdm_end_session(session_id, bytes);
    }
}
