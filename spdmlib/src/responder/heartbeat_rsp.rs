// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_heartbeat(&mut self, session_id: u32, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_heartbeat_response(session_id, bytes, &mut writer);
        let _ = self.send_secured_message(session_id, writer.used_slice(), false);
    }

    pub fn write_spdm_heartbeat_response(
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

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestHeartbeat,
            Some(session_id),
        );

        let heartbeat_req = SpdmHeartbeatRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(heartbeat_req) = heartbeat_req {
            debug!("!!! heartbeat req : {:02x?}\n", heartbeat_req);
        } else {
            error!("!!! heartbeat req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        info!("send spdm heartbeat rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload {}),
        };
        let _ = response.spdm_encode(&mut self.common, writer);
    }
}
#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::message::SpdmMessageHeader;
    use crate::protocol::gen_array_clone;
    use crate::responder;
    use crate::testlib::*;
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_heartbeat() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crate::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        let bytes = &mut [0u8; 1024];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        context.handle_spdm_heartbeat(session_id, bytes);
    }
}
