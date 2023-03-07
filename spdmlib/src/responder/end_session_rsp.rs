// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::{SpdmCodec, SpdmDeviceIo, SpdmTransportEncap};
use crate::error::{spdm_err, SpdmResult};
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_end_session(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        if self.write_spdm_end_session_response(bytes, &mut writer) {
            self.send_secured_message(
                session_id,
                writer.used_slice(),
                false,
                transport_encap,
                device_io,
            )?;
            let session = self
                .common
                .get_session_via_id(session_id)
                .ok_or(spdm_err!(EINVAL))?;
            session.teardown(session_id)
        } else {
            self.send_message(writer.used_slice(), transport_encap, device_io)
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
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        response.spdm_encode(&mut self.common, writer);
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
    fn test_case0_handle_spdm_end_session() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
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
        context.common.session = gen_array_clone(SpdmSession::new(), 4);
        context.common.session[0].setup(session_id).unwrap();
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&session_request[0..1022]);
        let _ = context.handle_spdm_end_session(
            session_id,
            bytes,
            pcidoe_transport_encap,
            &mut socket_io_transport,
        );
    }
}
