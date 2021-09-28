// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_heartbeat(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm heartbeat\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.encode_spdm_heartbeat(&mut send_buffer);
        self.send_secured_message(session_id, &send_buffer[..used])?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_secured_message(session_id, &mut receive_buffer)?;
        self.handle_spdm_heartbeat_response(&receive_buffer[..used])
    }

    pub fn encode_spdm_heartbeat(&mut self, buf: &mut [u8]) -> usize {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestHeartbeat,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        writer.used()
    }

    pub fn handle_spdm_heartbeat_response(&mut self, receive_buffer: &[u8]) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseHeartbeatAck => {
                    let heartbeat_rsp =
                        SpdmHeartbeatResponsePayload::spdm_read(&mut self.common, &mut reader);
                    if let Some(heartbeat_rsp) = heartbeat_rsp {
                        debug!("!!! heartbeat rsp : {:02x?}\n", heartbeat_rsp);
                        Ok(())
                    } else {
                        error!("!!! heartbeat : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_heartbeat() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let rsp_session_id = 0x11u16;
        let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.session = [SpdmSession::new(); 4];
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionHandshaking);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let rsp_session_id = 0x11u16;
        let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.session = [SpdmSession::new(); 4];
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionHandshaking);

        let status = requester.send_receive_spdm_heartbeat(session_id).is_ok();
        assert!(status);
    }
}
