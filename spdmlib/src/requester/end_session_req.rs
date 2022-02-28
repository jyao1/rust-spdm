// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::SpdmResult;
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_end_session(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm end_session\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.encode_spdm_end_session(&mut send_buffer);
        self.send_secured_message(session_id, &send_buffer[..used], false)?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_secured_message(session_id, &mut receive_buffer, false)?;
        self.handle_spdm_end_session_response(session_id, &receive_buffer[..used])
    }

    pub fn encode_spdm_end_session(&mut self, buf: &mut [u8]) -> usize {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        writer.used()
    }

    pub fn handle_spdm_end_session_response(
        &mut self,
        session_id: u32,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseEndSessionAck => {
                    let end_session_rsp =
                        SpdmEndSessionResponsePayload::spdm_read(&mut self.common, &mut reader);
                    if let Some(end_session_rsp) = end_session_rsp {
                        debug!("!!! end_session rsp : {:02x?}\n", end_session_rsp);

                        let session = self.common.get_session_via_id(session_id).unwrap();
                        session.teardown(session_id)?;

                        Ok(())
                    } else {
                        error!("!!! end_session : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let erm = self.spdm_handle_error_response_main(
                        session_id,
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestEndSession,
                        SpdmRequestResponseCode::SpdmResponseEndSessionAck,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_end_session_response(
                                session_id,
                                &receive_buffer[..used],
                            )
                        }
                        _ => spdm_result_err!(EINVAL),
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
    use crate::common::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_end_session() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);

        let status = requester.end_session(session_id).is_ok();
        assert!(status);
    }
}
