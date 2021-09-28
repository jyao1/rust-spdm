// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

use crate::common::ManagedBuffer;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_psk_finish(&mut self, session_id: u32) -> SpdmResult {
        info!("send spdm psk_finish\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let (send_used, message_f) = self.encode_spdm_psk_finish(session_id, &mut send_buffer)?;
        self.send_secured_message(session_id, &send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let receive_used = self.receive_secured_message(session_id, &mut receive_buffer)?;
        self.handle_spdm_psk_finish_response(session_id, message_f, &receive_buffer[..receive_used])
    }

    pub fn encode_spdm_psk_finish(
        &mut self,
        session_id: u32,
        buf: &mut [u8],
    ) -> SpdmResult<(usize, ManagedBuffer)> {
        let mut writer = Writer::init(buf);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestPskFinish,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(SpdmPskFinishRequestPayload {
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: [0xcc; SPDM_MAX_HASH_SIZE],
                },
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let send_used = writer.used();

        // generate HMAC with finished_key
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = send_used - base_hash_size;

        let mut message_f = ManagedBuffer::default();
        message_f
            .append_message(&buf[..temp_used])
            .ok_or(spdm_err!(ENOMEM))?;

        let session = self
            .common
            .get_immutable_session_via_id(session_id)
            .unwrap();
        let message_k = &session.runtime_info.message_k;

        let transcript_data =
            self.common
                .calc_req_transcript_data(true, message_k, Some(&message_f))?;
        let session = self.common.get_session_via_id(session_id).unwrap();
        let hmac = session.generate_hmac_with_request_finished_key(transcript_data.as_ref())?;
        message_f
            .append_message(hmac.as_ref())
            .ok_or(spdm_err!(ENOMEM))?;

        // patch the message before send
        buf[(send_used - base_hash_size)..send_used].copy_from_slice(hmac.as_ref());

        Ok((send_used, message_f))
    }

    pub fn handle_spdm_psk_finish_response(
        &mut self,
        session_id: u32,
        mut message_f: ManagedBuffer,
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponsePskFinishRsp => {
                    let psk_finish_rsp =
                        SpdmPskFinishResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let receive_used = reader.used();
                    if let Some(psk_finish_rsp) = psk_finish_rsp {
                        debug!("!!! psk_finish rsp : {:02x?}\n", psk_finish_rsp);
                        let session = self.common.get_session_via_id(session_id).unwrap();
                        message_f
                            .append_message(&receive_buffer[..receive_used])
                            .ok_or(spdm_err!(ENOMEM))?;
                        session.runtime_info.message_f = message_f;

                        let session = self
                            .common
                            .get_immutable_session_via_id(session_id)
                            .unwrap();
                        let message_k = &session.runtime_info.message_k; // generate the data secret
                        let th2 = self.common.calc_req_transcript_hash(
                            true,
                            &message_k,
                            Some(&message_f),
                        )?;
                        debug!("!!! th2 : {:02x?}\n", th2.as_ref());
                        let session = self.common.get_session_via_id(session_id).unwrap();
                        session.generate_data_secret(&th2).unwrap();
                        session.set_session_state(
                            crate::session::SpdmSessionState::SpdmSessionEstablished,
                        );

                        Ok(())
                    } else {
                        error!("!!! psk_finish : fail !!!\n");
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
    fn test_case0_send_receive_spdm_psk_finish() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();
        let data = &mut [
            0x1, 0x0, 0x2, 0x0, 0x9, 0x0, 0x0, 0x0, 0xfe, 0xff, 0xfe, 0xff, 0x16, 0x0, 0xca, 0xa7,
            0x51, 0x5a, 0x4d, 0x60, 0xcf, 0x4e, 0xc3, 0x17, 0x14, 0xa7, 0x55, 0x6f, 0x77, 0x56,
            0xad, 0xa4, 0xd0, 0x7e, 0xc2, 0xd4,
        ];

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);

        // let shared_buffer = SharedBuffer::new();
        // let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        crypto::hmac::register(HMAC_TEST);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        responder.common.session = [SpdmSession::new(); 4];
        responder.common.session[0].setup(4294901758).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        // let rsp_session_id = 0x11u16;
        // let session_id = (0x11u32 << 16) + rsp_session_id as u32;
        requester.common.session = [SpdmSession::new(); 4];
        requester.common.session[0].setup(4294901758).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);
        let status = requester.send_receive_spdm_psk_finish(4294901758).is_ok();
        assert!(status);
    }
}
