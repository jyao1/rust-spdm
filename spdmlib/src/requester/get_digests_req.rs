// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
use crate::error::{spdm_result_err, SpdmResult};
use crate::message::*;
use crate::requester::*;

impl RequesterContext {
    pub fn send_receive_spdm_digest(
        &mut self,
        session_id: Option<u32>,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        info!("send spdm digest\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_digest(&mut send_buffer);
        if session_id.is_none() {
            self.send_message(&send_buffer[..send_used], transport_encap, device_io)?;
        } else {
            self.send_secured_message(
                session_id.unwrap(),
                &send_buffer[..send_used],
                false,
                transport_encap,
                device_io,
            )?;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = if session_id.is_none() {
            self.receive_message(&mut receive_buffer, false, transport_encap, device_io)?
        } else {
            self.receive_secured_message(
                session_id.unwrap(),
                &mut receive_buffer,
                false,
                transport_encap,
                device_io,
            )?
        };

        self.handle_spdm_digest_response(
            0,
            &send_buffer[..send_used],
            &receive_buffer[..used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_digest(&mut self, buf: &mut [u8]) -> usize {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        writer.used()
    }

    pub fn handle_spdm_digest_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return spdm_result_err!(EFAULT);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseDigests => {
                        let digests =
                            SpdmDigestsResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let used = reader.used();
                        if let Some(digests) = digests {
                            debug!("!!! digests : {:02x?}\n", digests);

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                let message_b = &mut self.common.runtime_info.message_b;
                                message_b
                                    .append_message(send_buffer)
                                    .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                                message_b
                                    .append_message(&receive_buffer[..used])
                                    .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                            }

                            #[cfg(feature = "hashed-transcript-data")]
                            {
                                crypto::hash::hash_ctx_update(
                                    self.common
                                        .runtime_info
                                        .digest_context_m1m2
                                        .as_mut()
                                        .unwrap(),
                                    send_buffer,
                                );
                                crypto::hash::hash_ctx_update(
                                    self.common
                                        .runtime_info
                                        .digest_context_m1m2
                                        .as_mut()
                                        .unwrap(),
                                    &receive_buffer[..used],
                                );
                            }

                            Ok(())
                        } else {
                            error!("!!! digests : fail !!!\n");
                            spdm_result_err!(EFAULT)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let erm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetDigests,
                            SpdmRequestResponseCode::SpdmResponseDigests,
                            transport_encap,
                            device_io,
                        );
                        match erm {
                            Ok(rm) => {
                                let receive_buffer = rm.receive_buffer;
                                let used = rm.used;
                                self.handle_spdm_digest_response(
                                    session_id,
                                    send_buffer,
                                    &receive_buffer[..used],
                                    transport_encap,
                                    device_io,
                                )
                            }
                            _ => spdm_result_err!(EINVAL),
                        }
                    }
                    _ => spdm_result_err!(EINVAL),
                }
            }
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_digest() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);
        responder.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let status = requester
            .send_receive_spdm_digest(None, pcidoe_transport_encap2, &mut device_io_requester)
            .is_ok();
        assert!(status);
    }
}
