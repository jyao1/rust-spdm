// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "hashed-transcript-data")]
use crate::crypto;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::error::{SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD};
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_digest(&mut self, session_id: Option<u32>) -> SpdmResult {
        info!("send spdm digest\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_digest(&mut send_buffer);
        if session_id.is_none() {
            self.send_message(&send_buffer[..send_used])?;
        } else {
            self.send_secured_message(session_id.unwrap(), &send_buffer[..send_used], false)?;
        }

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = if session_id.is_none() {
            self.receive_message(&mut receive_buffer, false)?
        } else {
            self.receive_secured_message(session_id.unwrap(), &mut receive_buffer, false)?
        };

        self.handle_spdm_digest_response(0, &send_buffer[..send_used], &receive_buffer[..used])
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
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
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
                                    .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
                                message_b
                                    .append_message(&receive_buffer[..used])
                                    .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
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
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let rm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetDigests,
                            SpdmRequestResponseCode::SpdmResponseDigests,
                        )?;
                        let receive_buffer = rm.receive_buffer;
                        let used = rm.used;
                        self.handle_spdm_digest_response(
                            session_id,
                            send_buffer,
                            &receive_buffer[..used],
                        )
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
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

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );
        responder.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let status = requester.send_receive_spdm_digest(None).is_ok();
        assert!(status);
    }
}
