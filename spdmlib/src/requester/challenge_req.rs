// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    pub fn send_receive_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        info!("send spdm challenge\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used =
            self.encode_spdm_challenge(slot_id, measurement_summary_hash_type, &mut send_buffer)?;
        self.send_message(&send_buffer[..send_used], transport_encap, device_io)?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, true, transport_encap, device_io)?;
        self.handle_spdm_challenge_response(
            0, // NULL
            slot_id,
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        crypto::rand::get_random(&mut nonce)?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(SpdmChallengeRequestPayload {
                slot_id,
                measurement_summary_hash_type,
                nonce: SpdmNonceStruct { data: nonce },
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        Ok(writer.used())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_challenge_response(
        &mut self,
        session_id: u32,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        if (measurement_summary_hash_type
            == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
            || (measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
        {
            self.common.runtime_info.need_measurement_summary_hash = true;
        } else {
            self.common.runtime_info.need_measurement_summary_hash = false;
        }

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return spdm_result_err!(EFAULT);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseChallengeAuth => {
                        let challenge_auth = SpdmChallengeAuthResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(challenge_auth) = challenge_auth {
                            debug!("!!! challenge_auth : {:02x?}\n", challenge_auth);

                            // verify signature
                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used - base_asym_size;

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                let message_c = &mut self.common.runtime_info.message_c;
                                message_c
                                    .append_message(send_buffer)
                                    .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                                message_c
                                    .append_message(&receive_buffer[..temp_used])
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
                                    &receive_buffer[..temp_used],
                                );
                            }

                            if self
                                .verify_challenge_auth_signature(slot_id, &challenge_auth.signature)
                                .is_err()
                            {
                                error!("verify_challenge_auth_signature fail");
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_challenge_auth_signature pass");
                            }

                            Ok(())
                        } else {
                            error!("!!! challenge_auth : fail !!!\n");
                            spdm_result_err!(EFAULT)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let erm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestChallenge,
                            SpdmRequestResponseCode::SpdmResponseChallengeAuth,
                            transport_encap,
                            device_io,
                        );
                        match erm {
                            Ok(rm) => {
                                let receive_buffer = rm.receive_buffer;
                                let used = rm.used;
                                self.handle_spdm_challenge_response(
                                    session_id,
                                    slot_id,
                                    measurement_summary_hash_type,
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

    pub fn verify_challenge_auth_signature(
        &mut self,
        slot_id: u8,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            message
                .append_message(self.common.runtime_info.message_a.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(self.common.runtime_info.message_b.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(self.common.runtime_info.message_c.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
        }

        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        #[cfg(feature = "hashed-transcript-data")]
        let message_hash;
        #[cfg(feature = "hashed-transcript-data")]
        {
            let digest = crypto::hash::hash_ctx_finalize(
                self.common
                    .runtime_info
                    .digest_context_m1m2
                    .as_mut()
                    .cloned()
                    .unwrap(),
            );
            if let Some(digest) = digest {
                message_hash = digest;
            } else {
                return spdm_result_err!(ESEC);
            }
        }
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return spdm_result_err!(EINVAL);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .unwrap()
            .cert_chain
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .unwrap()
                .cert_chain
                .data_size as usize)];

        #[cfg(feature = "hashed-transcript-data")]
        let mut message = ManagedBuffer::default();

        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_4)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_CHALLENGE_AUTH_SIGN_CONTEXT)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(message_hash.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
        }

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message.as_ref(),
            signature,
        )
    }
}
#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_challenge() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::rand::register(DEFAULT_TEST.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.runtime_info.need_measurement_summary_hash = true;

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
        requester.common.reset_runtime_info();

        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.runtime_info.need_measurement_summary_hash = true;

        requester.common.peer_info.peer_cert_chain[0] = Some(SpdmCertChain::default());
        requester.common.peer_info.peer_cert_chain[0]
            .as_mut()
            .unwrap()
            .cert_chain = REQ_CERT_CHAIN_DATA;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        requester.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        let status = requester
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
