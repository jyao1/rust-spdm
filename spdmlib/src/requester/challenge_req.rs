// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_challenge(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult {
        info!("send spdm challenge\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let send_used =
            self.encode_spdm_challenge(slot_id, measurement_summary_hash_type, &mut send_buffer)?;
        self.send_message(&send_buffer[..send_used])?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;
        self.handle_spdm_challenge_response(
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..used],
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
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
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

    pub fn handle_spdm_challenge_response(
        &mut self,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
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
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseChallengeAuth => {
                    let challenge_auth =
                        SpdmChallengeAuthResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(challenge_auth) = challenge_auth {
                        debug!("!!! challenge_auth : {:02x?}\n", challenge_auth);

                        // verify signature
                        let base_asym_size =
                            self.common.negotiate_info.base_asym_sel.get_size() as usize;
                        let temp_used = used - base_asym_size;

                        let message_c = &mut self.common.runtime_info.message_c;
                        message_c
                            .append_message(send_buffer)
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        message_c
                            .append_message(&receive_buffer[..temp_used])
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;

                        if self
                            .common
                            .verify_challenge_auth_signature(&challenge_auth.signature)
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
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
#[cfg(test)]
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

        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        crypto::rand::register(DEFAULT_TEST);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.reset_runtime_info();
        responder.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.runtime_info.need_measurement_summary_hash = true;

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );
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

        requester.common.peer_info.peer_cert_chain.cert_chain = REQ_CERT_CHAIN_DATA;

        let status = requester
            .send_receive_spdm_challenge(
                0,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            )
            .is_ok();
        assert!(status);
    }
}
