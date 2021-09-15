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
        let mut writer = Writer::init(&mut send_buffer);

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
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        // append message_c
        if self
            .common
            .runtime_info
            .message_c
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }

        if (measurement_summary_hash_type
            == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
            || (measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
        {
            self.common.runtime_info.need_measurement_summary_hash = true;
        } else {
            self.common.runtime_info.need_measurement_summary_hash = false;
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
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
                        if self
                            .common
                            .runtime_info
                            .message_c
                            .append_message(&receive_buffer[..temp_used])
                            .is_none()
                        {
                            return spdm_result_err!(ENOMEM);
                        }
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
    fn test_case0_handle_spdm_algorithm() {
        let data = &mut [
            0x1, 0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x11, 0x3, 0x0, 0x1, 0x28, 0xaf, 0x70, 0x27,
            0xbc, 0x2d, 0x95, 0xb5, 0xa0, 0xe4, 0x26, 0x4, 0xc5, 0x8c, 0x5c, 0x3c, 0xbf, 0xa2,
            0xc8, 0x24, 0xa6, 0x30, 0xca, 0x2f, 0xf, 0x4a, 0x79, 0x35, 0x57, 0xfb, 0x39, 0x3b,
            0xdd, 0x8a, 0xc8, 0x8a, 0x92, 0xd8, 0xa3, 0x70, 0x17, 0x12, 0x83, 0x9b, 0x66, 0xe1,
            0x3a, 0x3a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0x3, 0x76, 0xd, 0x57, 0x9b, 0xaf, 0xe9,
            0x6f, 0xc2, 0x5c, 0x2f, 0x3a, 0xfb, 0x81, 0xb, 0x4f, 0xa4, 0x5a, 0x65, 0x4a, 0xc8,
            0x64, 0x38, 0x91, 0xb1, 0x89, 0x8d, 0x42, 0xe9, 0xff, 0x55, 0xb, 0xfd, 0xb1, 0xe1,
            0x3c, 0x19, 0x1f, 0x1e, 0x8, 0xa2, 0x78, 0xd, 0xf3, 0x6, 0x6a, 0xfa, 0xe, 0xee, 0xde,
            0x27, 0x9, 0xb3, 0x20, 0xa1, 0xf5, 0x8d, 0x6e, 0xfc, 0x8a, 0x30, 0x91, 0x5, 0x80, 0xae,
            0x89, 0xb4, 0xee, 0x38, 0xcc, 0x92, 0x8e, 0x5e, 0x5b, 0x25, 0x10, 0xdb, 0xd8, 0x32,
            0x11, 0xd7, 0xf8, 0x23, 0x76, 0x49, 0x3d, 0x96, 0x7e, 0xb3, 0x22, 0x4c, 0x5d, 0x50,
            0x79, 0x71, 0x98, 0x0, 0x0,
        ];
        
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = SpdmDeviceIoReceve::new(&shared_buffer, data);

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
