// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

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

        let nonce = [0xafu8; SPDM_NONCE_SIZE];
        //let spdm_random = SpdmCryptoRandom {}; // TBD
        //spdm_random.get_random (&mut nonce);

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
