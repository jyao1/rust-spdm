// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::error::SpdmResult;
use crate::requester::*;

use crate::common::ManagedBuffer;

use crate::crypto;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_key_exchange(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<u32> {
        info!("send spdm key exchange\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let req_session_id = 0xFFFE;

        let random = [0xafu8; SPDM_RANDOM_SIZE];
        //let spdm_random = SpdmCryptoRandom {}; // TBD
        //spdm_random.get_random (&mut nonce);

        let (exchange, key_exchange_context) =
            crypto::dhe::generate_key_pair(self.common.negotiate_info.dhe_sel)
                .ok_or(spdm_err!(EFAULT))?;

        debug!("!!! exchange data : {:02x?}\n", exchange);
        let mut opaque = SpdmOpaqueStruct {
            data_size: crate::common::OPAQUE_DATA_SUPPORT_VERSION.len() as u16,
            ..Default::default()
        };
        opaque.data[..(opaque.data_size as usize)]
            .copy_from_slice(crate::common::OPAQUE_DATA_SUPPORT_VERSION.as_ref());
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestKeyExchange,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload {
                slot_id,
                measurement_summary_hash_type,
                req_session_id,
                random: SpdmRandomStruct { data: random },
                exchange,
                opaque,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let send_used = writer.used();

        self.send_message(&send_buffer[..send_used])?;

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
        let receive_used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..receive_used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseKeyExchangeRsp => {
                    let key_exchange_rsp =
                        SpdmKeyExchangeResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let receive_used = reader.used();
                    if let Some(key_exchange_rsp) = key_exchange_rsp {
                        debug!("!!! key_exchange rsp : {:02x?}\n", key_exchange_rsp);
                        debug!(
                            "!!! exchange data (peer) : {:02x?}\n",
                            &key_exchange_rsp.exchange
                        );

                        let final_key = key_exchange_context
                            .compute_final_key(&key_exchange_rsp.exchange)
                            .ok_or(spdm_err!(EFAULT))?;

                        debug!("!!! final_key : {:02x?}\n", final_key.as_ref());

                        // verify signature
                        let base_asym_size =
                            self.common.negotiate_info.base_asym_sel.get_size() as usize;
                        let base_hash_size =
                            self.common.negotiate_info.base_hash_sel.get_size() as usize;

                        let mut message_k = ManagedBuffer::default();
                        message_k
                            .append_message(&send_buffer[..send_used])
                            .ok_or(spdm_err!(ENOMEM))?;
                        let temp_receive_used = receive_used - base_asym_size - base_hash_size;
                        message_k
                            .append_message(&receive_buffer[..temp_receive_used])
                            .ok_or(spdm_err!(ENOMEM))?;

                        if self
                            .common
                            .verify_key_exchange_rsp_signature(
                                &message_k,
                                &key_exchange_rsp.signature,
                            )
                            .is_err()
                        {
                            error!("verify_key_exchange_rsp_signature fail");
                            return spdm_result_err!(EFAULT);
                        } else {
                            info!("verify_key_exchange_rsp_signature pass");
                        }
                        message_k
                            .append_message(key_exchange_rsp.signature.as_ref())
                            .ok_or(spdm_err!(ENOMEM))?;

                        // create session - generate the handshake secret (including finished_key)
                        let th1 = self
                            .common
                            .calc_req_transcript_hash(false, &message_k, None)?;
                        debug!("!!! th1 : {:02x?}\n", th1.as_ref());
                        let base_hash_algo = self.common.negotiate_info.base_hash_sel;
                        let dhe_algo = self.common.negotiate_info.dhe_sel;
                        let aead_algo = self.common.negotiate_info.aead_sel;
                        let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
                        let sequence_number_count =
                            self.common.transport_encap.get_sequence_number_count();
                        let max_random_count = self.common.transport_encap.get_max_random_count();

                        let session_id = ((req_session_id as u32) << 16)
                            + key_exchange_rsp.rsp_session_id as u32;
                        let session = self
                            .common
                            .get_next_avaiable_session()
                            .ok_or(spdm_err!(EINVAL))?;

                        session.setup(session_id).unwrap();
                        session.set_use_psk(false);

                        session.set_crypto_param(
                            base_hash_algo,
                            dhe_algo,
                            aead_algo,
                            key_schedule_algo,
                        );
                        session.set_transport_param(sequence_number_count, max_random_count);
                        session.set_dhe_secret(&final_key);
                        session.generate_handshake_secret(&th1).unwrap();

                        // verify HMAC with finished_key
                        let transcript_data = self
                            .common
                            .calc_req_transcript_data(false, &message_k, None)?;
                        let session = self
                            .common
                            .get_session_via_id(session_id)
                            .ok_or(spdm_err!(EINVAL))?;
                        if session
                            .verify_hmac_with_response_finished_key(
                                transcript_data.as_ref(),
                                &key_exchange_rsp.verify_data,
                            )
                            .is_err()
                        {
                            error!("verify_hmac_with_response_finished_key fail");
                            let _ = session.teardown(session_id);
                            return spdm_result_err!(EFAULT);
                        } else {
                            info!("verify_hmac_with_response_finished_key pass");
                        }
                        message_k
                            .append_message(key_exchange_rsp.verify_data.as_ref())
                            .ok_or(spdm_err!(ENOMEM))?;
                        session.runtime_info.message_k = message_k;

                        session.set_session_state(
                            crate::session::SpdmSessionState::SpdmSessionHandshaking,
                        );

                        Ok(session_id)
                    } else {
                        error!("!!! key_exchange : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
