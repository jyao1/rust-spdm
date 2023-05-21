// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use config::MAX_SPDM_PSK_CONTEXT_SIZE;

use crate::crypto;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::error::SPDM_STATUS_UNSUPPORTED_CAP;
#[cfg(feature = "hashed-transcript-data")]
use crate::error::{
    SpdmResult, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_SESSION_NUMBER_EXCEED, SPDM_STATUS_VERIF_FAIL,
};
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_SESSION_NUMBER_EXCEED, SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::SpdmMeasurementSummaryHashType;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_psk_exchange(
        &mut self,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<u32> {
        info!("send spdm psk exchange\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let half_session_id = self.common.get_next_half_session_id(true)?;
        let send_used = self.encode_spdm_psk_exchange(
            half_session_id,
            measurement_summary_hash_type,
            &mut send_buffer,
        )?;

        self.send_message(&send_buffer[..send_used])?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let receive_used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_psk_exchange_response(
            half_session_id,
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..receive_used],
        )
    }

    pub fn encode_spdm_psk_exchange(
        &mut self,
        half_session_id: u16,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        crypto::rand::get_random(&mut psk_context)?;

        let mut opaque;
        if self.common.negotiate_info.spdm_version_sel.get_u8()
            < SpdmVersion::SpdmVersion12.get_u8()
        {
            opaque = SpdmOpaqueStruct {
                data_size: crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0277
                    .len() as u16,
                ..Default::default()
            };
            opaque.data[..(opaque.data_size as usize)].copy_from_slice(
                crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0277.as_ref(),
            );
        } else if self.common.negotiate_info.opaque_data_support
            == SpdmOpaqueSupport::OPAQUE_DATA_FMT1
        {
            opaque = SpdmOpaqueStruct {
                data_size:
                    crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0274_FMT1
                        .len() as u16,
                ..Default::default()
            };
            opaque.data[..(opaque.data_size as usize)].copy_from_slice(
                crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0274_FMT1
                    .as_ref(),
            );
        } else {
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload {
                measurement_summary_hash_type,
                req_session_id: half_session_id,
                psk_hint: SpdmPskHintStruct::default(),
                psk_context: SpdmPskContextStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: psk_context,
                },
                opaque,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_psk_exchange_response(
        &mut self,
        half_session_id: u16,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<u32> {
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
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => {
                        let psk_exchange_rsp = SpdmPskExchangeResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let receive_used = reader.used();
                        if let Some(psk_exchange_rsp) = psk_exchange_rsp {
                            debug!("!!! psk_exchange rsp : {:02x?}\n", psk_exchange_rsp);

                            let base_hash_size =
                                self.common.negotiate_info.base_hash_sel.get_size() as usize;
                            let temp_receive_used = receive_used - base_hash_size;

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let mut message_k = ManagedBufferK::default();
                            #[cfg(feature = "hashed-transcript-data")]
                            let mut message_k = SpdmHashCtx::default();

                            self.common
                                .init_message_k(&mut message_k, INVALID_SLOT, true, true)?;
                            self.common.append_message_k(&mut message_k, send_buffer)?;
                            self.common.append_message_k(
                                &mut message_k,
                                &receive_buffer[..temp_receive_used],
                            )?;

                            // create session - generate the handshake secret (including finished_key)
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let th1 = self.common.calc_req_transcript_hash(
                                INVALID_SLOT,
                                true,
                                &message_k,
                                None,
                            )?;
                            #[cfg(feature = "hashed-transcript-data")]
                            let th1 = crypto::hash::hash_ctx_finalize(message_k.clone())
                                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
                            debug!("!!! th1 : {:02x?}\n", th1.as_ref());
                            let base_hash_algo = self.common.negotiate_info.base_hash_sel;
                            let dhe_algo = self.common.negotiate_info.dhe_sel;
                            let aead_algo = self.common.negotiate_info.aead_sel;
                            let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
                            let sequence_number_count =
                                self.common.transport_encap.get_sequence_number_count();
                            let max_random_count =
                                self.common.transport_encap.get_max_random_count();

                            let secure_spdm_version_sel = if let Some(secured_message_version) =
                                psk_exchange_rsp
                                    .opaque
                                    .req_get_dmtf_secure_spdm_version_selection(&mut self.common)
                            {
                                secured_message_version.get_secure_spdm_version()
                            } else {
                                0
                            };

                            let session_id = ((psk_exchange_rsp.rsp_session_id as u32) << 16)
                                + half_session_id as u32;
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                            let session = self
                                .common
                                .get_next_avaiable_session()
                                .ok_or(SPDM_STATUS_SESSION_NUMBER_EXCEED)?;

                            session.setup(session_id)?;

                            session.set_use_psk(true);
                            let mut psk_key = SpdmDheFinalKeyStruct {
                                data_size: b"TestPskData\0".len() as u16,
                                data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
                            };
                            psk_key.data[0..(psk_key.data_size as usize)]
                                .copy_from_slice(b"TestPskData\0");
                            session.set_crypto_param(
                                base_hash_algo,
                                dhe_algo,
                                aead_algo,
                                key_schedule_algo,
                            );
                            session.set_transport_param(sequence_number_count, max_random_count);
                            session.set_dhe_secret(spdm_version_sel, psk_key)?; // transfer the ownership out
                            session.generate_handshake_secret(spdm_version_sel, &th1)?;

                            // verify HMAC with finished_key
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let transcript_data = self.common.calc_req_transcript_data(
                                INVALID_SLOT,
                                true,
                                &message_k,
                                None,
                            )?;
                            let session = self
                                .common
                                .get_session_via_id(session_id)
                                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

                            session.init_message_k(&message_k)?;

                            if session
                                .verify_hmac_with_response_finished_key(
                                    #[cfg(not(feature = "hashed-transcript-data"))]
                                    transcript_data.as_ref(),
                                    #[cfg(feature = "hashed-transcript-data")]
                                    crypto::hash::hash_ctx_finalize(message_k.clone())
                                        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?
                                        .as_ref(),
                                    &psk_exchange_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                let _ = session.teardown(session_id);
                                return Err(SPDM_STATUS_VERIF_FAIL);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }

                            if session
                                .append_message_k(psk_exchange_rsp.verify_data.as_ref())
                                .is_err()
                            {
                                let _ = session.teardown(session_id);
                                return Err(SPDM_STATUS_BUFFER_FULL);
                            }

                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionHandshaking,
                            );

                            session.secure_spdm_version_sel = secure_spdm_version_sel;
                            session.heartbeat_period = psk_exchange_rsp.heartbeat_period;

                            Ok(session_id)
                        } else {
                            error!("!!! psk_exchange : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            None,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskExchange,
                            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
                        );
                        match status {
                            Err(status) => Err(status),
                            Ok(()) => Err(SPDM_STATUS_ERROR_PEER),
                        }
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
    fn test_case0_send_receive_spdm_psk_exchange() {
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
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone;
        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;

        let status = requester
            .send_receive_spdm_psk_exchange(measurement_summary_hash_type)
            .is_ok();
        assert!(status);
    }
}
