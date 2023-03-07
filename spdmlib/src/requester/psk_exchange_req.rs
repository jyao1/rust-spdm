// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use config::MAX_SPDM_PSK_CONTEXT_SIZE;

use crate::crypto;
use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::SpdmMeasurementSummaryHashType;
use crate::protocol::*;
use crate::requester::*;
extern crate alloc;
use alloc::boxed::Box;

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBuffer;

const INITIAL_SESSION_ID: u16 = 0xFFFD;

impl RequesterContext {
    pub fn send_receive_spdm_psk_exchange(
        &mut self,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<u32> {
        info!("send spdm psk exchange\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used =
            self.encode_spdm_psk_exchange(measurement_summary_hash_type, &mut send_buffer)?;

        self.send_message(&send_buffer[..send_used], transport_encap, device_io)?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let receive_used =
            self.receive_message(&mut receive_buffer, false, transport_encap, device_io)?;
        self.handle_spdm_psk_exchange_response(
            0,
            measurement_summary_hash_type,
            &send_buffer[..send_used],
            &receive_buffer[..receive_used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_psk_exchange(
        &mut self,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);

        let req_session_id = INITIAL_SESSION_ID;

        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        crypto::rand::get_random(&mut psk_context)?;

        let mut opaque;
        if self
            .common
            .negotiate_info
            .opaque_data_support
            .contains(SpdmOpaqueSupport::OPAQUE_DATA_FMT1)
        {
            opaque = SpdmOpaqueStruct {
                data_size: crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT1
                    .len() as u16,
                ..Default::default()
            };
            opaque.data[..(opaque.data_size as usize)].copy_from_slice(
                crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT1.as_ref(),
            );
        } else {
            opaque = SpdmOpaqueStruct {
                data_size: crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT0
                    .len() as u16,
                ..Default::default()
            };
            opaque.data[..(opaque.data_size as usize)].copy_from_slice(
                crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT0.as_ref(),
            );
        }

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload {
                measurement_summary_hash_type,
                req_session_id,
                psk_hint: SpdmPskHintStruct::default(),
                psk_context: SpdmPskContextStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: psk_context,
                },
                opaque,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        Ok(writer.used())
    }

    pub fn handle_spdm_psk_exchange_response(
        &mut self,
        session_id: u32,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
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
                    return spdm_result_err!(EFAULT);
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

                            #[cfg(feature = "hashed-transcript-data")]
                            let mut digest_context_th = crypto::hash::hash_ctx_init(
                                self.common.negotiate_info.base_hash_sel,
                            )
                            .unwrap();
                            #[cfg(feature = "hashed-transcript-data")]
                            {
                                crypto::hash::hash_ctx_update(
                                    &mut digest_context_th,
                                    self.common.runtime_info.message_a.as_ref(),
                                );
                                crypto::hash::hash_ctx_update(&mut digest_context_th, send_buffer);
                                crypto::hash::hash_ctx_update(
                                    &mut digest_context_th,
                                    &receive_buffer[..temp_receive_used],
                                );
                            }

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let mut message_k = ManagedBuffer::default();
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                message_k
                                    .append_message(send_buffer)
                                    .ok_or(spdm_err!(ENOMEM))?;

                                message_k
                                    .append_message(&receive_buffer[..temp_receive_used])
                                    .ok_or(spdm_err!(ENOMEM))?;
                            }

                            // create session - generate the handshake secret (including finished_key)
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let th1 = self.common.calc_req_transcript_hash(
                                INVALID_SLOT,
                                true,
                                &message_k,
                                None,
                            )?;
                            #[cfg(feature = "hashed-transcript-data")]
                            let th1 =
                                crypto::hash::hash_ctx_finalize(digest_context_th.clone()).unwrap();
                            debug!("!!! th1 : {:02x?}\n", th1.as_ref());
                            let base_hash_algo = self.common.negotiate_info.base_hash_sel;
                            let dhe_algo = self.common.negotiate_info.dhe_sel;
                            let aead_algo = self.common.negotiate_info.aead_sel;
                            let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
                            let sequence_number_count = transport_encap.get_sequence_number_count();
                            let max_random_count = transport_encap.get_max_random_count();

                            let secure_spdm_version_sel = if let Some(secured_message_version) =
                                psk_exchange_rsp
                                    .opaque
                                    .req_get_dmtf_secure_spdm_version_selection(&mut self.common)
                            {
                                secured_message_version.get_secure_spdm_version()
                            } else {
                                0
                            };

                            let session_id = ((INITIAL_SESSION_ID as u32) << 16)
                                + psk_exchange_rsp.rsp_session_id as u32;
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                            let session = self
                                .common
                                .get_next_avaiable_session()
                                .ok_or(spdm_err!(EINVAL))?;

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
                                .ok_or(spdm_err!(EINVAL))?;
                            if session
                                .verify_hmac_with_response_finished_key(
                                    #[cfg(not(feature = "hashed-transcript-data"))]
                                    transcript_data.as_ref(),
                                    #[cfg(feature = "hashed-transcript-data")]
                                    crypto::hash::hash_ctx_finalize(digest_context_th.clone())
                                        .unwrap()
                                        .as_ref(),
                                    &psk_exchange_rsp.verify_data,
                                )
                                .is_err()
                            {
                                error!("verify_hmac_with_response_finished_key fail");
                                let _ = session.teardown(session_id);
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_hmac_with_response_finished_key pass");
                            }
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                message_k
                                    .append_message(psk_exchange_rsp.verify_data.as_ref())
                                    .ok_or(spdm_err!(ENOMEM))?;
                                session.runtime_info.message_k = message_k;
                            }
                            #[cfg(feature = "hashed-transcript-data")]
                            {
                                crypto::hash::hash_ctx_update(
                                    &mut digest_context_th,
                                    psk_exchange_rsp.verify_data.as_ref(),
                                );
                                session.runtime_info.digest_context_th = Some(digest_context_th);
                            }

                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionHandshaking,
                            );

                            session.secure_spdm_version_sel = secure_spdm_version_sel;
                            session.heartbeat_period = psk_exchange_rsp.heartbeat_period;

                            Ok(session_id)
                        } else {
                            error!("!!! psk_exchange : fail !!!\n");
                            spdm_result_err!(EFAULT)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let erm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestPskExchange,
                            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
                            transport_encap,
                            device_io,
                        );
                        match erm {
                            Ok(rm) => {
                                let receive_buffer = rm.receive_buffer;
                                let used = rm.used;
                                self.handle_spdm_psk_exchange_response(
                                    session_id,
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

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll;

        let status = requester
            .send_receive_spdm_psk_exchange(
                measurement_summary_hash_type,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
