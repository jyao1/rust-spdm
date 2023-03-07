// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;
use alloc::boxed::Box;

use crate::common::ManagedBuffer;
use crate::protocol::*;
use crate::requester::*;

use crate::crypto;

use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::{SpdmMeasurementSummaryHashType, SpdmSignatureStruct, SpdmVersion};

const INITIAL_SESSION_ID: u16 = 0xFFFE;

impl RequesterContext {
    pub fn send_receive_spdm_key_exchange(
        &mut self,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<u32> {
        info!("send spdm key exchange\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let (key_exchange_context, send_used) = self.encode_spdm_key_exchange(
            &mut send_buffer,
            slot_id,
            measurement_summary_hash_type,
        )?;
        self.send_message(&send_buffer[..send_used], transport_encap, device_io)?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let receive_used =
            self.receive_message(&mut receive_buffer, false, transport_encap, device_io)?;
        self.handle_spdm_key_exhcange_response(
            0,
            slot_id,
            &send_buffer[..send_used],
            &receive_buffer[..receive_used],
            measurement_summary_hash_type,
            key_exchange_context,
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_key_exchange(
        &mut self,
        buf: &mut [u8],
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<(Box<dyn crypto::SpdmDheKeyExchange>, usize)> {
        let mut writer = Writer::init(buf);

        let req_session_id = INITIAL_SESSION_ID;

        let mut random = [0u8; SPDM_RANDOM_SIZE];
        crypto::rand::get_random(&mut random)?;

        let (exchange, key_exchange_context) =
            crypto::dhe::generate_key_pair(self.common.negotiate_info.dhe_sel)
                .ok_or(spdm_err!(EFAULT))?;

        debug!("!!! exchange data : {:02x?}\n", exchange);

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
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyExchange,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload {
                slot_id,
                measurement_summary_hash_type,
                req_session_id,
                session_policy: self.common.config_info.session_policy,
                random: SpdmRandomStruct { data: random },
                exchange,
                opaque,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        Ok((key_exchange_context, writer.used()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_key_exhcange_response(
        &mut self,
        session_id: u32,
        slot_id: u8,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        key_exchange_context: Box<dyn crypto::SpdmDheKeyExchange>,
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
                    SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp => {
                        let key_exchange_rsp = SpdmKeyExchangeResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
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
                            let temp_receive_used = receive_used - base_asym_size - base_hash_size;

                            #[cfg(feature = "hashed-transcript-data")]
                            let cert_chain_hash;
                            #[cfg(feature = "hashed-transcript-data")]
                            if let Some(hash) = self.common.get_certchain_hash_req(slot_id, false) {
                                cert_chain_hash = hash;
                            } else {
                                return spdm_result_err!(EFAULT);
                            }

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
                                crypto::hash::hash_ctx_update(
                                    &mut digest_context_th,
                                    cert_chain_hash.as_ref(),
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

                            if self
                                .verify_key_exchange_rsp_signature(
                                    slot_id,
                                    #[cfg(not(feature = "hashed-transcript-data"))]
                                    &message_k,
                                    #[cfg(feature = "hashed-transcript-data")]
                                    digest_context_th.clone(),
                                    &key_exchange_rsp.signature,
                                )
                                .is_err()
                            {
                                error!("verify_key_exchange_rsp_signature fail");
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_key_exchange_rsp_signature pass");
                            }

                            #[cfg(not(feature = "hashed-transcript-data"))]
                            message_k
                                .append_message(key_exchange_rsp.signature.as_ref())
                                .ok_or(spdm_err!(ENOMEM))?;

                            #[cfg(feature = "hashed-transcript-data")]
                            crypto::hash::hash_ctx_update(
                                &mut digest_context_th,
                                key_exchange_rsp.signature.as_ref(),
                            );

                            // create session - generate the handshake secret (including finished_key)
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let th1 = self
                                .common
                                .calc_req_transcript_hash(slot_id, false, &message_k, None)?;
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
                                key_exchange_rsp
                                    .opaque
                                    .req_get_dmtf_secure_spdm_version_selection(&mut self.common)
                            {
                                secured_message_version.get_secure_spdm_version()
                            } else {
                                0
                            };

                            info!(
                                "secure_spdm_version_sel set to {:02X?}",
                                secure_spdm_version_sel
                            );

                            let session_id = ((INITIAL_SESSION_ID as u32) << 16)
                                + key_exchange_rsp.rsp_session_id as u32;
                            let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
                            let session = self
                                .common
                                .get_next_avaiable_session()
                                .ok_or(spdm_err!(EINVAL))?;

                            session.setup(session_id)?;

                            session.set_use_psk(false);

                            session.set_crypto_param(
                                base_hash_algo,
                                dhe_algo,
                                aead_algo,
                                key_schedule_algo,
                            );
                            session.set_transport_param(sequence_number_count, max_random_count);
                            session.set_dhe_secret(spdm_version_sel, final_key)?;
                            session.generate_handshake_secret(spdm_version_sel, &th1)?;

                            // verify HMAC with finished_key
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            let transcript_data = self
                                .common
                                .calc_req_transcript_data(slot_id, false, &message_k, None)?;
                            let mut session = self
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
                            #[cfg(not(feature = "hashed-transcript-data"))]
                            {
                                message_k
                                    .append_message(key_exchange_rsp.verify_data.as_ref())
                                    .ok_or(spdm_err!(ENOMEM))?;
                                session.runtime_info.message_k = message_k;
                            }

                            #[cfg(feature = "hashed-transcript-data")]
                            {
                                crypto::hash::hash_ctx_update(
                                    &mut digest_context_th,
                                    key_exchange_rsp.verify_data.as_ref(),
                                );

                                session.runtime_info.digest_context_th = Some(digest_context_th);
                            }

                            session.set_session_state(
                                crate::common::session::SpdmSessionState::SpdmSessionHandshaking,
                            );

                            session.secure_spdm_version_sel = secure_spdm_version_sel;
                            session.heartbeat_period = key_exchange_rsp.heartbeat_period;

                            Ok(session_id)
                        } else {
                            error!("!!! key_exchange : fail !!!\n");
                            spdm_result_err!(EFAULT)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let erm = self.spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestKeyExchange,
                            SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp,
                            transport_encap,
                            device_io,
                        );
                        match erm {
                            Ok(rm) => {
                                let receive_buffer = rm.receive_buffer;
                                let used = rm.used;
                                self.handle_spdm_key_exhcange_response(
                                    session_id,
                                    slot_id,
                                    send_buffer,
                                    &receive_buffer[..used],
                                    measurement_summary_hash_type,
                                    key_exchange_context,
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

    #[cfg(feature = "hashed-transcript-data")]
    pub fn verify_key_exchange_rsp_signature(
        &mut self,
        slot_id: u8,
        message_k: HashCtx,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let message_hash = crypto::hash::hash_ctx_finalize(message_k).unwrap();
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

        let mut message = ManagedBuffer::default();
        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_2)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT)
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

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn verify_key_exchange_rsp_signature(
        &mut self,
        slot_id: u8,
        message_k: &ManagedBuffer,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let mut message = self
            .common
            .calc_req_transcript_data(slot_id, false, message_k, None)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
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

        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_2)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT)
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
    fn test_case0_send_receive_spdm_key_exchange() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let message_m = &[
            0x11, 0xe0, 0x00, 0x00, 0x11, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        responder.common.reset_runtime_info();

        #[cfg(not(feature = "hashed-transcript-data"))]
        responder
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        #[cfg(feature = "hashed-transcript-data")]
        responder.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(responder.common.negotiate_info.base_hash_sel).unwrap(),
        );
        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            responder
                .common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            message_m,
        );
        responder.common.provision_info.my_cert_chain_data = Some(REQ_CERT_CHAIN_DATA);

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
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        requester.common.reset_runtime_info();

        #[cfg(not(feature = "hashed-transcript-data"))]
        requester
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        #[cfg(feature = "hashed-transcript-data")]
        requester.common.runtime_info.digest_context_m1m2 = Some(
            crypto::hash::hash_ctx_init(requester.common.negotiate_info.base_hash_sel).unwrap(),
        );

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            requester
                .common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            message_m,
        );
        requester.common.peer_info.peer_cert_chain[0] = Some(SpdmCertChain::default());
        requester.common.peer_info.peer_cert_chain[0]
            .as_mut()
            .unwrap()
            .cert_chain = REQ_CERT_CHAIN_DATA;

        let measurement_summary_hash_type =
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll;
        let status = requester
            .send_receive_spdm_key_exchange(
                0,
                measurement_summary_hash_type,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
