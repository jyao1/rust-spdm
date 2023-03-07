// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::responder::*;

use crate::common::{ManagedBuffer, SpdmOpaqueSupport};
use crate::common::{SpdmCodec, SpdmDeviceIo, SpdmTransportEncap};
use crate::crypto;
use crate::protocol::*;
extern crate alloc;
use crate::common::opaque::SpdmOpaqueStruct;
#[cfg(feature = "hashed-transcript-data")]
use crate::crypto::HashCtx;
use crate::message::*;
use alloc::boxed::Box;

impl ResponderContext {
    pub fn handle_spdm_key_exchange(
        &mut self,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_key_exchange_response(bytes, &mut writer, transport_encap)?;
        self.send_message(writer.used_slice(), transport_encap, device_io)
    }

    pub fn write_spdm_key_exchange_response(
        &mut self,
        bytes: &[u8],
        writer: &mut Writer,
        transport_encap: &mut dyn SpdmTransportEncap,
    ) -> SpdmResult {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let key_exchange_req =
            SpdmKeyExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);

        let mut return_opaque = SpdmOpaqueStruct::default();

        if let Some(key_exchange_req) = &key_exchange_req {
            debug!("!!! key_exchange req : {:02x?}\n", key_exchange_req);

            if (key_exchange_req.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (key_exchange_req.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
            }

            if key_exchange_req.session_policy
                & KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_MASK
                == KEY_EXCHANGE_REQUESTER_SESSION_POLICY_TERMINATION_POLICY_VALUE
            {
                self.common.negotiate_info.termination_policy_set = true;
            } else {
                self.common.negotiate_info.termination_policy_set = false;
            }

            if let Some(secured_message_version_list) = key_exchange_req
                .opaque
                .rsp_get_dmtf_supported_secure_spdm_version_list(&mut self.common)
            {
                if secured_message_version_list.version_count
                    > crate::common::opaque::MAX_SECURE_SPDM_VERSION_COUNT as u8
                {
                    return spdm_result_err!(EINVAL);
                }
                for index in 0..secured_message_version_list.version_count as usize {
                    if secured_message_version_list.versions_list[index].get_secure_spdm_version()
                        == self.common.config_info.secure_spdm_version
                    {
                        if self
                            .common
                            .negotiate_info
                            .opaque_data_support
                            .contains(SpdmOpaqueSupport::OPAQUE_DATA_FMT1)
                        {
                            return_opaque.data_size =
                                crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT1
                                    .len() as u16;
                            return_opaque.data[..(return_opaque.data_size as usize)]
                                .copy_from_slice(
                                crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT1
                                    .as_ref(),
                            );
                        } else {
                            return_opaque.data_size =
                                crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT0
                                    .len() as u16;
                            return_opaque.data[..(return_opaque.data_size as usize)]
                                .copy_from_slice(
                                crate::common::opaque::RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT0
                                    .as_ref(),
                            );
                        }
                    }
                }
            }
        } else {
            error!("!!! key_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EINVAL);
        }

        info!("send spdm key_exchange rsp\n");

        let (exchange, key_exchange_context) =
            crypto::dhe::generate_key_pair(self.common.negotiate_info.dhe_sel).unwrap();

        debug!("!!! exchange data : {:02x?}\n", exchange);

        debug!(
            "!!! exchange data (peer) : {:02x?}\n",
            &key_exchange_req.as_ref().unwrap().exchange
        );

        let final_key =
            key_exchange_context.compute_final_key(&key_exchange_req.as_ref().unwrap().exchange);

        if final_key.is_none() {
            return spdm_result_err!(ESEC);
        }
        let final_key = final_key.unwrap();
        debug!("!!! final_key : {:02x?}\n", final_key.as_ref());

        let mut random = [0u8; SPDM_RANDOM_SIZE];
        let _ = crypto::rand::get_random(&mut random);

        let rsp_session_id = 0xFFFE;

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeResponse(SpdmKeyExchangeResponsePayload {
                heartbeat_period: self.common.config_info.heartbeat_period,
                rsp_session_id,
                mut_auth_req: SpdmKeyExchangeMutAuthAttributes::empty(),
                req_slot_id: 0x0,
                random: SpdmRandomStruct { data: random },
                exchange,
                measurement_summary_hash: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xaa; SPDM_MAX_HASH_SIZE]),
                },
                opaque: return_opaque.clone(),
                signature: SpdmSignatureStruct {
                    data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                    data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                },
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        // generate signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = used - base_asym_size - base_hash_size;

        #[cfg(not(feature = "hashed-transcript-data"))]
        let mut message_k = ManagedBuffer::default();
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            if message_k.append_message(&bytes[..reader.used()]).is_none() {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return spdm_result_err!(EFAULT);
            }
            if message_k
                .append_message(&writer.used_slice()[..temp_used])
                .is_none()
            {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return spdm_result_err!(EFAULT);
            }
        }

        #[cfg(feature = "hashed-transcript-data")]
        let cert_chain_hash;
        #[cfg(feature = "hashed-transcript-data")]
        if let Some(hash) = self.common.get_certchain_hash_rsp(false) {
            cert_chain_hash = hash;
        } else {
            return spdm_result_err!(EINVAL);
        }

        #[cfg(feature = "hashed-transcript-data")]
        let mut digest_context_th =
            crypto::hash::hash_ctx_init(self.common.negotiate_info.base_hash_sel).unwrap();
        #[cfg(feature = "hashed-transcript-data")]
        {
            crypto::hash::hash_ctx_update(
                &mut digest_context_th,
                self.common.runtime_info.message_a.as_ref(),
            );
            crypto::hash::hash_ctx_update(&mut digest_context_th, cert_chain_hash.as_ref());
            crypto::hash::hash_ctx_update(&mut digest_context_th, &bytes[..reader.used()]);
            crypto::hash::hash_ctx_update(
                &mut digest_context_th,
                &writer.used_slice()[..temp_used],
            );
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        let signature = self.generate_key_exchange_rsp_signature(&message_k);
        #[cfg(feature = "hashed-transcript-data")]
        let signature = self.generate_key_exchange_rsp_signature(digest_context_th.clone());
        if signature.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
        let signature = signature.unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        if message_k.append_message(signature.as_ref()).is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(&mut digest_context_th, signature.as_ref());

        // create session - generate the handshake secret (including finished_key)
        #[cfg(not(feature = "hashed-transcript-data"))]
        let th1 = self
            .common
            .calc_rsp_transcript_hash(false, &message_k, None);
        #[cfg(feature = "hashed-transcript-data")]
        let th1 = crypto::hash::hash_ctx_finalize(digest_context_th.clone());
        #[cfg(not(feature = "hashed-transcript-data"))]
        if th1.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
        let th1 = th1.unwrap();
        debug!("!!! th1 : {:02x?}\n", th1.as_ref());
        let hash_algo = self.common.negotiate_info.base_hash_sel;
        let dhe_algo = self.common.negotiate_info.dhe_sel;
        let aead_algo = self.common.negotiate_info.aead_sel;
        let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
        let sequence_number_count = transport_encap.get_sequence_number_count();
        let max_random_count = transport_encap.get_max_random_count();

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_next_avaiable_session();
        if session.is_none() {
            error!("!!! too many sessions : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }

        let session = session.unwrap();
        let session_id =
            ((key_exchange_req.unwrap().req_session_id as u32) << 16) + rsp_session_id as u32;
        session.setup(session_id).unwrap();
        session.set_use_psk(false);
        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_transport_param(sequence_number_count, max_random_count);
        session.set_dhe_secret(spdm_version_sel, final_key)?;
        session
            .generate_handshake_secret(spdm_version_sel, &th1)
            .unwrap();

        // generate HMAC with finished_key
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = self
            .common
            .calc_rsp_transcript_data(false, &message_k, None);
        #[cfg(not(feature = "hashed-transcript-data"))]
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = transcript_data.unwrap();

        let session = self.common.get_session_via_id(session_id).unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        let hmac = session.generate_hmac_with_response_finished_key(transcript_data.as_ref());
        #[cfg(feature = "hashed-transcript-data")]
        let hmac = session.generate_hmac_with_response_finished_key(
            crypto::hash::hash_ctx_finalize(digest_context_th.clone())
                .unwrap()
                .as_ref(),
        );
        if hmac.is_err() {
            let _ = session.teardown(session_id);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
        let hmac = hmac.unwrap();
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            if message_k.append_message(hmac.as_ref()).is_none() {
                let _ = session.teardown(session_id);
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return spdm_result_err!(EFAULT);
            }

            session.runtime_info.message_k = message_k;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            crypto::hash::hash_ctx_update(&mut digest_context_th, hmac.as_ref());

            session.runtime_info.digest_context_th = Some(digest_context_th);
        }

        // patch the message before send
        writer.mut_used_slice()[(used - base_hash_size - base_asym_size)..(used - base_hash_size)]
            .copy_from_slice(signature.as_ref());
        writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref()); // impl AsRef<[u8]> for SpdmDigestStruct

        let heartbeat_period = self.common.config_info.heartbeat_period;
        let secure_spdm_version_sel = self.common.config_info.secure_spdm_version;
        let session = self.common.get_session_via_id(session_id).unwrap();
        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        session.heartbeat_period = heartbeat_period;
        if return_opaque.data_size != 0 {
            session.secure_spdm_version_sel = secure_spdm_version_sel;
        }

        Ok(())
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_key_exchange_rsp_signature(
        &mut self,
        message_k: HashCtx,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let message_hash = crypto::hash::hash_ctx_finalize(message_k).unwrap();
        debug!("message_hash - {:02x?}", message_hash.as_ref());

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

        crypto::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or_else(|| spdm_err!(EFAULT))
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_key_exchange_rsp_signature(
        &mut self,
        message_k: &ManagedBuffer,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let mut message = self
            .common
            .calc_rsp_transcript_data(false, message_k, None)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

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

        crypto::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or_else(|| spdm_err!(EFAULT))
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::message::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use bytes::BytesMut;
    use codec::{Codec, Writer};

    #[test]
    #[cfg(not(feature = "hashed-transcript-data"))]
    fn test_case0_handle_spdm_key_exchange() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        crypto::hmac::register(HMAC_TEST.clone());

        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_256_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let rng = ring::rand::SystemRandom::new();
        let private_key =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &rng)
                .ok()
                .unwrap();
        let public_key_old = private_key.compute_public_key().ok().unwrap();
        let public_key = BytesMut::from(&public_key_old.as_ref()[1..]);

        let key_exchange: &mut [u8; 1024] = &mut [0u8; 1024];
        let mut writer = Writer::init(key_exchange);
        let mut value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 100u8,
            req_session_id: 0xffu16,
            session_policy: 1,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct::from(public_key),
            opaque: SpdmOpaqueStruct {
                data_size: crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT1
                    .len() as u16,
                data: [0u8; config::MAX_SPDM_OPAQUE_SIZE],
            },
        };
        value.opaque.data[0..value.opaque.data_size as usize].copy_from_slice(
            &crate::common::opaque::REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT1,
        );
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        let _ = context.handle_spdm_key_exchange(bytes);
    }
}
