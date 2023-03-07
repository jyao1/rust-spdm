// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmOpaqueSupport;
use crate::common::SpdmTransportEncap;
use crate::crypto;
use crate::error::{spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use config::MAX_SPDM_PSK_CONTEXT_SIZE;
extern crate alloc;
use alloc::boxed::Box;

#[cfg(not(feature = "hashed-transcript-data"))]
use crate::common::ManagedBuffer;

impl ResponderContext {
    pub fn handle_spdm_psk_exchange(
        &mut self,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_psk_exchange_response(bytes, &mut writer, transport_encap)?;
        self.send_message(writer.used_slice(), transport_encap, device_io)
    }

    pub fn write_spdm_psk_exchange_response(
        &mut self,
        bytes: &[u8],
        writer: &mut Writer,
        transport_encap: &mut dyn SpdmTransportEncap,
    ) -> SpdmResult {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let psk_exchange_req =
            SpdmPskExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);

        let mut return_opaque = SpdmOpaqueStruct::default();

        if let Some(psk_exchange_req) = &psk_exchange_req {
            debug!("!!! psk_exchange req : {:02x?}\n", psk_exchange_req);

            if (psk_exchange_req.measurement_summary_hash_type
                == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb)
                || (psk_exchange_req.measurement_summary_hash_type
                    == SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll)
            {
                self.common.runtime_info.need_measurement_summary_hash = true;
            } else {
                self.common.runtime_info.need_measurement_summary_hash = false;
            }

            if let Some(secured_message_version_list) = psk_exchange_req
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
            error!("!!! psk_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }

        #[cfg(feature = "hashed-transcript-data")]
        let mut digest_context_th =
            crypto::hash::hash_ctx_init(self.common.negotiate_info.base_hash_sel).unwrap();
        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            &mut digest_context_th,
            self.common.runtime_info.message_a.as_ref(),
        );

        info!("send spdm psk_exchange rsp\n");

        let mut psk_context = [0u8; MAX_SPDM_PSK_CONTEXT_SIZE];
        let _ = crypto::rand::get_random(&mut psk_context);

        let rsp_session_id = 0xFFFD;

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload {
                heartbeat_period: self.common.config_info.heartbeat_period,
                rsp_session_id,
                measurement_summary_hash: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xaa; SPDM_MAX_HASH_SIZE]),
                },
                psk_context: SpdmPskContextStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: psk_context,
                },
                opaque: return_opaque.clone(),
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: Box::new([0xcc; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };

        response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;
        let temp_used = used - base_hash_size;

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
        {
            crypto::hash::hash_ctx_update(&mut digest_context_th, &bytes[..reader.used()]);
            crypto::hash::hash_ctx_update(
                &mut digest_context_th,
                &writer.used_slice()[..temp_used],
            );
        }

        // create session - generate the handshake secret (including finished_key)
        #[cfg(not(feature = "hashed-transcript-data"))]
        let th1 = self.common.calc_rsp_transcript_hash(true, &message_k, None);
        #[cfg(feature = "hashed-transcript-data")]
        let th1 = crypto::hash::hash_ctx_finalize(digest_context_th.clone());
        #[cfg(feature = "hashed-transcript-data")]
        if th1.is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return spdm_result_err!(EFAULT);
        }
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
            ((psk_exchange_req.unwrap().req_session_id as u32) << 16) + rsp_session_id as u32;
        session.setup(session_id).unwrap();
        session.set_use_psk(true);
        let mut psk_key = SpdmDheFinalKeyStruct {
            data_size: b"TestPskData\0".len() as u16,
            data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
        };
        psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskData\0");
        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_transport_param(sequence_number_count, max_random_count);
        session.set_dhe_secret(spdm_version_sel, psk_key)?; // transfer the ownership out
        session
            .generate_handshake_secret(spdm_version_sel, &th1)
            .unwrap();

        // generate HMAC with finished_key
        #[cfg(not(feature = "hashed-transcript-data"))]
        let transcript_data = self.common.calc_rsp_transcript_data(true, &message_k, None);
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
        writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref());
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
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::config::MAX_SPDM_PSK_HINT_SIZE;
    use crate::message::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_psk_exchange() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut context = responder::ResponderContext::new(config_info, provision_info);
        context.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_128_GCM;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let challenge = &mut [0u8; 1024];
        let mut writer = Writer::init(challenge);
        let mut value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: 32,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
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
        bytes[2..].copy_from_slice(&challenge[0..1022]);
        let _ = context.handle_spdm_psk_exchange(
            bytes,
            pcidoe_transport_encap,
            &mut socket_io_transport,
        );
    }
}
