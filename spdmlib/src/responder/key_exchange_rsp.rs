// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

use crate::common::ManagedBuffer;

use crate::crypto;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_key_exchange(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_key_exchange_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_key_exchange_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let key_exchange_req =
            SpdmKeyExchangeRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(key_exchange_req) = key_exchange_req {
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
        } else {
            error!("!!! key_exchange req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        info!("send spdm key_exchange rsp\n");

        let (exchange, key_exchange_context) =
            crypto::dhe::generate_key_pair(self.common.negotiate_info.dhe_sel).unwrap();

        debug!("!!! exchange data : {:02x?}\n", exchange);

        debug!(
            "!!! exchange data (peer) : {:02x?}\n",
            &key_exchange_req.unwrap().exchange
        );

        let final_key = key_exchange_context.compute_final_key(&key_exchange_req.unwrap().exchange);

        if final_key.is_none() {
            return;
        }
        let final_key = final_key.unwrap();
        debug!("!!! final_key : {:02x?}\n", final_key.as_ref());

        let mut random = [0u8; SPDM_RANDOM_SIZE];
        let _ = crypto::rand::get_random(&mut random);

        let rsp_session_id = 0xFFFE;

        let mut opaque = SpdmOpaqueStruct {
            data_size: crate::common::OPAQUE_DATA_VERSION_SELECTION.len() as u16,
            ..Default::default()
        };
        opaque.data[..(opaque.data_size as usize)]
            .copy_from_slice(crate::common::OPAQUE_DATA_VERSION_SELECTION.as_ref());
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseKeyExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeResponse(SpdmKeyExchangeResponsePayload {
                heartbeat_period: 0x0,
                rsp_session_id,
                mut_auth_req: SpdmKeyExchangeMutAuthAttributes::empty(),
                req_slot_id: 0x0,
                random: SpdmRandomStruct { data: random },
                exchange,
                measurement_summary_hash: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: [0xaa; SPDM_MAX_HASH_SIZE],
                },
                opaque,
                signature: SpdmSignatureStruct {
                    data_size: self.common.negotiate_info.base_asym_sel.get_size(),
                    data: [0xbb; SPDM_MAX_ASYM_KEY_SIZE],
                },
                verify_data: SpdmDigestStruct {
                    data_size: self.common.negotiate_info.base_hash_sel.get_size(),
                    data: [0xcc; SPDM_MAX_HASH_SIZE],
                },
            }),
        };

        response.spdm_encode(&mut self.common, writer);
        let used = writer.used();

        // generate signature
        let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
        let base_hash_size = self.common.negotiate_info.base_hash_sel.get_size() as usize;

        let mut message_k = ManagedBuffer::default();
        if message_k.append_message(&bytes[..reader.used()]).is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let temp_used = used - base_asym_size - base_hash_size;
        if message_k
            .append_message(&writer.used_slice()[..temp_used])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let signature = self.common.generate_key_exchange_rsp_signature(&message_k);
        if signature.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let signature = signature.unwrap();
        if message_k.append_message(signature.as_ref()).is_none() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        // create session - generate the handshake secret (including finished_key)
        let th1 = self
            .common
            .calc_rsp_transcript_hash(false, &message_k, None);
        if th1.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let th1 = th1.unwrap();
        debug!("!!! th1 : {:02x?}\n", th1.as_ref());
        let hash_algo = self.common.negotiate_info.base_hash_sel;
        let dhe_algo = self.common.negotiate_info.dhe_sel;
        let aead_algo = self.common.negotiate_info.aead_sel;
        let key_schedule_algo = self.common.negotiate_info.key_schedule_sel;
        let sequence_number_count = self.common.transport_encap.get_sequence_number_count();
        let max_random_count = self.common.transport_encap.get_max_random_count();

        let session = self.common.get_next_avaiable_session();
        if session.is_none() {
            error!("!!! too many sessions : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let session = session.unwrap();
        let session_id =
            ((key_exchange_req.unwrap().req_session_id as u32) << 16) + rsp_session_id as u32;
        session.setup(session_id).unwrap();
        session.set_use_psk(false);
        session.set_crypto_param(hash_algo, dhe_algo, aead_algo, key_schedule_algo);
        session.set_transport_param(sequence_number_count, max_random_count);
        session.set_dhe_secret(&final_key);
        session.generate_handshake_secret(&th1).unwrap();

        // generate HMAC with finished_key
        let transcript_data = self
            .common
            .calc_rsp_transcript_data(false, &message_k, None);
        if transcript_data.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let transcript_data = transcript_data.unwrap();

        let session = self.common.get_session_via_id(session_id).unwrap();
        let hmac = session.generate_hmac_with_response_finished_key(transcript_data.as_ref());
        if hmac.is_err() {
            let _ = session.teardown(session_id);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let hmac = hmac.unwrap();
        if message_k.append_message(hmac.as_ref()).is_none() {
            let _ = session.teardown(session_id);
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        session.runtime_info.message_k = message_k;

        // patch the message before send
        writer.mut_used_slice()[(used - base_hash_size - base_asym_size)..(used - base_hash_size)]
            .copy_from_slice(signature.as_ref());
        writer.mut_used_slice()[(used - base_hash_size)..used].copy_from_slice(hmac.as_ref()); // impl AsRef<[u8]> for SpdmDigestStruct

        let session = self.common.get_session_via_id(session_id).unwrap();
        session.set_session_state(crate::session::SpdmSessionState::SpdmSessionHandshaking);
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use bytes::BytesMut;
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_key_exchange() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);
        crypto::hmac::register(HMAC_TEST);

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
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
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
        let value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb,
            slot_id: 100u8,
            req_session_id: 0xffu16,
            random: SpdmRandomStruct {
                data: [100u8; SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct::from(public_key),
            opaque: SpdmOpaqueStruct {
                data_size: 64u16,
                data: [100u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
            },
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&key_exchange[0..1022]);

        context.handle_spdm_key_exchange(bytes);
    }
}
