// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmConnectionState;
use crate::crypto;
use crate::error::SpdmResult;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_algorithm(&mut self, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_algorithm(bytes, &mut writer);
        self.send_message(writer.used_slice())
    }

    pub fn write_spdm_algorithm(&mut self, bytes: &[u8], writer: &mut Writer) {
        if self.common.runtime_info.get_connection_state()
            != SpdmConnectionState::SpdmConnectionAfterCapabilities
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnexpectedRequest, 0, writer);
            return;
        }
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            None,
        );

        let other_params_support;

        let negotiate_algorithms =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(negotiate_algorithms) = negotiate_algorithms {
            debug!("!!! negotiate_algorithms : {:02x?}\n", negotiate_algorithms);
            other_params_support = negotiate_algorithms.other_params_support;
            self.common.negotiate_info.measurement_specification_sel =
                negotiate_algorithms.measurement_specification;
            self.common.negotiate_info.base_hash_sel = negotiate_algorithms.base_hash_algo;
            self.common.negotiate_info.base_asym_sel = negotiate_algorithms.base_asym_algo;
            for alg in negotiate_algorithms
                .alg_struct
                .iter()
                .take(negotiate_algorithms.alg_struct_count as usize)
            {
                match &alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(v) => self.common.negotiate_info.dhe_sel = *v,
                    SpdmAlg::SpdmAlgoAead(v) => self.common.negotiate_info.aead_sel = *v,
                    SpdmAlg::SpdmAlgoReqAsym(v) => self.common.negotiate_info.req_asym_sel = *v,
                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                        self.common.negotiate_info.key_schedule_sel = *v
                    }
                    SpdmAlg::SpdmAlgoUnknown(_v) => {}
                }
            }
        } else {
            error!("!!! negotiate_algorithms : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        if self
            .common
            .append_message_a(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        self.common
            .negotiate_info
            .measurement_specification_sel
            .prioritize(self.common.config_info.measurement_specification);
        self.common.negotiate_info.measurement_hash_sel =
            self.common.config_info.measurement_hash_algo;
        self.common
            .negotiate_info
            .base_hash_sel
            .prioritize(self.common.config_info.base_hash_algo);
        self.common
            .negotiate_info
            .base_asym_sel
            .prioritize(self.common.config_info.base_asym_algo);
        self.common
            .negotiate_info
            .dhe_sel
            .prioritize(self.common.config_info.dhe_algo);
        self.common
            .negotiate_info
            .aead_sel
            .prioritize(self.common.config_info.aead_algo);
        self.common
            .negotiate_info
            .req_asym_sel
            .prioritize(self.common.config_info.req_asym_algo);
        self.common
            .negotiate_info
            .key_schedule_sel
            .prioritize(self.common.config_info.key_schedule_algo);

        //
        // update cert chain - append root cert hash
        //
        for slot_id in 0..SPDM_MAX_SLOT_NUMBER {
            if self.common.provision_info.my_cert_chain[slot_id].is_none()
                && self.common.provision_info.my_cert_chain_data[slot_id].is_some()
            {
                let cert_chain = self.common.provision_info.my_cert_chain_data[slot_id]
                    .as_ref()
                    .unwrap();
                let (root_cert_begin, root_cert_end) =
                    crypto::cert_operation::get_cert_from_cert_chain(
                        &cert_chain.data[..(cert_chain.data_size as usize)],
                        0,
                    )
                    .unwrap();
                let root_cert = &cert_chain.data[root_cert_begin..root_cert_end];
                if let Some(root_hash) =
                    crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, root_cert)
                {
                    let data_size = 4 + root_hash.data_size + cert_chain.data_size;
                    let mut data =
                        [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE];
                    data[0] = (data_size & 0xFF) as u8;
                    data[1] = (data_size >> 8) as u8;
                    data[4..(4 + root_hash.data_size as usize)]
                        .copy_from_slice(&root_hash.data[..(root_hash.data_size as usize)]);
                    data[(4 + root_hash.data_size as usize)..(data_size as usize)]
                        .copy_from_slice(&cert_chain.data[..(cert_chain.data_size as usize)]);
                    self.common.provision_info.my_cert_chain[slot_id] =
                        Some(SpdmCertChainBuffer { data_size, data });
                    debug!("my_cert_chain - {:02x?}\n", &data[..(data_size as usize)]);
                } else {
                    self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
                    return;
                }
            }
        }

        info!("send spdm algorithm\n");

        let other_params_selection = self.common.config_info.opaque_support & other_params_support;
        self.common.negotiate_info.opaque_data_support = other_params_selection;

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
                measurement_specification_sel: self
                    .common
                    .negotiate_info
                    .measurement_specification_sel,
                other_params_selection,
                measurement_hash_algo: self.common.negotiate_info.measurement_hash_sel,
                base_asym_sel: self.common.negotiate_info.base_asym_sel,
                base_hash_sel: self.common.negotiate_info.base_hash_sel,
                alg_struct_count: 4,
                alg_struct: [
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(self.common.negotiate_info.dhe_sel),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                        alg_supported: SpdmAlg::SpdmAlgoAead(self.common.negotiate_info.aead_sel),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                        alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                            self.common.negotiate_info.req_asym_sel,
                        ),
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                        alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                            self.common.negotiate_info.key_schedule_sel,
                        ),
                    },
                ],
            }),
        };
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }
        if self.common.append_message_a(writer.used_slice()).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
        }
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::common::opaque::*;
    use crate::message::SpdmMessageHeader;
    use crate::responder;
    use crate::testlib::*;
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_algorithm() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion11,
            request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
        };
        assert!(value.encode(&mut writer).is_ok());

        let negotiate_algorithms = &mut [0u8; 1024];
        let mut writer = Writer::init(negotiate_algorithms);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            other_params_support: SpdmOpaqueSupport::empty(),
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            alg_struct_count: 4,
            alg_struct: [
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                    alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                    alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                    alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                        SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                    ),
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                    alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
                    ),
                },
            ],
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&negotiate_algorithms[0..1022]);

        context.handle_spdm_algorithm(bytes);

        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
        );
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let u8_slice = &u8_slice[2..];
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let mut reader = Reader::init(u8_slice);
        let spdm_sturct_data =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context.common, &mut reader)
                .unwrap();
        assert_eq!(
            spdm_sturct_data.measurement_specification,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            spdm_sturct_data.base_asym_algo,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        );
        assert_eq!(
            spdm_sturct_data.base_hash_algo,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384
        );
        assert_eq!(spdm_sturct_data.alg_struct_count, 4);
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_type,
            SpdmAlgType::SpdmAlgTypeDHE
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[0].alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_type,
            SpdmAlgType::SpdmAlgTypeAEAD
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[1].alg_supported,
            SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_type,
            SpdmAlgType::SpdmAlgTypeReqAsym
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[2].alg_supported,
            SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_type,
            SpdmAlgType::SpdmAlgTypeKeySchedule
        );
        assert_eq!(
            spdm_sturct_data.alg_struct[3].alg_supported,
            SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
        );

        let u8_slice = &u8_slice[46..];
        debug!("u8_slice: {:02X?}\n", u8_slice);
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseAlgorithms
        );
        if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification_sel,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.measurement_hash_algo,
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_384
            );
            assert_eq!(
                payload.base_asym_sel,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
            );
            assert_eq!(payload.base_hash_sel, SpdmBaseHashAlgo::TPM_ALG_SHA_384);
            assert_eq!(payload.alg_struct_count, 4);

            assert_eq!(payload.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
            assert_eq!(
                payload.alg_struct[0].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::empty())
            );

            assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
            assert_eq!(
                payload.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::empty())
            );

            assert_eq!(
                payload.alg_struct[2].alg_type,
                SpdmAlgType::SpdmAlgTypeReqAsym
            );
            assert_eq!(
                payload.alg_struct[2].alg_supported,
                SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::empty())
            );

            assert_eq!(
                payload.alg_struct[3].alg_type,
                SpdmAlgType::SpdmAlgTypeKeySchedule
            );
            assert_eq!(
                payload.alg_struct[3].alg_supported,
                SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE)
            );
        }
    }
}
