// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_algorithm(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_algorithm(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_algorithm(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let negotiate_algorithms =
            SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(negotiate_algorithms) = negotiate_algorithms {
            debug!("!!! negotiate_algorithms : {:02x?}\n", negotiate_algorithms);
            self.common.negotiate_info.measurement_specification_sel =
                negotiate_algorithms.measurement_specification;
            self.common.negotiate_info.base_hash_sel = negotiate_algorithms.base_hash_algo;
            self.common.negotiate_info.base_asym_sel = negotiate_algorithms.base_asym_algo;
            for alg in negotiate_algorithms
                .alg_struct
                .iter()
                .take(negotiate_algorithms.alg_struct_count as usize)
            {
                match alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(v) => self.common.negotiate_info.dhe_sel = v,
                    SpdmAlg::SpdmAlgoAead(v) => self.common.negotiate_info.aead_sel = v,
                    SpdmAlg::SpdmAlgoReqAsym(v) => self.common.negotiate_info.req_asym_sel = v,
                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                        self.common.negotiate_info.key_schedule_sel = v
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
            .runtime_info
            .message_a
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
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
        if self.common.provision_info.my_cert_chain.is_none()
            && self.common.provision_info.my_cert_chain_data.is_some()
        {
            let cert_chain = self.common.provision_info.my_cert_chain_data.unwrap();
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
                let mut data = [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE];
                data[0] = (data_size & 0xFF) as u8;
                data[1] = (data_size >> 8) as u8;
                data[4..(4 + root_hash.data_size as usize)]
                    .copy_from_slice(&root_hash.data[..(root_hash.data_size as usize)]);
                data[(4 + root_hash.data_size as usize)..(data_size as usize)]
                    .copy_from_slice(&cert_chain.data[..(cert_chain.data_size as usize)]);
                self.common.provision_info.my_cert_chain =
                    Some(SpdmCertChainData { data_size, data });
                debug!("my_cert_chain - {:02x?}\n", &data[..(data_size as usize)]);
            } else {
                return;
            }
        }

        info!("send spdm algorithm\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
                measurement_specification_sel: self
                    .common
                    .negotiate_info
                    .measurement_specification_sel,
                measurement_hash_algo: self.common.negotiate_info.measurement_hash_sel,
                base_asym_sel: self.common.negotiate_info.base_asym_sel,
                base_hash_sel: self.common.negotiate_info.base_hash_sel,
                alg_struct_count: 4,
                alg_struct: [
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(self.common.negotiate_info.dhe_sel),
                        alg_ext_count: 0,
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoAead(self.common.negotiate_info.aead_sel),
                        alg_ext_count: 0,
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                            self.common.negotiate_info.req_asym_sel,
                        ),
                        alg_ext_count: 0,
                    },
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                            self.common.negotiate_info.key_schedule_sel,
                        ),
                        alg_ext_count: 0,
                    },
                ],
            }),
        };
        response.spdm_encode(&mut self.common, writer);

        self.common
            .runtime_info
            .message_a
            .append_message(writer.used_slice());
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_algorithm() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let negotiate_algorithms = &mut [0u8; 1024];
        let mut writer = Writer::init(negotiate_algorithms);
        let value = SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification: SpdmMeasurementSpecification::DMTF,
            base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            alg_struct_count: 4,
            alg_struct: [SpdmAlgStruct {
                alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                alg_fixed_count: 2,
                alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048),
                alg_ext_count: 0,
            }; config::MAX_SPDM_ALG_STRUCT_COUNT],
        };
        value.spdm_encode(&mut context.common, &mut writer);

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
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );

        let u8_slice = &u8_slice[2..];
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
        for i in 0..4 {
            assert_eq!(
                spdm_sturct_data.alg_struct[i].alg_type,
                SpdmAlgType::SpdmAlgTypeDHE
            );
            assert_eq!(spdm_sturct_data.alg_struct[i].alg_fixed_count, 2);
            assert_eq!(
                spdm_sturct_data.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048)
            );
            assert_eq!(spdm_sturct_data.alg_struct[i].alg_ext_count, 0);
        }

        let u8_slice = &u8_slice[46..];
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseAlgorithms
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
            assert_eq!(payload.alg_struct[0].alg_fixed_count, 2);
            assert_eq!(
                payload.alg_struct[0].alg_supported,
                SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::empty())
            );
            assert_eq!(payload.alg_struct[0].alg_ext_count, 0);

            assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
            assert_eq!(payload.alg_struct[1].alg_fixed_count, 2);
            assert_eq!(
                payload.alg_struct[1].alg_supported,
                SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::empty())
            );
            assert_eq!(payload.alg_struct[1].alg_ext_count, 0);

            assert_eq!(
                payload.alg_struct[2].alg_type,
                SpdmAlgType::SpdmAlgTypeReqAsym
            );
            assert_eq!(payload.alg_struct[2].alg_fixed_count, 2);
            assert_eq!(
                payload.alg_struct[2].alg_supported,
                SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::empty())
            );
            assert_eq!(payload.alg_struct[2].alg_ext_count, 0);

            assert_eq!(
                payload.alg_struct[3].alg_type,
                SpdmAlgType::SpdmAlgTypeKeySchedule
            );
            assert_eq!(payload.alg_struct[3].alg_fixed_count, 2);
            assert_eq!(
                payload.alg_struct[3].alg_supported,
                SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::empty())
            );
            assert_eq!(payload.alg_struct[3].alg_ext_count, 0);
        }
    }
}
