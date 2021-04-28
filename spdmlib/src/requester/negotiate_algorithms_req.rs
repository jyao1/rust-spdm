// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_algorithm(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestNegotiateAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: self.common.config_info.measurement_specification,
                    base_asym_algo: self.common.config_info.base_asym_algo,
                    base_hash_algo: self.common.config_info.base_hash_algo,
                    alg_struct_count: 4,
                    alg_struct: [
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                            alg_fixed_count: 2,
                            alg_supported: SpdmAlg::SpdmAlgoDhe(self.common.config_info.dhe_algo),
                            alg_ext_count: 0,
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                            alg_fixed_count: 2,
                            alg_supported: SpdmAlg::SpdmAlgoAead(self.common.config_info.aead_algo),
                            alg_ext_count: 0,
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                            alg_fixed_count: 2,
                            alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                                self.common.config_info.req_asym_algo,
                            ),
                            alg_ext_count: 0,
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                            alg_fixed_count: 2,
                            alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                                self.common.config_info.key_schedule_algo,
                            ),
                            alg_ext_count: 0,
                        },
                    ],
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        if self
            .common
            .runtime_info
            .message_a
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }
        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseAlgorithms => {
                    let algorithms =
                        SpdmAlgorithmsResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(algorithms) = algorithms {
                        debug!("!!! algorithms : {:02x?}\n", algorithms);
                        self.common.negotiate_info.measurement_specification_sel =
                            algorithms.measurement_specification_sel;
                        self.common.negotiate_info.measurement_hash_sel =
                            algorithms.measurement_hash_algo;
                        self.common.negotiate_info.base_hash_sel = algorithms.base_hash_sel;
                        self.common.negotiate_info.base_asym_sel = algorithms.base_asym_sel;
                        for alg in algorithms
                            .alg_struct
                            .iter()
                            .take(algorithms.alg_struct_count as usize)
                        {
                            match alg.alg_supported {
                                SpdmAlg::SpdmAlgoDhe(v) => self.common.negotiate_info.dhe_sel = v,
                                SpdmAlg::SpdmAlgoAead(v) => self.common.negotiate_info.aead_sel = v,
                                SpdmAlg::SpdmAlgoReqAsym(v) => {
                                    self.common.negotiate_info.req_asym_sel = v
                                }
                                SpdmAlg::SpdmAlgoKeySchedule(v) => {
                                    self.common.negotiate_info.key_schedule_sel = v
                                }
                                SpdmAlg::SpdmAlgoUnknown(_v) => {}
                            }
                        }
                        if self
                            .common
                            .runtime_info
                            .message_a
                            .append_message(&receive_buffer[..used])
                            .is_some()
                        {
                            return Ok(());
                        };
                    }
                    error!("!!! algorithms : fail !!!\n");
                    spdm_result_err!(EFAULT)
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
