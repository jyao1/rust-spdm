// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_NEGOTIATION_FAIL,
};

use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_algorithm(&mut self) -> SpdmResult {
        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            None,
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.encode_spdm_algorithm(&mut send_buffer)?;
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_algorithm_response(0, &send_buffer[..send_used], &receive_buffer[..used])
    }

    pub fn encode_spdm_algorithm(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let other_params_support: SpdmOpaqueSupport = self.common.config_info.opaque_support;

        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: self.common.config_info.measurement_specification,
                    other_params_support,
                    base_asym_algo: self.common.config_info.base_asym_algo,
                    base_hash_algo: self.common.config_info.base_hash_algo,
                    alg_struct_count: 4,
                    alg_struct: [
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                            alg_supported: SpdmAlg::SpdmAlgoDhe(self.common.config_info.dhe_algo),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                            alg_supported: SpdmAlg::SpdmAlgoAead(self.common.config_info.aead_algo),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                            alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                                self.common.config_info.req_asym_algo,
                            ),
                        },
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                            alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                                self.common.config_info.key_schedule_algo,
                            ),
                        },
                    ],
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_algorithm_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseAlgorithms => {
                        let algorithms =
                            SpdmAlgorithmsResponsePayload::spdm_read(&mut self.common, &mut reader);
                        let used = reader.used();
                        if let Some(algorithms) = algorithms {
                            debug!("!!! algorithms : {:02x?}\n", algorithms);

                            self.common.negotiate_info.measurement_specification_sel =
                                algorithms.measurement_specification_sel;

                            self.common.negotiate_info.opaque_data_support =
                                algorithms.other_params_selection;

                            self.common.negotiate_info.measurement_hash_sel =
                                algorithms.measurement_hash_algo;
                            if algorithms.base_hash_sel.bits() == 0 {
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                            }
                            self.common.negotiate_info.base_hash_sel = algorithms.base_hash_sel;
                            if algorithms.base_asym_sel.bits() == 0 {
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                            }
                            self.common.negotiate_info.base_asym_sel = algorithms.base_asym_sel;
                            for alg in algorithms
                                .alg_struct
                                .iter()
                                .take(algorithms.alg_struct_count as usize)
                            {
                                match &alg.alg_supported {
                                    SpdmAlg::SpdmAlgoDhe(v) => {
                                        self.common.negotiate_info.dhe_sel = *v
                                    }
                                    SpdmAlg::SpdmAlgoAead(v) => {
                                        self.common.negotiate_info.aead_sel = *v
                                    }
                                    SpdmAlg::SpdmAlgoReqAsym(v) => {
                                        self.common.negotiate_info.req_asym_sel = *v
                                    }
                                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                                        self.common.negotiate_info.key_schedule_sel = *v
                                    }
                                    SpdmAlg::SpdmAlgoUnknown(_v) => {}
                                }
                            }

                            self.common.append_message_a(send_buffer)?;
                            self.common.append_message_a(&receive_buffer[..used])?;

                            return Ok(());
                        }
                        error!("!!! algorithms : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                    SpdmRequestResponseCode::SpdmResponseError => self
                        .spdm_handle_error_response_main(
                            Some(session_id),
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                            SpdmRequestResponseCode::SpdmResponseAlgorithms,
                        ),
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
