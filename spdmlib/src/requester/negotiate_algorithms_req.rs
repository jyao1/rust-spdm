// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{SpdmResult, spdm_result_err};
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_algorithm(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_algorithm(&mut send_buffer);
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_algorithm_response(0, &send_buffer[..send_used], &receive_buffer[..used])
    }

    pub fn encode_spdm_algorithm(&mut self, buf: &mut [u8]) -> usize {
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
        writer.used()
    }

    pub fn handle_spdm_algorithm_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
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
                        self.common.negotiate_info.base_hash_sel = algorithms.base_hash_sel;
                        self.common.negotiate_info.base_asym_sel = algorithms.base_asym_sel;
                        for alg in algorithms
                            .alg_struct
                            .iter()
                            .take(algorithms.alg_struct_count as usize)
                        {
                            match &alg.alg_supported {
                                SpdmAlg::SpdmAlgoDhe(v) => self.common.negotiate_info.dhe_sel = *v,
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

                        let message_a = &mut self.common.runtime_info.message_a;
                        message_a
                            .append_message(send_buffer)
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        message_a
                            .append_message(&receive_buffer[..used])
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        let message_vca = &mut self.common.runtime_info.message_vca;
                        message_vca
                            .append_message(send_buffer)
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        message_vca
                            .append_message(&receive_buffer[..used])
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        return Ok(());
                    }
                    error!("!!! algorithms : fail !!!\n");
                    spdm_result_err!(EFAULT)
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let erm = self.spdm_handle_error_response_main(
                        session_id,
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
                        SpdmRequestResponseCode::SpdmResponseAlgorithms,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_algorithm_response(
                                session_id,
                                send_buffer,
                                &receive_buffer[..used],
                            )
                        }
                        _ => spdm_result_err!(EINVAL),
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_algorithm() {
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

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let status = requester.send_receive_spdm_algorithm().is_ok();
        assert!(status);
    }
}
