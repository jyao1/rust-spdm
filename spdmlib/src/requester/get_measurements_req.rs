// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{SpdmResult, spdm_err, spdm_result_err};
use crate::crypto;
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_measurement_record(
        &mut self,
        session_id: Option<u32>,
        measurement_attributes: SpdmMeasurementeAttributes,
        measurement_operation: SpdmMeasurementOperation,
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure,
        slot_id: u8,
    ) -> SpdmResult<u8> {
        info!("send spdm measurement\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_measurement_record(
            measurement_attributes,
            measurement_operation,
            slot_id,
            &mut send_buffer,
        )?;
        match session_id {
            Some(session_id) => {
                self.send_secured_message(session_id, &send_buffer[..send_used], false)?;
            }
            None => {
                self.send_message(&send_buffer[..send_used])?;
            }
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = match session_id {
            Some(session_id) => {
                self.receive_secured_message(session_id, &mut receive_buffer, true)?
            }
            None => self.receive_message(&mut receive_buffer, true)?,
        };

        self.handle_spdm_measurement_record_response(
            session_id,
            slot_id,
            measurement_attributes,
            measurement_operation,
            spdm_measurement_record_structure,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_measurement_record(
        &mut self,
        measurement_attributes: SpdmMeasurementeAttributes,
        measurement_operation: SpdmMeasurementOperation,
        slot_id: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        crypto::rand::get_random(&mut nonce)?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            },
            payload: SpdmMessagePayload::SpdmGetMeasurementsRequest(
                SpdmGetMeasurementsRequestPayload {
                    measurement_attributes,
                    measurement_operation,
                    nonce: SpdmNonceStruct { data: nonce },
                    slot_id,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        Ok(writer.used())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_measurement_record_response(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        measurement_attributes: SpdmMeasurementeAttributes,
        measurement_operation: SpdmMeasurementOperation,
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<u8> {
        if measurement_attributes.contains(SpdmMeasurementeAttributes::SIGNATURE_REQUESTED) {
            self.common.runtime_info.need_measurement_signature = true;
        } else {
            self.common.runtime_info.need_measurement_signature = false;
        }

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseMeasurements => {
                    let measurements =
                        SpdmMeasurementsResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(measurements) = measurements {
                        debug!("!!! measurements : {:02x?}\n", measurements);

                        if message_header.version == SpdmVersion::SpdmVersion12 {
                            self.common.runtime_info.content_changed = measurements.content_changed;
                        }

                        // verify signature
                        if measurement_attributes
                            .contains(SpdmMeasurementeAttributes::SIGNATURE_REQUESTED)
                        {
                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used - base_asym_size;

                            let message_m = match session_id {
                                Some(session_id) => {
                                    let session = if let Some(s) =
                                        self.common.get_session_via_id(session_id)
                                    {
                                        s
                                    } else {
                                        return spdm_result_err!(EFAULT);
                                    };
                                    &mut session.runtime_info.message_m
                                }
                                None => &mut self.common.runtime_info.message_m,
                            };
                            message_m
                                .append_message(send_buffer)
                                .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                            message_m
                                .append_message(&receive_buffer[..temp_used])
                                .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                            if self
                                .verify_measurement_signature(
                                    slot_id,
                                    session_id,
                                    &measurements.signature,
                                )
                                .is_err()
                            {
                                error!("verify_measurement_signature fail");
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_measurement_signature pass");
                            }
                            match session_id {
                                Some(session_id) => {
                                    let session = if let Some(s) =
                                        self.common.get_session_via_id(session_id)
                                    {
                                        s
                                    } else {
                                        return spdm_result_err!(EFAULT);
                                    };
                                    session.runtime_info.message_m.reset_message();
                                }
                                None => self.common.runtime_info.message_m.reset_message(),
                            };
                        } else {
                            let message_m = match session_id {
                                Some(session_id) => {
                                    let session = if let Some(s) =
                                        self.common.get_session_via_id(session_id)
                                    {
                                        s
                                    } else {
                                        return spdm_result_err!(EFAULT);
                                    };
                                    &mut session.runtime_info.message_m
                                }
                                None => &mut self.common.runtime_info.message_m,
                            };
                            message_m
                                .append_message(send_buffer)
                                .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                            message_m
                                .append_message(&receive_buffer[..used])
                                .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        }

                        *spdm_measurement_record_structure = SpdmMeasurementRecordStructure {
                            ..measurements.measurement_record
                        };

                        match measurement_operation {
                            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber => {
                                Ok(measurements.number_of_measurement)
                            }
                            SpdmMeasurementOperation::SpdmMeasurementRequestAll => {
                                Ok(measurements.measurement_record.number_of_blocks)
                            }
                            _ => Ok(measurements.measurement_record.number_of_blocks),
                        }
                    } else {
                        error!("!!! measurements : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let sid: u32 = if let Some(sid_) = session_id { sid_ } else { 0 };
                    let erm = self.spdm_handle_error_response_main(
                        sid,
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestGetMeasurements,
                        SpdmRequestResponseCode::SpdmResponseMeasurements,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_measurement_record_response(
                                session_id,
                                slot_id,
                                measurement_attributes,
                                measurement_operation,
                                spdm_measurement_record_structure,
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

    pub fn send_receive_spdm_measurement(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        spdm_measuremente_attributes: SpdmMeasurementeAttributes,
        measurement_operation: SpdmMeasurementOperation,
        out_total_number: &mut u8, // out, total number when measurement_operation = SpdmMeasurementQueryTotalNumber
        //      number of blocks got measured.
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure, // out
    ) -> SpdmResult {
        if let Ok(total_number) = self.send_receive_spdm_measurement_record(
            session_id,
            spdm_measuremente_attributes,
            measurement_operation,
            spdm_measurement_record_structure,
            slot_id,
        ) {
            *out_total_number = total_number;
            Ok(())
        } else {
            spdm_result_err!(EFAULT)
        }
    }

    pub fn verify_measurement_signature(
        &mut self,
        slot_id: u8,
        session_id: Option<u32>,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let mut message = ManagedBuffer::default();

        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            let message_vca = self.common.runtime_info.message_vca.clone();
            message
                .append_message(message_vca.as_ref())
                .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
        }

        match session_id {
            None => {
                message
                    .append_message(self.common.runtime_info.message_m.as_ref())
                    .ok_or_else(|| spdm_err!(ENOMEM))?;
            }
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                    s
                } else {
                    return spdm_result_err!(EINVAL);
                };
                message
                    .append_message(session.runtime_info.message_m.as_ref())
                    .ok_or_else(|| spdm_err!(ENOMEM))?;
            }
        }

        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        debug!("message_m - {:02x?}", message.as_ref());
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
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            message
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
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

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    #[should_panic(expected = "not implemented")]
    fn test_case0_send_receive_spdm_measurement() {
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

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        let message_m = &[0];
        responder
            .common
            .runtime_info
            .message_m
            .append_message(message_m);
        responder.common.reset_runtime_info();

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(SpdmCertChain::default());
        requester.common.peer_info.peer_cert_chain[0]
            .as_mut()
            .unwrap()
            .cert_chain = REQ_CERT_CHAIN_DATA;
        requester.common.reset_runtime_info();

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber;
        let mut total_number: u8 = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementeAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut total_number,
                &mut spdm_measurement_record_structure,
            )
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementRequestAll;
        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementeAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut total_number,
                &mut spdm_measurement_record_structure,
            )
            .is_ok();
        assert!(status);

        let measurement_operation = SpdmMeasurementOperation::Unknown(5);
        let status = requester
            .send_receive_spdm_measurement(
                None,
                0,
                SpdmMeasurementeAttributes::SIGNATURE_REQUESTED,
                measurement_operation,
                &mut total_number,
                &mut spdm_measurement_record_structure,
            )
            .is_ok();
        assert!(status);
    }
}
