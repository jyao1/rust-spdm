// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_measurement_record(
        &mut self,
        measurement_attributes: SpdmMeasurementeAttributes,
        measurement_operation: SpdmMeasurementOperation,
        slot_id: u8,
    ) -> SpdmResult<u8> {
        info!("send spdm measurement\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let nonce = [0xafu8; SPDM_NONCE_SIZE];
        //let spdm_random = SpdmCryptoRandom {}; // TBD
        //spdm_random.get_random (&mut nonce);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestGetMeasurements,
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
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        // append message_m
        if self
            .common
            .runtime_info
            .message_m
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }

        if measurement_attributes.contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE) {
            self.common.runtime_info.need_measurement_signature = true;
        } else {
            self.common.runtime_info.need_measurement_signature = false;
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseMeasurements => {
                    let measurements =
                        SpdmMeasurementsResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(measurements) = measurements {
                        debug!("!!! measurements : {:02x?}\n", measurements);

                        // verify signature
                        if measurement_attributes
                            .contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE)
                        {
                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used - base_asym_size;
                            if self
                                .common
                                .runtime_info
                                .message_m
                                .append_message(&receive_buffer[..temp_used])
                                .is_none()
                            {
                                return spdm_result_err!(ENOMEM);
                            }
                            if self
                                .common
                                .verify_measurement_signature(&measurements.signature)
                                .is_err()
                            {
                                error!("verify_measurement_signature fail");
                                return spdm_result_err!(EFAULT);
                            } else {
                                info!("verify_measurement_signature pass");
                            }
                            self.common.runtime_info.message_m.reset_message();
                        } else if self
                            .common
                            .runtime_info
                            .message_m
                            .append_message(&receive_buffer[..used])
                            .is_none()
                        {
                            return spdm_result_err!(ENOMEM);
                        }

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
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }

    pub fn send_receive_spdm_measurement(
        &mut self,
        measurement_operation: SpdmMeasurementOperation,
        slot_id: u8,
    ) -> SpdmResult {
        match measurement_operation {
            SpdmMeasurementOperation::SpdmMeasurementRequestAll => self
                .send_receive_spdm_measurement_record(
                    SpdmMeasurementeAttributes::INCLUDE_SIGNATURE,
                    SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                    slot_id,
                )
                .and(Ok(())),
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber => {
                if let Ok(total_number) = self.send_receive_spdm_measurement_record(
                    SpdmMeasurementeAttributes::empty(),
                    SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                    slot_id,
                ) {
                    for block_i in 1..(total_number + 1) {
                        if self
                            .send_receive_spdm_measurement_record(
                                if block_i == total_number {
                                    SpdmMeasurementeAttributes::INCLUDE_SIGNATURE
                                } else {
                                    SpdmMeasurementeAttributes::empty()
                                },
                                SpdmMeasurementOperation::Unknown(block_i as u8),
                                slot_id,
                            )
                            .is_err()
                        {
                            return spdm_result_err!(EFAULT);
                        }
                    }
                    Ok(())
                } else {
                    spdm_result_err!(EFAULT)
                }
            }
            SpdmMeasurementOperation::Unknown(index) => self
                .send_receive_spdm_measurement_record(
                    SpdmMeasurementeAttributes::INCLUDE_SIGNATURE,
                    SpdmMeasurementOperation::Unknown(index as u8),
                    slot_id,
                )
                .and(Ok(())),
        }
    }
}
