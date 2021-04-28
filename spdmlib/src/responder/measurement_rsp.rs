// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_measurement(&mut self, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_measurements) = get_measurements {
            debug!("!!! get_measurements : {:02x?}\n", get_measurements);
        } else {
            error!("!!! get_measurements : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let get_measurements = get_measurements.unwrap();

        let measurement_digest_size = self.common.negotiate_info.measurement_hash_sel.get_size();
        let signature_size = self.common.negotiate_info.base_asym_sel.get_size();

        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE)
        {
            self.common.runtime_info.need_measurement_signature = true;
        } else {
            self.common.runtime_info.need_measurement_signature = false;
        }

        if self
            .common
            .runtime_info
            .message_m
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        info!("send spdm measurement\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let number_of_measurement = if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll
        {
            5
        } else if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
        {
            0
        } else {
            1
        };
        let measurement_record = if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll
        {
            SpdmMeasurementRecordStructure {
                number_of_blocks: 5,
                record: [
                    SpdmMeasurementBlockStructure {
                        index: 1,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + measurement_digest_size as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: measurement_digest_size as u16,
                            value: [0x5au8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    SpdmMeasurementBlockStructure {
                        index: 2,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + measurement_digest_size as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: SHA384_DIGEST_SIZE as u16,
                            value: [0x5bu8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    SpdmMeasurementBlockStructure {
                        index: 3,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + measurement_digest_size as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: measurement_digest_size as u16,
                            value: [0x5cu8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    SpdmMeasurementBlockStructure {
                        index: 4,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + measurement_digest_size as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: measurement_digest_size as u16,
                            value: [0x5du8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    SpdmMeasurementBlockStructure {
                        index: 5,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
                            value_size: config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
                            value: [0x5eu8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                ],
            }
        } else if let SpdmMeasurementOperation::Unknown(index) =
            get_measurements.measurement_operation
        {
            SpdmMeasurementRecordStructure {
                number_of_blocks: 1,
                record: [
                    SpdmMeasurementBlockStructure {
                        index: 1,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 3 + measurement_digest_size as u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: measurement_digest_size as u16,
                            value: [0x5au8 + index; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    SpdmMeasurementBlockStructure::default(),
                    SpdmMeasurementBlockStructure::default(),
                    SpdmMeasurementBlockStructure::default(),
                    SpdmMeasurementBlockStructure::default(),
                ],
            }
        } else {
            SpdmMeasurementRecordStructure::default()
        };

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseMeasurements,
            },
            payload: SpdmMessagePayload::SpdmMeasurementsResponse(
                SpdmMeasurementsResponsePayload {
                    number_of_measurement,
                    slot_id: 0x1,
                    measurement_record,
                    nonce: SpdmNonceStruct {
                        data: [0x5fu8; SPDM_NONCE_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; config::MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: signature_size as u16,
                        data: [0x60u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        // generat signature
        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE)
        {
            let base_asym_size = self.common.negotiate_info.base_asym_sel.get_size() as usize;
            let temp_used = used - base_asym_size;
            self.common
                .runtime_info
                .message_m
                .append_message(&send_buffer[..temp_used]);

            let signature = self.common.generate_measurement_signature();
            if signature.is_err() {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
            let signature = signature.unwrap();
            // patch the message before send
            send_buffer[(used - base_asym_size)..used].copy_from_slice(signature.as_ref());
            self.common.runtime_info.message_m.reset_message();
        } else {
            self.common
                .runtime_info
                .message_m
                .append_message(&send_buffer[..used]);
        }

        let _ = self.send_message(&send_buffer[0..used]);
    }
}
