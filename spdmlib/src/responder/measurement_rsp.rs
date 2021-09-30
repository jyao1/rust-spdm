// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_measurement(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_measurement_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_measurement_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_measurements) = get_measurements {
            debug!("!!! get_measurements : {:02x?}\n", get_measurements);
        } else {
            error!("!!! get_measurements : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
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
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        info!("send spdm measurement\n");

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let _ = crypto::rand::get_random(&mut nonce);

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
            if index > 5 {
                return;
            }
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
                    nonce: SpdmNonceStruct { data: nonce },
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
        response.spdm_encode(&mut self.common, writer);
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
                .append_message(&writer.used_slice()[..temp_used]);

            let signature = self.common.generate_measurement_signature();
            if signature.is_err() {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
            let signature = signature.unwrap();
            // patch the message before send
            writer.mut_used_slice()[(used - base_asym_size)..used]
                .copy_from_slice(signature.as_ref());
            self.common.runtime_info.message_m.reset_message();
        } else {
            self.common
                .runtime_info
                .message_m
                .append_message(writer.used_slice());
        }
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
    fn test_case0_handle_spdm_measurement() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementeAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::Unknown(5),
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0xaau8,
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        context.handle_spdm_measurement(bytes);

        let data = context.common.runtime_info.message_m.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementeAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::Unknown(5)
        );

        let spdm_message_slice = &u8_slice[4..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseMeasurements
        );
        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.number_of_measurement, 1);
            assert_eq!(payload.slot_id, 1);
            assert_eq!(payload.measurement_record.number_of_blocks, 1);
            assert_eq!(payload.measurement_record.record[0].index, 1);
            assert_eq!(
                payload.measurement_record.record[0].measurement_specification,
                SpdmMeasurementSpecification::DMTF
            );
            let measurement_size = context
                .common
                .negotiate_info
                .measurement_hash_sel
                .get_size()
                + 3;
            assert_eq!(
                payload.measurement_record.record[0].measurement_size,
                measurement_size
            );
            assert_eq!(
                payload.measurement_record.record[0].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
            );
            assert_eq!(
                payload.measurement_record.record[0]
                    .measurement
                    .representation,
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
            );
            let value_size = context
                .common
                .negotiate_info
                .measurement_hash_sel
                .get_size();
            assert_eq!(
                payload.measurement_record.record[0].measurement.value_size,
                value_size
            );
            for i in 0..value_size as usize {
                assert_eq!(
                    payload.measurement_record.record[0].measurement.value[i],
                    95
                );
            }
        }
    }

    #[test]
    fn test_case1_handle_spdm_measurement() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementeAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0xaau8,
        };
        value.spdm_encode(&mut context.common, &mut writer);

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        context.handle_spdm_measurement(bytes);

        let data = context.common.runtime_info.message_m.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementeAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll
        );

        let spdm_message_slice = &u8_slice[4..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseMeasurements
        );

        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.number_of_measurement, 5);
            assert_eq!(payload.slot_id, 1);
            assert_eq!(payload.measurement_record.number_of_blocks, 5);

            for i in 0..5 {
                assert_eq!(payload.measurement_record.record[i].index, (i as u8) + 1);
                assert_eq!(
                    payload.measurement_record.record[i].measurement_specification,
                    SpdmMeasurementSpecification::DMTF
                );
            }

            let measurement_size = context
                .common
                .negotiate_info
                .measurement_hash_sel
                .get_size()
                + 3;
            for i in 0..4 {
                assert_eq!(
                    payload.measurement_record.record[i].measurement_size,
                    measurement_size
                );
                assert_eq!(
                    payload.measurement_record.record[i]
                        .measurement
                        .representation,
                    SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
                );
            }
            assert_eq!(
                payload.measurement_record.record[4].measurement_size,
                3 + config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
            );
            assert_eq!(
                payload.measurement_record.record[4]
                    .measurement
                    .representation,
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit
            );

            assert_eq!(
                payload.measurement_record.record[0].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
            );
            assert_eq!(
                payload.measurement_record.record[1].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware
            );
            assert_eq!(
                payload.measurement_record.record[2].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig
            );
            assert_eq!(
                payload.measurement_record.record[3].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig
            );
            assert_eq!(
                payload.measurement_record.record[4].measurement.r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest
            );

            let value_size = context
                .common
                .negotiate_info
                .measurement_hash_sel
                .get_size();
            assert_eq!(
                payload.measurement_record.record[0].measurement.value_size,
                value_size
            );
            assert_eq!(
                payload.measurement_record.record[1].measurement.value_size,
                SHA384_DIGEST_SIZE as u16
            );
            assert_eq!(
                payload.measurement_record.record[2].measurement.value_size,
                value_size
            );
            assert_eq!(
                payload.measurement_record.record[3].measurement.value_size,
                value_size
            );
            assert_eq!(
                payload.measurement_record.record[4].measurement.value_size,
                config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
            );

            for j in 0..value_size as usize {
                assert_eq!(
                    payload.measurement_record.record[0].measurement.value[j],
                    0x5au8
                );
                assert_eq!(
                    payload.measurement_record.record[1].measurement.value[j],
                    0x5bu8
                );
                assert_eq!(
                    payload.measurement_record.record[2].measurement.value[j],
                    0x5cu8
                );
                assert_eq!(
                    payload.measurement_record.record[3].measurement.value[j],
                    0x5du8
                );
                assert_eq!(
                    payload.measurement_record.record[4].measurement.value[j],
                    0x5eu8
                );
            }
        }
    }
}
