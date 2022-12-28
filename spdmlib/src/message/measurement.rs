// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::protocol::opaque::SpdmOpaqueStruct;
use crate::protocol::{SpdmMeasurementRecordStructure, SpdmNonceStruct, SpdmSignatureStruct};
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

use super::SpdmVersion;

pub const MEASUREMENT_RESPONDER_PARAM2_SLOT_ID_MASK: u8 = 0b0000_1111;
pub const MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_MASK: u8 = 0b0011_0000;
pub const MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_NOT_SUPPORTED_VALUE: u8 = 0b0000_0000;
pub const MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_DETECTED_CHANGE_VALUE: u8 = 0b0001_0000;
pub const MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_NO_CHANGE_VALUE: u8 = 0b0010_0000;

pub const RESERVED_INDEX_START: u8 = 0xF0;
pub const RESERVED_INDEX_END: u8 = 0xFC;

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementeAttributes: u8 {
        const SIGNATURE_REQUESTED = 0b00000001;
        const RAW_BIT_STREAM_REQUESTED = 0b0000_0010;
    }
}

impl Codec for SpdmMeasurementeAttributes {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementeAttributes> {
        let bits = u8::read(r)?;

        SpdmMeasurementeAttributes::from_bits(bits)
    }
}

enum_builder! {
    @U8
    EnumName: SpdmMeasurementOperation;
    EnumVal{
        SpdmMeasurementQueryTotalNumber => 0x0,
        SpdmMeasurementRequestAll => 0xFF
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmGetMeasurementsRequestPayload {
    pub measurement_attributes: SpdmMeasurementeAttributes,
    pub measurement_operation: SpdmMeasurementOperation,
    pub nonce: SpdmNonceStruct,
    pub slot_id: u8,
}

impl SpdmCodec for SpdmGetMeasurementsRequestPayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.measurement_attributes.encode(bytes); // param1
        if let SpdmMeasurementOperation::Unknown(x) = self.measurement_operation {
            if (RESERVED_INDEX_START..=RESERVED_INDEX_END).contains(&x) {
                panic!("Invalid Index\n");
            }
        }
        self.measurement_operation.encode(bytes); // param2
        if self
            .measurement_attributes
            .contains(SpdmMeasurementeAttributes::SIGNATURE_REQUESTED)
        {
            self.nonce.encode(bytes);
            if context.negotiate_info.spdm_version_sel != SpdmVersion::SpdmVersion10 {
                self.slot_id.encode(bytes);
            }
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetMeasurementsRequestPayload> {
        let measurement_attributes = SpdmMeasurementeAttributes::read(r)?; // param1
        let measurement_operation = SpdmMeasurementOperation::read(r)?; // param2
        if let SpdmMeasurementOperation::Unknown(x) = measurement_operation {
            if (RESERVED_INDEX_START..=RESERVED_INDEX_END).contains(&x) {
                log::error!("Invalid Index\n");
                return None;
            }
        }
        let nonce =
            if measurement_attributes.contains(SpdmMeasurementeAttributes::SIGNATURE_REQUESTED) {
                SpdmNonceStruct::read(r)?
            } else {
                SpdmNonceStruct::default()
            };
        let slot_id = if context.negotiate_info.spdm_version_sel != SpdmVersion::SpdmVersion10
            && measurement_attributes.contains(SpdmMeasurementeAttributes::SIGNATURE_REQUESTED)
        {
            u8::read(r)?
        } else {
            0
        };

        Some(SpdmGetMeasurementsRequestPayload {
            measurement_attributes,
            measurement_operation,
            nonce,
            slot_id,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMeasurementsResponsePayload {
    pub spdm_measurement_operation: SpdmMeasurementOperation,
    pub number_of_measurement: u8,
    pub content_changed: u8,
    pub slot_id: u8,
    pub measurement_record: SpdmMeasurementRecordStructure,
    pub nonce: SpdmNonceStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
}

impl SpdmCodec for SpdmMeasurementsResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        if self.spdm_measurement_operation
            != SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
        {
            0u8.encode(bytes); // param1
        } else {
            self.number_of_measurement.encode(bytes); // param1
        }
        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12
            && context.config_info.runtime_content_change_support
        // param2
        {
            (self.slot_id | self.content_changed).encode(bytes);
        } else if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion11 {
            self.slot_id.encode(bytes);
        } else {
            0u8.encode(bytes);
        }
        if self.spdm_measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
        {
            0u32.encode(bytes); // NumberOfBlocks and MeasurementRecordLength
        } else {
            self.measurement_record.spdm_encode(context, bytes);
        }
        self.nonce.encode(bytes);
        self.opaque.spdm_encode(context, bytes);
        if context.runtime_info.need_measurement_signature {
            self.signature.spdm_encode(context, bytes);
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementsResponsePayload> {
        let number_of_measurement = u8::read(r)?; // param1
        let param2 = u8::read(r)?; // param2
        let slot_id = param2 & MEASUREMENT_RESPONDER_PARAM2_SLOT_ID_MASK; // Bit [3:0]
        let content_changed = param2 & MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_MASK; // Bit [5:4]
        let measurement_record = SpdmMeasurementRecordStructure::spdm_read(context, r)?;
        let nonce = SpdmNonceStruct::read(r)?;
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = if context.runtime_info.need_measurement_signature {
            SpdmSignatureStruct::spdm_read(context, r)?
        } else {
            SpdmSignatureStruct::default()
        };
        let spdm_measurement_operation = if number_of_measurement == 1 {
            SpdmMeasurementOperation::Unknown(number_of_measurement) // requester should not use this value
        } else if measurement_record.number_of_blocks == 0 {
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
        } else {
            SpdmMeasurementOperation::SpdmMeasurementRequestAll
        };
        Some(SpdmMeasurementsResponsePayload {
            spdm_measurement_operation,
            number_of_measurement,
            content_changed,
            slot_id,
            measurement_record,
            nonce,
            opaque,
            signature,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct OperationalMode: u32 {
        const MANUFACTURING_MODE = 0b0000_0001;
        const VALIDATION_MODE = 0b0000_0010;
        const NORMAL_OPERATIONAL_MODE = 0b0000_0100;
        const RECOVERY_MODE = 0b0000_1000;
        const RETURN_MERCHANDISE_AUTHORIZATION_MODE = 0b0001_0000;
        const DECOMMISSIONED_MODE = 0b0010_0000;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct DeviceMode: u32 {
        const NON_INVASIVE_DEBUG_MODE = 0b0000_0001;
        const INVASIVE_DEBUG_MODE = 0b0000_0010;
        const NON_INVASIVE_DEBUG_MODE_ACTIVE_RESET_CYCLE = 0b0000_0100;
        const INVASIVE_DEBUG_MODE_ACTIVE_RESET_CYCLE = 0b0000_1000;
        const INVASIVE_DEBUG_MODE_ACTIVE_AT_LEAST_ONCE_SINCE_MANUFACTURING_MODE = 0b0001_0000;
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMeasurementsDeviceMode {
    pub operational_mode_capabilties: OperationalMode,
    pub operational_mode_state: OperationalMode,
    pub device_mode_capabilties: DeviceMode,
    pub device_mode_state: DeviceMode,
}

#[cfg(all(test,))]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(all(test,))]
mod tests {
    use super::*;
    use crate::common::gen_array_clone;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::config::*;
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};

    #[test]
    fn test_case0_spdm_spdm_measuremente_attributes() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementeAttributes::SIGNATURE_REQUESTED;
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementeAttributes::read(&mut reader).unwrap(),
            SpdmMeasurementeAttributes::SIGNATURE_REQUESTED
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_measurements_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementeAttributes::SIGNATURE_REQUESTED,
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0xaau8,
        };

        create_spdm_context!(context);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementeAttributes::SIGNATURE_REQUESTED
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        );
        assert_eq!(get_measurements.slot_id, 0xaau8);
        for i in 0..32 {
            assert_eq!(get_measurements.nonce.data[i], 100u8);
        }
        assert_eq!(13, reader.left());
    }
    #[test]
    fn test_case1_spdm_get_measurements_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementeAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0xaau8,
        };

        create_spdm_context!(context);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementeAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
        );
        assert_eq!(get_measurements.slot_id, 0);
        for i in 0..32 {
            assert_eq!(get_measurements.nonce.data[i], 0);
        }
        assert_eq!(46, reader.left());
    }
    #[test]
    #[should_panic]
    fn test_case0_spdm_measurements_response_payload() {
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementsResponsePayload {
            spdm_measurement_operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            number_of_measurement: 100u8,
            slot_id: 7u8,
            content_changed: MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_NOT_SUPPORTED_VALUE,
            measurement_record: SpdmMeasurementRecordStructure {
                number_of_blocks: 5,
                record: gen_array_clone(
                    SpdmMeasurementBlockStructure {
                        index: 100u8,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 67u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                            representation:
                                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: 64u16,
                            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    },
                    MAX_SPDM_MEASUREMENT_BLOCK_COUNT,
                ),
            },
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: 512,
                data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_signature = true;
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);

        assert_eq!(1000, reader.left());
        let mut measurements_response =
            SpdmMeasurementsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(measurements_response.number_of_measurement, 100);
        assert_eq!(measurements_response.slot_id, 7);
        assert_eq!(
            measurements_response.content_changed,
            MEASUREMENT_RESPONDER_PARAM2_CONTENT_CHANGED_NOT_SUPPORTED_VALUE
        );

        assert_eq!(measurements_response.measurement_record.number_of_blocks, 5);
        for i in 0..5 {
            assert_eq!(
                measurements_response.measurement_record.record[i].index,
                100
            );
            assert_eq!(
                measurements_response.measurement_record.record[i].measurement_specification,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                measurements_response.measurement_record.record[i].measurement_size,
                67
            );
            assert_eq!(
                measurements_response.measurement_record.record[i]
                    .measurement
                    .r#type,
                SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
            );
            assert_eq!(
                measurements_response.measurement_record.record[i]
                    .measurement
                    .representation,
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
            );
            assert_eq!(
                measurements_response.measurement_record.record[i]
                    .measurement
                    .value_size,
                64
            );
            for j in 0..64 {
                assert_eq!(
                    measurements_response.measurement_record.record[i]
                        .measurement
                        .value[j],
                    100
                );
            }
        }
        for i in 0..32 {
            assert_eq!(measurements_response.nonce.data[i], 100);
        }

        assert_eq!(measurements_response.opaque.data_size, 64);
        for i in 0..64 {
            assert_eq!(measurements_response.opaque.data[i], 100);
        }

        assert_eq!(measurements_response.signature.data_size, 512);
        for i in 0..512 {
            assert_eq!(measurements_response.signature.data[i], 100);
        }
        assert_eq!(29, reader.left());

        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);

        context.runtime_info.need_measurement_signature = false;
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(1000, reader.left());
        measurements_response =
            SpdmMeasurementsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(measurements_response.signature.data_size, 0);

        for i in 0..32 {
            assert_eq!(measurements_response.nonce.data[i], 100);
        }
        for i in 0..512 {
            assert_eq!(measurements_response.signature.data[i], 0);
        }
        assert_eq!(541, reader.left());
    }
}
