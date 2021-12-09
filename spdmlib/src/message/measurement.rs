// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::common::algo::{
    SpdmMeasurementRecordStructure, SpdmNonceStruct, SpdmSignatureStruct,
};
use crate::common::opaque::SpdmOpaqueStruct;
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementeAttributes: u8 {
        const INCLUDE_SIGNATURE = 0b00000001;
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

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmGetMeasurementsRequestPayload {
    pub measurement_attributes: SpdmMeasurementeAttributes,
    pub measurement_operation: SpdmMeasurementOperation,
    pub nonce: SpdmNonceStruct,
    pub slot_id: u8,
}

impl SpdmCodec for SpdmGetMeasurementsRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.measurement_attributes.encode(bytes); // param1
        self.measurement_operation.encode(bytes); // param2
        if self
            .measurement_attributes
            .contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE)
        {
            self.nonce.encode(bytes);
            self.slot_id.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetMeasurementsRequestPayload> {
        let measurement_attributes = SpdmMeasurementeAttributes::read(r)?; // param1
        let measurement_operation = SpdmMeasurementOperation::read(r)?; // param2
        let nonce =
            if measurement_attributes.contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE) {
                SpdmNonceStruct::read(r)?
            } else {
                SpdmNonceStruct::default()
            };
        let slot_id =
            if measurement_attributes.contains(SpdmMeasurementeAttributes::INCLUDE_SIGNATURE) {
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

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmMeasurementsResponsePayload {
    pub number_of_measurement: u8,
    pub slot_id: u8,
    pub measurement_record: SpdmMeasurementRecordStructure,
    pub nonce: SpdmNonceStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
}

impl SpdmCodec for SpdmMeasurementsResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.number_of_measurement.encode(bytes); // param1
        self.slot_id.encode(bytes); // param2
        self.measurement_record.spdm_encode(context, bytes);
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
        let slot_id = u8::read(r)?; // param2
        let measurement_record = SpdmMeasurementRecordStructure::spdm_read(context, r)?;
        let nonce = SpdmNonceStruct::read(r)?;
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = if context.runtime_info.need_measurement_signature {
            SpdmSignatureStruct::spdm_read(context, r)?
        } else {
            SpdmSignatureStruct::default()
        };
        Some(SpdmMeasurementsResponsePayload {
            number_of_measurement,
            slot_id,
            measurement_record,
            nonce,
            opaque,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::common::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_spdm_measuremente_attributes() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementeAttributes::INCLUDE_SIGNATURE;
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementeAttributes::read(&mut reader).unwrap(),
            SpdmMeasurementeAttributes::INCLUDE_SIGNATURE
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_measurements_request_payload() {
        let u8_slice = &mut [0u8; 48];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementeAttributes::INCLUDE_SIGNATURE,
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            slot_id: 0xaau8,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(48, reader.left());
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementeAttributes::INCLUDE_SIGNATURE
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

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

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
    fn test_case0_spdm_measurements_response_payload() {
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementsResponsePayload {
            number_of_measurement: 100u8,
            slot_id: 100u8,
            measurement_record: SpdmMeasurementRecordStructure {
                number_of_blocks: 5,
                record: [SpdmMeasurementBlockStructure {
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
                }; MAX_SPDM_MEASUREMENT_BLOCK_COUNT],
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

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_signature = true;
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);

        assert_eq!(1000, reader.left());
        let mut measurements_response =
            SpdmMeasurementsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(measurements_response.number_of_measurement, 100);
        assert_eq!(measurements_response.slot_id, 100);

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
