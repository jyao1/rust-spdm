// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{
    SpdmMeasurementRecordStructure, SpdmNonceStruct, SpdmOpaqueStruct, SpdmSignatureStruct,
};
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
        if context.runtime_info.need_measurement_signature {
            self.nonce.encode(bytes);
        }
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
        let nonce = if context.runtime_info.need_measurement_signature {
            SpdmNonceStruct::read(r)?
        } else {
            SpdmNonceStruct::default()
        };
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
