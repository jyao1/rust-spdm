// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmContext;
use crate::config;
use crate::protocol::{
    SpdmCertChain, SpdmCertChainData, SpdmDheExchangeStruct, SpdmDigestStruct,
    SpdmDmtfMeasurementRepresentation, SpdmDmtfMeasurementStructure, SpdmDmtfMeasurementType,
    SpdmMeasurementBlockStructure, SpdmMeasurementRecordStructure, SpdmMeasurementSpecification,
    SpdmSignatureStruct, SPDM_MAX_ASYM_KEY_SIZE, SPDM_MAX_DHE_KEY_SIZE, SPDM_MAX_HASH_SIZE,
};
use codec::{u24, Codec, Reader, Writer};
use core::fmt::Debug;
extern crate alloc;
use alloc::boxed::Box;

pub trait SpdmCodec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    /// Should we assert() here? or return to caller to let the caller handle it?
    fn spdm_encode(&self, _context: &mut SpdmContext, _bytes: &mut Writer);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn spdm_read(_context: &mut SpdmContext, _: &mut Reader) -> Option<Self>;

    // /// Convenience function to get the results of `encode()`.
    // /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    // /// Should we assert() here? or return to caller to let the caller handle it?
    // fn spdm_get_encoding(&self, bytes: &mut [u8]) -> Writer {
    //     let mut ret = Writer::init(bytes);
    //     self.encode(&mut ret);
    //     ret
    // }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn spdm_read_bytes(context: &mut SpdmContext, bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::spdm_read(context, &mut rd)
    }
}

impl SpdmCodec for SpdmDigestStruct {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        assert_eq!(self.data_size, context.get_hash_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmDigestStruct> {
        let data_size = context.get_hash_size();
        let mut data = Box::new([0u8; SPDM_MAX_HASH_SIZE]);
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDigestStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmSignatureStruct {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        assert_eq!(self.data_size, context.get_asym_key_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmSignatureStruct> {
        let data_size = context.get_asym_key_size();
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmSignatureStruct { data_size, data })
    }
}
impl SpdmCodec for SpdmCertChain {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        let length = self.cert_chain.data_size + self.root_hash.data_size + 4_u16;
        length.encode(bytes);
        0u16.encode(bytes);

        self.root_hash.spdm_encode(context, bytes);

        for d in self
            .cert_chain
            .data
            .iter()
            .take(self.cert_chain.data_size as usize)
        {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmCertChain> {
        let length = u16::read(r)?;
        u16::read(r)?;
        let root_hash = SpdmDigestStruct::spdm_read(context, r)?;
        let data_size = length - 4 - root_hash.data_size;
        let mut cert_chain = SpdmCertChainData {
            data_size,
            ..Default::default()
        };
        for d in cert_chain.data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmCertChain {
            root_hash,
            cert_chain,
        })
    }
}

impl SpdmCodec for SpdmMeasurementRecordStructure {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        self.number_of_blocks.encode(bytes);
        self.measurement_record_length.encode(bytes);

        for d in self
            .measurement_record_data
            .iter()
            .take(self.measurement_record_length.get() as usize)
        {
            d.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementRecordStructure> {
        let number_of_blocks = u8::read(r)?;
        let measurement_record_length = u24::read(r)?;

        let mut measurement_record_data = [0u8; config::MAX_MEASUREMENT_RECORD_DATA_SIZE];
        for d in measurement_record_data
            .iter_mut()
            .take(measurement_record_length.get() as usize)
        {
            *d = u8::read(r)?;
        }

        Some(SpdmMeasurementRecordStructure {
            number_of_blocks,
            measurement_record_length,
            measurement_record_data,
        })
    }
}

impl SpdmCodec for SpdmDheExchangeStruct {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmDheExchangeStruct> {
        let data_size = context.get_dhe_key_size();
        let mut data = [0u8; SPDM_MAX_DHE_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDheExchangeStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmDmtfMeasurementStructure {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        let type_value = self.r#type.get_u8();
        let representation_value = self.representation.get_u8();
        let final_value = type_value + representation_value;
        final_value.encode(bytes);

        // TBD: Check measurement_hash

        self.value_size.encode(bytes);
        for v in self.value.iter().take(self.value_size as usize) {
            v.encode(bytes);
        }
    }
    fn spdm_read(
        _context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDmtfMeasurementStructure> {
        let final_value = u8::read(r)?;
        let type_value = final_value & 0x7f;
        let representation_value = final_value & 0x80;
        let representation = match representation_value {
            0 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            0x80 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
            val => SpdmDmtfMeasurementRepresentation::Unknown(val),
        };
        let r#type = match type_value {
            0 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            1 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
            2 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
            3 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
            4 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
            5 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementStructuredRepresentationMode
                }
                _ => SpdmDmtfMeasurementType::Unknown(5),
            },
            6 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(6),
            },
            7 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(7),
            },
            val => SpdmDmtfMeasurementType::Unknown(val),
        };

        // TBD: Check measurement_hash

        let value_size = u16::read(r)?;
        let mut value = [0u8; config::MAX_MEASUREMENT_RECORD_DATA_SIZE];
        for v in value.iter_mut().take(value_size as usize) {
            *v = u8::read(r)?;
        }
        Some(SpdmDmtfMeasurementStructure {
            r#type,
            representation,
            value_size,
            value,
        })
    }
}

impl SpdmCodec for SpdmMeasurementBlockStructure {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        self.index.encode(bytes);
        self.measurement_specification.encode(bytes);
        self.measurement_size.encode(bytes);
        self.measurement.spdm_encode(context, bytes);
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementBlockStructure> {
        let index = u8::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        let measurement_size = u16::read(r)?;
        let measurement = SpdmDmtfMeasurementStructure::spdm_read(context, r)?;
        Some(SpdmMeasurementBlockStructure {
            index,
            measurement_specification,
            measurement_size,
            measurement,
        })
    }
}
