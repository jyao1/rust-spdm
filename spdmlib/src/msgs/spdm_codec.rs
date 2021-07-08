// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::config;
use crate::msgs::*;
use codec::{u24, Codec, Reader, Writer};
use core::fmt::Debug;

pub trait SpdmCodec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    /// Should we assert() here? or return to caller to let the caller handle it?
    fn spdm_encode(&self, _context: &mut common::SpdmContext, _bytes: &mut Writer);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn spdm_read(_context: &mut common::SpdmContext, _: &mut Reader) -> Option<Self>;

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
    fn spdm_read_bytes(context: &mut common::SpdmContext, bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::spdm_read(context, &mut rd)
    }
}

impl SpdmCodec for SpdmDigestStruct {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        assert_eq!(self.data_size,context.get_hash_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmDigestStruct> {
        let data_size = context.get_hash_size();
        let mut data = [0u8; SPDM_MAX_HASH_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDigestStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmSignatureStruct {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        assert_eq!(self.data_size,context.get_asym_key_size());
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmSignatureStruct> {
        let data_size = context.get_asym_key_size();
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmSignatureStruct { data_size, data })
    }
}
impl SpdmCodec for SpdmCertChain {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        let length = self.cert_chain.data_size as u16 + self.root_hash.data_size as u16 + 4_u16;
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
    fn spdm_read(context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmCertChain> {
        let length = u16::read(r)?;
        u16::read(r)?;
        let root_hash = SpdmDigestStruct::spdm_read(context, r)?;
        let data_size = length - 4 - root_hash.data_size as u16;
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
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.number_of_blocks.encode(bytes);

        let mut calc_length = 0u32;
        for d in self.record.iter().take(self.number_of_blocks as usize) {
            if d.measurement_size != d.measurement.value_size + 3 {
                panic!();
            }
            calc_length += d.measurement_size as u32 + 4;
        }
        let record_length = u24(calc_length);
        record_length.encode(bytes);

        for d in self.record.iter().take(self.number_of_blocks as usize) {
            d.spdm_encode(context, bytes);
        }
    }
    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMeasurementRecordStructure> {
        let number_of_blocks = u8::read(r)?;
        let record_length = u24::read(r)?;

        let mut record =
            [SpdmMeasurementBlockStructure::default(); config::MAX_SPDM_MEASUREMENT_BLOCK_COUNT];
        for d in record.iter_mut().take(number_of_blocks as usize) {
            *d = SpdmMeasurementBlockStructure::spdm_read(context, r)?;
        }

        let mut calc_length = 0u32;
        for d in record.iter().take(number_of_blocks as usize) {
            if d.measurement_size != d.measurement.value_size + 3 {
                return None;
            }
            calc_length += d.measurement_size as u32 + 4;
        }
        if calc_length != record_length.0 {
            return None;
        }

        Some(SpdmMeasurementRecordStructure {
            number_of_blocks,
            record,
        })
    }
}

impl SpdmCodec for SpdmDheExchangeStruct {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDheExchangeStruct> {
        let data_size = context.get_dhe_key_size();
        let mut data = [0u8; SPDM_MAX_DHE_KEY_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmDheExchangeStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmPskContextStruct {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskContextStruct> {
        let data_size = u16::read(r)?;
        let mut data = [0u8; config::MAX_SPDM_PSK_CONTEXT_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmPskContextStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmPskHintStruct {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(_context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmPskHintStruct> {
        let data_size = u16::read(r)?;
        let mut data = [0u8; config::MAX_SPDM_PSK_HINT_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }
        Some(SpdmPskHintStruct { data_size, data })
    }
}

impl SpdmCodec for SpdmDmtfMeasurementStructure {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        let type_value = self.r#type.get_u8();
        let representation_value = self.r#type.get_u8();
        let final_value = type_value + representation_value;
        final_value.encode(bytes);

        // TBD: Check measurement_hash

        self.value_size.encode(bytes);
        for v in self.value.iter().take(self.value_size as usize) {
            v.encode(bytes);
        }
    }
    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDmtfMeasurementStructure> {
        let final_value = u8::read(r)?;
        let type_value = final_value & 0x7f;
        let representation_value = final_value & 0x80;
        let r#type = match type_value {
            0 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            1 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
            2 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
            3 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
            4 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
            val => SpdmDmtfMeasurementType::Unknown(val),
        };
        let representation = match representation_value {
            0 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            1 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
            val => SpdmDmtfMeasurementRepresentation::Unknown(val),
        };

        // TBD: Check measurement_hash

        let value_size = u16::read(r)?;
        let mut value = [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
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
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.index.encode(bytes);
        self.measurement_specification.encode(bytes);
        self.measurement_size.encode(bytes);
        self.measurement.spdm_encode(context, bytes);
    }
    fn spdm_read(
        context: &mut common::SpdmContext,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;
    #[test]
    fn test_case0_spdm_digest_struct() {
        let u8_slice = &mut [0u8; 68];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmDigestStruct {
            data_size:64,
            data: [100u8; SPDM_MAX_HASH_SIZE],
        };

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = common::SpdmContext::new(
            my_spdm_device_io,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.negotiate_info.base_hash_sel=SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(68, reader.left());
        let spdm_digest_struct =SpdmDigestStruct::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_digest_struct.data_size, 64);
        for i in 0..64 {
            assert_eq!(spdm_digest_struct.data[i], 100u8);
        }
        assert_eq!(4, reader.left());
    }
    #[test]
    fn test_case0_spdm_signature_struct(){
        let u8_slice = &mut [0u8; 512];
        let mut writer = Writer::init(u8_slice);
        let value= SpdmSignatureStruct {
            data_size: 512,
            data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
        };

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap{};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context =  common::SpdmContext::new(
            my_spdm_device_io,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.negotiate_info.base_asym_sel=SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        
        value.spdm_encode(&mut context,&mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(512, reader.left());
        let spdm_signature_struct = SpdmSignatureStruct::spdm_read(&mut context,&mut reader).unwrap();
        assert_eq!(spdm_signature_struct.data_size,512);
        for i in 0..512
        {
            assert_eq!(spdm_signature_struct.data[i],100);
        }
    }
}