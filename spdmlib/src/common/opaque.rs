// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::spdm_codec::SpdmCodec;
use super::*;
use crate::config;
use codec::{Codec, Reader, Writer};

//pub const SPDM_MAX_OPAQUE_SIZE : usize = 1024;

#[derive(Debug, Clone)]
pub struct SpdmOpaqueStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_OPAQUE_SIZE],
}
impl Default for SpdmOpaqueStruct {
    fn default() -> SpdmOpaqueStruct {
        SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_OPAQUE_SIZE],
        }
    }
}

impl SpdmCodec for SpdmOpaqueStruct {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::default() {
            0u16.encode(bytes);
        } else {
            self.data_size.encode(bytes);
            for d in self.data.iter().take(self.data_size as usize) {
                d.encode(bytes);
            }
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmOpaqueStruct> {
        let data_size = u16::read(r)?;
        let mut data = [0u8; config::MAX_SPDM_OPAQUE_SIZE];
        if context.negotiate_info.opaque_data_support != SpdmOpaqueSupport::default() {
            for d in data.iter_mut().take(data_size as usize) {
                *d = u8::read(r)?;
            }
        }

        Some(SpdmOpaqueStruct { data_size, data })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmOpaqueSupport: u8 {
        const OPAQUE_DATA_FMT0 = 0b0000_0001;
        const OPAQUE_DATA_FMT1 = 0b0000_0010;
    }
}

impl Codec for SpdmOpaqueSupport {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmOpaqueSupport> {
        let bits = u8::read(r)?;

        SpdmOpaqueSupport::from_bits(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MAX_SPDM_OPAQUE_SIZE;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_opaque_struct() {
        let u8_slice = &mut [0u8; 68];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmOpaqueStruct {
            data_size: 64,
            data: [100u8; MAX_SPDM_OPAQUE_SIZE],
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(68, reader.left());
        let spdm_opaque_struct = SpdmOpaqueStruct::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_opaque_struct.data_size, 64);
        for i in 0..64 {
            assert_eq!(spdm_opaque_struct.data[i], 100);
        }
        assert_eq!(2, reader.left());
    }
}
