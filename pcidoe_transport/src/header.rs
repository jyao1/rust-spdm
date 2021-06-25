// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmTransportEncap;
use spdmlib::error::SpdmResult;
use spdmlib::{spdm_err, spdm_result_err};

enum_builder! {
    @U16
    EnumName: PciDoeVendorId;
    EnumVal{
        PciDoeVendorIdPciSig => 0x0001
    }
}

enum_builder! {
    @U8
    EnumName: PciDoeDataObjectType;
    EnumVal{
        PciDoeDataObjectTypeDoeDiscovery => 0x00,
        PciDoeDataObjectTypeSpdm => 0x01,
        PciDoeDataObjectTypeSecuredSpdm => 0x02
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PciDoeMessageHeader {
    pub vendor_id: PciDoeVendorId,
    pub data_object_type: PciDoeDataObjectType,
    pub payload_length: u32, // in bytes
}

impl Codec for PciDoeMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.vendor_id.encode(bytes);
        self.data_object_type.encode(bytes);
        0u8.encode(bytes);
        let mut length = (self.payload_length + 8) >> 2;
        if length > 0x100000 {
            panic!();
        }
        if length == 0x100000 {
            length = 0;
        }
        length.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<PciDoeMessageHeader> {
        let vendor_id = PciDoeVendorId::read(r)?;
        let data_object_type = PciDoeDataObjectType::read(r)?;
        u8::read(r)?;
        let mut length = u32::read(r)?;
        if length == 0 {
            length = 0x40000;
        }
        if length < 2 {
            return None;
        }
        let payload_length = (length << 2) - 8;
        Some(PciDoeMessageHeader {
            vendor_id,
            data_object_type,
            payload_length,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PciDoeTransportEncap {}

impl SpdmTransportEncap for PciDoeTransportEncap {
    fn encap(
        &mut self,
        spdm_buffer: &[u8],
        transport_buffer: &mut [u8],
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let aligned_payload_len = (payload_len + 3) / 4 * 4;
        let mut writer = Writer::init(&mut transport_buffer[..]);
        let pcidoe_header = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: if secured_message {
                PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm
            } else {
                PciDoeDataObjectType::PciDoeDataObjectTypeSpdm
            },
            payload_length: aligned_payload_len as u32,
        };
        pcidoe_header.encode(&mut writer);
        let header_size = writer.used();
        if transport_buffer.len() < header_size + aligned_payload_len {
            return spdm_result_err!(EINVAL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + aligned_payload_len)
    }

    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&transport_buffer[..]);
        let secured_message;
        match PciDoeMessageHeader::read(&mut reader) {
            Some(pcidoe_header) => {
                match pcidoe_header.vendor_id {
                    PciDoeVendorId::PciDoeVendorIdPciSig => {}
                    _ => return spdm_result_err!(EINVAL),
                }
                match pcidoe_header.data_object_type {
                    PciDoeDataObjectType::PciDoeDataObjectTypeSpdm => secured_message = false,
                    PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm => secured_message = true,
                    _ => return spdm_result_err!(EINVAL),
                }
            }
            None => return spdm_result_err!(EIO),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        // TBD : check payload_size with Length field;
        if spdm_buffer.len() < payload_size {
            return spdm_result_err!(EINVAL);
        }
        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    fn encap_app(&mut self, spdm_buffer: &[u8], app_buffer: &mut [u8]) -> SpdmResult<usize> {
        app_buffer[0..spdm_buffer.len()].copy_from_slice(spdm_buffer);
        Ok(spdm_buffer.len())
    }

    fn decap_app(&mut self, app_buffer: &[u8], spdm_buffer: &mut [u8]) -> SpdmResult<usize> {
        spdm_buffer[0..app_buffer.len()].copy_from_slice(app_buffer);
        Ok(app_buffer.len())
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        0
    }
    fn get_max_random_count(&mut self) -> u16 {
        0
    }
}


#[cfg(test)]
mod tests 
{
    use super::*;

    #[test]
    fn test_case0_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 100,
        };
         value.encode(&mut writer);
         let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let pcidoemessageheader =PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(0, reader.left());
        assert_eq!(pcidoemessageheader.vendor_id,PciDoeVendorId::PciDoeVendorIdPciSig); 
        assert_eq!(pcidoemessageheader.data_object_type,PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery); 
        assert_eq!(pcidoemessageheader.payload_length,100); 
    }
    #[test]
    fn test_case1_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 0xffff8,
        };
         value.encode(&mut writer);
         let mut reader = Reader::init(u8_slice);
        let pcidoemessageheader =PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(pcidoemessageheader.payload_length,0xffff8); 
    }
    #[test]
    fn test_case2_mctpmessageheader() {
        let u8_slice = &mut [0u8; 10];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 0,
        };
         value.encode(&mut writer);
        let mut reader = Reader::init(u8_slice);
        let pcidoemessageheader =PciDoeMessageHeader::read(&mut reader).unwrap();
        assert_eq!(2, reader.left());
        assert_eq!(pcidoemessageheader.payload_length,0);  
    }
    #[test]
    fn test_case3_mctpmessageheader() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 0x100,
        };

         value.encode(&mut writer);
        assert_eq!(0, writer.left());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let pcidoemessageheader =PciDoeMessageHeader::read(&mut reader);
        assert_eq!(0, reader.left());
        assert_eq!(pcidoemessageheader.is_none(), true); 
    }
    #[test]
    #[should_panic]
    fn test_case4_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 0xffffffff,
        };
        value.encode(&mut writer);
    }
    #[test]
    #[should_panic]
    fn test_case5_mctpmessageheader() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value =  PciDoeMessageHeader
        {
            vendor_id :PciDoeVendorId::PciDoeVendorIdPciSig ,
            data_object_type :PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery ,
            payload_length : 0xf00000,
        };
         value.encode(&mut writer);     
    }
}
