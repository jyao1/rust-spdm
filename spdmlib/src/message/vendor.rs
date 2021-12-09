// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(non_snake_case)]

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::config;
use codec::{enum_builder, Codec, Reader, Writer};

enum_builder! {
    @U16
    EnumName: RegistryOrStandardsBodyID;
    EnumVal{
        DMTF => 0x00,
        TCG => 0x01,
        USB => 0x02,
        PCISIG => 0x03,
        IANA => 0x04,
        HDBASET => 0x05,
        MIPI => 0x06,
        CXL => 0x07,
        JEDEC => 0x08
    }
}

impl RegistryOrStandardsBodyID {
    pub fn get_default_vendor_id_len(&self) -> u16 {
        match self {
            RegistryOrStandardsBodyID::DMTF => 0,
            RegistryOrStandardsBodyID::TCG => 2,
            RegistryOrStandardsBodyID::USB => 2,
            RegistryOrStandardsBodyID::PCISIG => 2,
            RegistryOrStandardsBodyID::IANA => 4,
            RegistryOrStandardsBodyID::HDBASET => 4,
            RegistryOrStandardsBodyID::MIPI => 2,
            RegistryOrStandardsBodyID::CXL => 2,
            RegistryOrStandardsBodyID::JEDEC => 2,
            RegistryOrStandardsBodyID::Unknown(_) => 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct VendorIDStruct {
    pub Len: u8,
    pub VendorID: [u8; config::MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
}

impl Codec for VendorIDStruct {
    fn encode(&self, bytes: &mut Writer) {
        self.Len.encode(bytes);
        for d in self.VendorID.iter().take(self.Len as usize) {
            d.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<VendorIDStruct> {
        let Len = u8::read(r)?;
        let mut VendorID = [0u8; config::MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
        for d in VendorID.iter_mut().take(Len as usize) {
            *d = u8::read(r)?;
        }
        Some(VendorIDStruct { Len, VendorID })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ReqPayloadStruct {
    pub ReqLength: u16,
    pub VendorDefinedReqPayload: [u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}
impl Codec for ReqPayloadStruct {
    fn encode(&self, bytes: &mut Writer) {
        self.ReqLength.encode(bytes);
        for d in self
            .VendorDefinedReqPayload
            .iter()
            .take(self.ReqLength as usize)
        {
            d.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<ReqPayloadStruct> {
        let ReqLength = u16::read(r)?;
        let mut VendorDefinedReqPayload = [0u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
        for d in VendorDefinedReqPayload.iter_mut().take(ReqLength as usize) {
            *d = u8::read(r)?;
        }
        Some(ReqPayloadStruct {
            ReqLength,
            VendorDefinedReqPayload,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ResPayloadStruct {
    pub ResLength: u16,
    pub VendorDefinedResPayload: [u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
}

impl Codec for ResPayloadStruct {
    fn encode(&self, bytes: &mut Writer) {
        self.ResLength.encode(bytes);
        for d in self
            .VendorDefinedResPayload
            .iter()
            .take(self.ResLength as usize)
        {
            d.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<ResPayloadStruct> {
        let ResLength = u16::read(r)?;
        let mut VendorDefinedResPayload = [0u8; config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE];
        for d in VendorDefinedResPayload.iter_mut().take(ResLength as usize) {
            *d = u8::read(r)?;
        }
        Some(ResPayloadStruct {
            ResLength,
            VendorDefinedResPayload,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SpdmVendorDefinedRequestPayload {
    pub StandardID: RegistryOrStandardsBodyID,
    pub VendorID: VendorIDStruct,
    pub ReqPayload: ReqPayloadStruct,
}

impl SpdmCodec for SpdmVendorDefinedRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.StandardID.encode(bytes); //Standard ID
        self.VendorID.encode(bytes);
        self.ReqPayload.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let StandardID = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let VendorID = VendorIDStruct::read(r)?;
        let ReqPayload = ReqPayloadStruct::read(r)?;

        Some(SpdmVendorDefinedRequestPayload {
            StandardID,
            VendorID,
            ReqPayload,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SpdmVendorDefinedResponsePayload {
    pub StandardID: RegistryOrStandardsBodyID,
    pub VendorID: VendorIDStruct,
    pub ResPayload: ResPayloadStruct,
}

impl SpdmCodec for SpdmVendorDefinedResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.StandardID.encode(bytes); //Standard ID
        self.VendorID.encode(bytes);
        self.ResPayload.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmVendorDefinedResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let StandardID = RegistryOrStandardsBodyID::read(r)?; // Standard ID
        let VendorID = VendorIDStruct::read(r)?;
        let ResPayload = ResPayloadStruct::read(r)?;

        Some(SpdmVendorDefinedResponsePayload {
            StandardID,
            VendorID,
            ResPayload,
        })
    }
}
