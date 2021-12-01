// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
#![allow(non_snake_case)]

use crate::common;
use crate::config;
use crate::msgs::SpdmCodec;
use codec::{Codec, Reader, Writer};

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum RegistryOrStandardsBodyID {
    DMTF = 0u16,    // default vendor id len: 0
    TCG = 1u16,     // 2
    USB = 2u16,     // 2
    PCISIG = 3u16,  // 2
    IANA = 4u16,    // 4
    HDBASET = 5u16, // 4
    MIPI = 6u16,    // 2
    CXL = 7u16,     // 2
    JEDEC = 8u16,   // 2
}

impl RegistryOrStandardsBodyID {
    pub fn get_default_vendor_idlen(&self) -> u16 {
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
        }
    }
}

impl Codec for RegistryOrStandardsBodyID {
    fn encode(&self, bytes: &mut Writer) {
        (*self as u16).encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<RegistryOrStandardsBodyID> {
        let id = u16::read(r)?;
        match id {
            0u16 => Some(RegistryOrStandardsBodyID::DMTF),
            1u16 => Some(RegistryOrStandardsBodyID::TCG),
            2u16 => Some(RegistryOrStandardsBodyID::USB),
            3u16 => Some(RegistryOrStandardsBodyID::PCISIG),
            4u16 => Some(RegistryOrStandardsBodyID::IANA),
            5u16 => Some(RegistryOrStandardsBodyID::HDBASET),
            6u16 => Some(RegistryOrStandardsBodyID::MIPI),
            7u16 => Some(RegistryOrStandardsBodyID::CXL),
            8u16 => Some(RegistryOrStandardsBodyID::JEDEC),
            _ => None,
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
