// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::msgs::SpdmCodec;
use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmRequestCapabilityFlags: u32 {
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_CAP_MASK = Self::PSK_CAP.bits | 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
    }
}

impl Codec for SpdmRequestCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmRequestCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmRequestCapabilityFlags::from_bits(bits)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmGetCapabilitiesRequestPayload {
    pub ct_exponent: u8,
    pub flags: SpdmRequestCapabilityFlags,
}

impl SpdmCodec for SpdmGetCapabilitiesRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2

        0u8.encode(bytes); // reserved
        self.ct_exponent.encode(bytes);
        0u16.encode(bytes); // reserved2
        self.flags.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCapabilitiesRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        u16::read(r)?; // reserved2
        let flags = SpdmRequestCapabilityFlags::read(r)?;

        Some(SpdmGetCapabilitiesRequestPayload { ct_exponent, flags })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmResponseCapabilityFlags: u32 {
        const CACHE_CAP = 0b0000_0001;
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const MEAS_CAP_NO_SIG = 0b0000_1000;
        const MEAS_CAP_SIG = 0b0001_0000;
        const MEAS_CAP_MASK = Self::MEAS_CAP_NO_SIG.bits | Self::MEAS_CAP_SIG.bits;
        const MEAS_FRESH_CAP = 0b0010_0000;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_CAP_WITH_CONTEXT = 0b0000_1000_0000_0000;
        const PSK_CAP_MASK = Self::PSK_CAP.bits | Self::PSK_CAP_WITH_CONTEXT.bits;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
    }
}

impl Codec for SpdmResponseCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmResponseCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmResponseCapabilityFlags::from_bits(bits)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmCapabilitiesResponsePayload {
    pub ct_exponent: u8,
    pub flags: SpdmResponseCapabilityFlags,
}

impl SpdmCodec for SpdmCapabilitiesResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2

        0u8.encode(bytes); // reserved
        self.ct_exponent.encode(bytes);
        0u16.encode(bytes); // reserved2
        self.flags.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCapabilitiesResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        u16::read(r)?; // reserved2
        let flags = SpdmResponseCapabilityFlags::read(r)?;

        Some(SpdmCapabilitiesResponsePayload { ct_exponent, flags })
    }
}

#[cfg(test)]
mod tests 
{
    use super::*;

    #[test]
    fn test_case0_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::CACHE_CAP ;
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),SpdmResponseCapabilityFlags::CACHE_CAP);  
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::CERT_CAP ;
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),SpdmRequestCapabilityFlags::CERT_CAP);  
        assert_eq!(0, reader.left());
    } 
}
