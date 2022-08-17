// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::message::*;
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmGetCapabilitiesRequestPayload {
    pub ct_exponent: u8,
    pub flags: SpdmRequestCapabilityFlags,
    // New fields from SpdmVersion12
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl SpdmCodec for SpdmGetCapabilitiesRequestPayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2

        0u8.encode(bytes); // reserved
        self.ct_exponent.encode(bytes);
        0u16.encode(bytes); // reserved2
        self.flags.encode(bytes);

        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            self.data_transfer_size.encode(bytes);
            self.max_spdm_msg_size.encode(bytes);
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCapabilitiesRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        u16::read(r)?; // reserved2
        let flags = SpdmRequestCapabilityFlags::read(r)?;

        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            let data_transfer_size = u32::read(r)?;
            let max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < 42 {
                panic!("responder: data_transfer_size or max_spdm_msg_size < 42");
            }
            Some(SpdmGetCapabilitiesRequestPayload {
                ct_exponent,
                flags,
                data_transfer_size,
                max_spdm_msg_size,
            })
        } else {
            Some(SpdmGetCapabilitiesRequestPayload {
                ct_exponent,
                flags,
                data_transfer_size: 0,
                max_spdm_msg_size: 0,
            })
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmCapabilitiesResponsePayload {
    pub ct_exponent: u8,
    pub flags: SpdmResponseCapabilityFlags,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
}

impl SpdmCodec for SpdmCapabilitiesResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2

        0u8.encode(bytes); // reserved
        self.ct_exponent.encode(bytes);
        0u16.encode(bytes); // reserved2
        self.flags.encode(bytes);

        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            self.data_transfer_size.encode(bytes);
            self.max_spdm_msg_size.encode(bytes);
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCapabilitiesResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        u8::read(r)?; // reserved
        let ct_exponent = u8::read(r)?;
        u16::read(r)?; // reserved2
        let flags = SpdmResponseCapabilityFlags::read(r)?;

        if context.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            let data_transfer_size = u32::read(r)?;
            let max_spdm_msg_size = u32::read(r)?;
            if data_transfer_size < 42 || max_spdm_msg_size < 42 {
                panic!("requester: data_transfer_size or max_spdm_msg_size < 42");
            }
            Some(SpdmCapabilitiesResponsePayload {
                ct_exponent,
                flags,
                data_transfer_size,
                max_spdm_msg_size,
            })
        } else {
            Some(SpdmCapabilitiesResponsePayload {
                ct_exponent,
                flags,
                data_transfer_size: 0,
                max_spdm_msg_size: 0,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::all();
        value.encode(&mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_response_capability_flags() {
        let value = SpdmResponseCapabilityFlags::CACHE_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::KEY_UPD_CAP;
        new_spdm_response_capability_flags(value);
        let value = SpdmResponseCapabilityFlags::HBEAT_CAP;
        new_spdm_response_capability_flags(value);
    }
    #[test]
    fn test_case2_spdm_response_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmResponseCapabilityFlags::empty();
        value.encode(&mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::all();
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::all()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_request_capability_flags() {
        let value = SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CERT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::CHAL_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::ENCRYPT_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MAC_CAP;
        new_spdm_request_capability_flags(value);
        let value = SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        new_spdm_request_capability_flags(value);
    }
    #[test]
    fn test_case3_spdm_request_capability_flags() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRequestCapabilityFlags::empty();
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            SpdmRequestCapabilityFlags::empty()
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 100,
            flags: SpdmRequestCapabilityFlags::CERT_CAP,
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 100);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::CERT_CAP
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload {
            ct_exponent: 0,
            flags: SpdmRequestCapabilityFlags::all(),
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_capabilities_request_payload =
            SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_capabilities_request_payload.ct_exponent, 0);
        assert_eq!(
            spdm_get_capabilities_request_payload.flags,
            SpdmRequestCapabilityFlags::all()
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetCapabilitiesRequestPayload::default();

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context, &mut reader);
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 100,
            flags: SpdmResponseCapabilityFlags::all(),
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 100);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::all()
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload {
            ct_exponent: 0,
            flags: SpdmResponseCapabilityFlags::all(),
            data_transfer_size: 0,
            max_spdm_msg_size: 0,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::all()
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case2_spdm_capabilities_response_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmCapabilitiesResponsePayload::default();

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_capabilities_response_payload =
            SpdmCapabilitiesResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_capabilities_response_payload.ct_exponent, 0);
        assert_eq!(
            spdm_capabilities_response_payload.flags,
            SpdmResponseCapabilityFlags::empty()
        );
        assert_eq!(2, reader.left());
    }

    fn new_spdm_response_capability_flags(value: SpdmResponseCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        value.encode(&mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmResponseCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }

    fn new_spdm_request_capability_flags(value: SpdmRequestCapabilityFlags) {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        value.encode(&mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmRequestCapabilityFlags::read(&mut reader).unwrap(),
            value
        );
        assert_eq!(0, reader.left())
    }
}
