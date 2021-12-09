// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::config;
use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmGetCertificateRequestPayload {
    pub slot_id: u8,
    pub offset: u16,
    pub length: u16,
}

impl SpdmCodec for SpdmGetCertificateRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.slot_id.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.offset.encode(bytes);
        self.length.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetCertificateRequestPayload> {
        let slot_id = u8::read(r)?; // param1
        u8::read(r)?; // param2
        let offset = u16::read(r)?;
        let length = u16::read(r)?;

        Some(SpdmGetCertificateRequestPayload {
            slot_id,
            offset,
            length,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SpdmCertificateResponsePayload {
    pub slot_id: u8,
    pub portion_length: u16,
    pub remainder_length: u16,
    pub cert_chain: [u8; config::MAX_SPDM_CERT_PORTION_LEN],
}
impl Default for SpdmCertificateResponsePayload {
    fn default() -> SpdmCertificateResponsePayload {
        SpdmCertificateResponsePayload {
            slot_id: 0,
            portion_length: 0,
            remainder_length: 0,
            cert_chain: [0u8; config::MAX_SPDM_CERT_PORTION_LEN],
        }
    }
}

impl SpdmCodec for SpdmCertificateResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.slot_id.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.portion_length.encode(bytes);
        self.remainder_length.encode(bytes);

        for d in self.cert_chain.iter().take(self.portion_length as usize) {
            d.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmCertificateResponsePayload> {
        let slot_id = u8::read(r)?; // param1
        u8::read(r)?; // param2
        let portion_length = u16::read(r)?;
        let remainder_length = u16::read(r)?;

        let mut cert_chain = [0u8; config::MAX_SPDM_CERT_PORTION_LEN];
        for data in cert_chain.iter_mut().take(portion_length as usize) {
            *data = u8::read(r)?;
        }
        Some(SpdmCertificateResponsePayload {
            slot_id,
            portion_length,
            remainder_length,
            cert_chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_get_capabilities_request_payload() {
        let u8_slice = &mut [0u8; 12];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmGetCertificateRequestPayload::default();
        value.slot_id = 100;
        value.offset = 100;
        value.length = 100;

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(12, reader.left());
        let spdm_get_certificate_request_payload =
            SpdmGetCertificateRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 100);
        assert_eq!(spdm_get_certificate_request_payload.offset, 100);
        assert_eq!(spdm_get_certificate_request_payload.length, 100);
        assert_eq!(6, reader.left());
    }
    #[test]
    fn test_case0_spdm_certificate_response_payload() {
        let u8_slice = &mut [0u8; 520];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmCertificateResponsePayload::default();
        value.slot_id = 100;
        value.portion_length = 512;
        value.remainder_length = 100;
        value.cert_chain = [100u8; config::MAX_SPDM_CERT_PORTION_LEN];

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = common::SpdmContext::new(
            my_spdm_device_io,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(520, reader.left());
        let spdm_get_certificate_request_payload =
            SpdmCertificateResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 100);
        assert_eq!(spdm_get_certificate_request_payload.portion_length, 512);
        assert_eq!(spdm_get_certificate_request_payload.remainder_length, 100);
        for i in 0..512 {
            assert_eq!(spdm_get_certificate_request_payload.cert_chain[i], 100u8);
        }
    }
}
