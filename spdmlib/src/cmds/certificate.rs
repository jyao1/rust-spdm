// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::common;
use crate::config;
use crate::msgs::SpdmCodec;
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
