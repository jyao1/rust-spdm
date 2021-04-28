// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{SpdmDigestStruct, SPDM_MAX_SLOT_NUMBER};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmGetDigestsRequestPayload {}

impl SpdmCodec for SpdmGetDigestsRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmGetDigestsRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmGetDigestsRequestPayload {})
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmDigestsResponsePayload {
    pub slot_mask: u8,
    pub slot_count: u8,
    pub digests: [SpdmDigestStruct; SPDM_MAX_SLOT_NUMBER],
}

impl SpdmCodec for SpdmDigestsResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        self.slot_mask.encode(bytes); // param2

        let mut count = 0u8;
        for i in 0..8 {
            if (self.slot_mask & (1 << i)) != 0 {
                count += 1;
            }
        }

        if count != self.slot_count {
            panic!();
        }

        for digest in self.digests.iter().take(count as usize) {
            digest.spdm_encode(context, bytes);
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmDigestsResponsePayload> {
        u8::read(r)?; // param1
        let slot_mask = u8::read(r)?; // param2

        let mut slot_count = 0u8;
        for i in 0..8 {
            if (slot_mask & (1 << i)) != 0 {
                slot_count += 1;
            }
        }

        let mut digests = [SpdmDigestStruct::default(); SPDM_MAX_SLOT_NUMBER];
        for digest in digests.iter_mut().take(slot_count as usize) {
            *digest = SpdmDigestStruct::spdm_read(context, r)?;
        }
        Some(SpdmDigestsResponsePayload {
            slot_mask,
            slot_count,
            digests,
        })
    }
}
