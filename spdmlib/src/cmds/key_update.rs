// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::common;
use crate::msgs::SpdmCodec;
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

enum_builder! {
    @U8
    EnumName: SpdmKeyUpdateOperation;
    EnumVal{
        SpdmUpdateSingleKey => 0x1,
        SpdmUpdateAllKeys => 0x2,
        SpdmVerifyNewKey => 0x3
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmKeyUpdateRequestPayload {
    pub key_update_operation: SpdmKeyUpdateOperation,
    pub tag: u8,
}

impl SpdmCodec for SpdmKeyUpdateRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.key_update_operation.encode(bytes); // param1
        self.tag.encode(bytes); // param2
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyUpdateRequestPayload> {
        let key_update_operation = SpdmKeyUpdateOperation::read(r)?; // param1
        let tag = u8::read(r)?; // param2

        Some(SpdmKeyUpdateRequestPayload {
            key_update_operation,
            tag,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmKeyUpdateResponsePayload {
    pub key_update_operation: SpdmKeyUpdateOperation,
    pub tag: u8,
}

impl SpdmCodec for SpdmKeyUpdateResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.key_update_operation.encode(bytes); // param1
        self.tag.encode(bytes); // param2
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyUpdateResponsePayload> {
        let key_update_operation = SpdmKeyUpdateOperation::read(r)?; // param1
        let tag = u8::read(r)?; // param2

        Some(SpdmKeyUpdateResponsePayload {
            key_update_operation,
            tag,
        })
    }
}
