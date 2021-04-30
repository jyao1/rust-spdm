// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{
    SpdmDigestStruct, SpdmRequestCapabilityFlags, SpdmResponseCapabilityFlags, SpdmSignatureStruct,
};
use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmFinishRequestAttributes: u8 {
        const SIGNATURE_INCLUDED = 0b00000001;
    }
}

impl Codec for SpdmFinishRequestAttributes {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmFinishRequestAttributes> {
        let bits = u8::read(r)?;

        SpdmFinishRequestAttributes::from_bits(bits)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmFinishRequestPayload {
    pub finish_request_attributes: SpdmFinishRequestAttributes,
    pub req_slot_id: u8,
    pub signature: SpdmSignatureStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmFinishRequestPayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.finish_request_attributes.encode(bytes); // param1
        self.req_slot_id.encode(bytes); // param2
        if self
            .finish_request_attributes
            .contains(SpdmFinishRequestAttributes::SIGNATURE_INCLUDED)
        {
            self.signature.spdm_encode(context, bytes);
        }
        self.verify_data.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmFinishRequestPayload> {
        let finish_request_attributes = SpdmFinishRequestAttributes::read(r)?; // param1
        let req_slot_id = u8::read(r)?; // param2
        let mut signature = SpdmSignatureStruct::default();
        if finish_request_attributes.contains(SpdmFinishRequestAttributes::SIGNATURE_INCLUDED) {
            signature = SpdmSignatureStruct::spdm_read(context, r)?;
        }
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmFinishRequestPayload {
            finish_request_attributes,
            req_slot_id,
            signature,
            verify_data,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmFinishResponsePayload {
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmFinishResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
        let in_clear_text = context
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        if in_clear_text {
            self.verify_data.spdm_encode(context, bytes);
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmFinishResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        let in_clear_text = context
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);

        let mut verify_data = SpdmDigestStruct::default();
        if in_clear_text {
            verify_data = SpdmDigestStruct::spdm_read(context, r)?;
        }

        Some(SpdmFinishResponsePayload { verify_data })
    }
}
