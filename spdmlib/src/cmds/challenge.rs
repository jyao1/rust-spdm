// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{
    SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmNonceStruct, SpdmOpaqueStruct,
    SpdmSignatureStruct,
};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmChallengeRequestPayload {
    pub slot_id: u8,
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub nonce: SpdmNonceStruct,
}

impl SpdmCodec for SpdmChallengeRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.slot_id.encode(bytes); // param1
        self.measurement_summary_hash_type.encode(bytes); // param2
        self.nonce.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChallengeRequestPayload> {
        let slot_id = u8::read(r)?;
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?;
        let nonce = SpdmNonceStruct::read(r)?;

        Some(SpdmChallengeRequestPayload {
            slot_id,
            measurement_summary_hash_type,
            nonce,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmChallengeAuthAttribute: u8 {
        const BASIC_MUT_AUTH_REQ = 0b10000000;
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmChallengeAuthResponsePayload {
    pub slot_id: u8,
    pub slot_mask: u8,
    pub challenge_auth_attribute: SpdmChallengeAuthAttribute,
    pub cert_chain_hash: SpdmDigestStruct,
    pub nonce: SpdmNonceStruct,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
}

impl SpdmCodec for SpdmChallengeAuthResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        let param1 = self.slot_id + self.challenge_auth_attribute.bits();
        param1.encode(bytes);
        self.slot_mask.encode(bytes); // param2
        self.cert_chain_hash.spdm_encode(context, bytes);
        self.nonce.encode(bytes);
        if context.runtime_info.need_measurement_summary_hash {
            self.measurement_summary_hash.spdm_encode(context, bytes);
        }
        self.opaque.spdm_encode(context, bytes);
        self.signature.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmChallengeAuthResponsePayload> {
        let param1 = u8::read(r)?;
        let slot_id = param1 & 0xF;
        let challenge_auth_attribute = SpdmChallengeAuthAttribute::from_bits(param1 & 0xF0)?;
        let slot_mask = u8::read(r)?; // param2
        let cert_chain_hash = SpdmDigestStruct::spdm_read(context, r)?;
        let nonce = SpdmNonceStruct::read(r)?;
        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = SpdmSignatureStruct::spdm_read(context, r)?;

        Some(SpdmChallengeAuthResponsePayload {
            slot_id,
            slot_mask,
            challenge_auth_attribute,
            cert_chain_hash,
            nonce,
            measurement_summary_hash,
            opaque,
            signature,
        })
    }
}
