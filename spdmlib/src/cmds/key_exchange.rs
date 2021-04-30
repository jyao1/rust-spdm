// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmOpaqueStruct,
    SpdmRandomStruct, SpdmSignatureStruct,
};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmKeyExchangeRequestPayload {
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub slot_id: u8,
    pub req_session_id: u16,
    pub random: SpdmRandomStruct,
    pub exchange: SpdmDheExchangeStruct,
    pub opaque: SpdmOpaqueStruct,
}

impl SpdmCodec for SpdmKeyExchangeRequestPayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.measurement_summary_hash_type.encode(bytes); // param1
        self.slot_id.encode(bytes); // param2
        self.req_session_id.encode(bytes);
        0u16.encode(bytes); // reserved

        self.random.encode(bytes);
        self.exchange.spdm_encode(context, bytes);
        self.opaque.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyExchangeRequestPayload> {
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?; // param1
        let slot_id = u8::read(r)?; // param2
        let req_session_id = u16::read(r)?;
        u16::read(r)?;

        let random = SpdmRandomStruct::read(r)?;
        let exchange = SpdmDheExchangeStruct::spdm_read(context, r)?;
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;

        Some(SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type,
            slot_id,
            req_session_id,
            random,
            exchange,
            opaque,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmKeyExchangeMutAuthAttributes: u8 {
        const MUT_AUTH_REQ = 0b00000001;
        const MUT_AUTH_REQ_WITH_ENCAP_REQUEST = 0b00000010;
        const MUT_AUTH_REQ_WITH_GET_DIGESTS = 0b00000100;
    }
}

impl Codec for SpdmKeyExchangeMutAuthAttributes {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmKeyExchangeMutAuthAttributes> {
        let bits = u8::read(r)?;

        SpdmKeyExchangeMutAuthAttributes::from_bits(bits)
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmKeyExchangeResponsePayload {
    pub heartbeat_period: u8,
    pub rsp_session_id: u16,
    pub mut_auth_req: SpdmKeyExchangeMutAuthAttributes,
    pub req_slot_id: u8,
    pub random: SpdmRandomStruct,
    pub exchange: SpdmDheExchangeStruct,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub opaque: SpdmOpaqueStruct,
    pub signature: SpdmSignatureStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmKeyExchangeResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.heartbeat_period.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.rsp_session_id.encode(bytes);
        self.mut_auth_req.encode(bytes);
        self.req_slot_id.encode(bytes);

        self.random.encode(bytes);
        self.exchange.spdm_encode(context, bytes);
        if context.runtime_info.need_measurement_summary_hash {
            self.measurement_summary_hash.spdm_encode(context, bytes);
        }
        self.opaque.spdm_encode(context, bytes);
        self.signature.spdm_encode(context, bytes);
        self.verify_data.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmKeyExchangeResponsePayload> {
        let heartbeat_period = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let rsp_session_id = u16::read(r)?; // reserved
        let mut_auth_req = SpdmKeyExchangeMutAuthAttributes::read(r)?;
        let req_slot_id = u8::read(r)?;
        let random = SpdmRandomStruct::read(r)?;
        let exchange = SpdmDheExchangeStruct::spdm_read(context, r)?;
        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };
        let opaque = SpdmOpaqueStruct::spdm_read(context, r)?;
        let signature = SpdmSignatureStruct::spdm_read(context, r)?;
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmKeyExchangeResponsePayload {
            heartbeat_period,
            rsp_session_id,
            mut_auth_req,
            req_slot_id,
            random,
            exchange,
            measurement_summary_hash,
            opaque,
            signature,
            verify_data,
        })
    }
}
