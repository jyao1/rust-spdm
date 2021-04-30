// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::msgs::SpdmCodec;
use crate::msgs::{
    SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmOpaqueStruct, SpdmPskContextStruct,
    SpdmPskHintStruct,
};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmPskExchangeRequestPayload {
    pub measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    pub req_session_id: u16,
    pub psk_hint: SpdmPskHintStruct,
    pub psk_context: SpdmPskContextStruct,
    pub opaque: SpdmOpaqueStruct,
}

impl SpdmCodec for SpdmPskExchangeRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.measurement_summary_hash_type.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.req_session_id.encode(bytes);

        self.psk_hint.data_size.encode(bytes);
        self.psk_context.data_size.encode(bytes);
        self.opaque.data_size.encode(bytes);

        for d in self
            .psk_hint
            .data
            .iter()
            .take(self.psk_hint.data_size as usize)
        {
            d.encode(bytes);
        }
        for d in self
            .psk_context
            .data
            .iter()
            .take(self.psk_context.data_size as usize)
        {
            d.encode(bytes);
        }
        for d in self.opaque.data.iter().take(self.opaque.data_size as usize) {
            d.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskExchangeRequestPayload> {
        let measurement_summary_hash_type = SpdmMeasurementSummaryHashType::read(r)?; // param1
        u8::read(r)?; // param2
        let req_session_id = u16::read(r)?;

        let mut psk_hint = SpdmPskHintStruct::default();
        let mut psk_context = SpdmPskContextStruct::default();
        let mut opaque = SpdmOpaqueStruct::default();

        psk_hint.data_size = u16::read(r)?;
        psk_context.data_size = u16::read(r)?;
        opaque.data_size = u16::read(r)?;

        for d in psk_hint.data.iter_mut().take(psk_hint.data_size as usize) {
            *d = u8::read(r)?;
        }
        for d in psk_context
            .data
            .iter_mut()
            .take(psk_context.data_size as usize)
        {
            *d = u8::read(r)?;
        }
        for d in opaque.data.iter_mut().take(opaque.data_size as usize) {
            *d = u8::read(r)?;
        }

        Some(SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type,
            req_session_id,
            psk_hint,
            psk_context,
            opaque,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmPskExchangeResponsePayload {
    pub heartbeat_period: u8,
    pub rsp_session_id: u16,
    pub measurement_summary_hash: SpdmDigestStruct,
    pub psk_context: SpdmPskContextStruct,
    pub opaque: SpdmOpaqueStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmPskExchangeResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.heartbeat_period.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.rsp_session_id.encode(bytes);
        0u16.encode(bytes);

        self.psk_context.data_size.encode(bytes);
        self.opaque.data_size.encode(bytes);

        if context.runtime_info.need_measurement_summary_hash {
            self.measurement_summary_hash.spdm_encode(context, bytes);
        }
        for d in self
            .psk_context
            .data
            .iter()
            .take(self.psk_context.data_size as usize)
        {
            d.encode(bytes);
        }
        for d in self.opaque.data.iter().take(self.opaque.data_size as usize) {
            d.encode(bytes);
        }
        self.verify_data.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskExchangeResponsePayload> {
        let heartbeat_period = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let rsp_session_id = u16::read(r)?; // reserved
        u16::read(r)?;

        let mut psk_context = SpdmPskContextStruct::default();
        let mut opaque = SpdmOpaqueStruct::default();

        psk_context.data_size = u16::read(r)?;
        opaque.data_size = u16::read(r)?;

        let measurement_summary_hash = if context.runtime_info.need_measurement_summary_hash {
            SpdmDigestStruct::spdm_read(context, r)?
        } else {
            SpdmDigestStruct::default()
        };

        for d in psk_context
            .data
            .iter_mut()
            .take(psk_context.data_size as usize)
        {
            *d = u8::read(r)?;
        }
        for d in opaque.data.iter_mut().take(opaque.data_size as usize) {
            *d = u8::read(r)?;
        }
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmPskExchangeResponsePayload {
            heartbeat_period,
            rsp_session_id,
            measurement_summary_hash,
            psk_context,
            opaque,
            verify_data,
        })
    }
}
