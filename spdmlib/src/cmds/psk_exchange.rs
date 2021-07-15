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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::msgs::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_key_exchange_request_payload() {
        let u8_slice = &mut [0u8; 180];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            req_session_id: 100u16,
            psk_hint: SpdmPskHintStruct {
                data_size: 32,
                data: [100u8; MAX_SPDM_PSK_HINT_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
        };

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
        assert_eq!(180, reader.left());
        let psk_exchange_request =
            SpdmPskExchangeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            psk_exchange_request.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
        );
        assert_eq!(psk_exchange_request.psk_hint.data_size, 32);
        assert_eq!(psk_exchange_request.psk_context.data_size, 64);
        assert_eq!(psk_exchange_request.opaque.data_size, 64);
        for i in 0..32 {
            assert_eq!(psk_exchange_request.psk_hint.data[i], 100);
        }
        for i in 0..64 {
            assert_eq!(psk_exchange_request.psk_context.data[i], 100);
            assert_eq!(psk_exchange_request.opaque.data[i], 100);
        }
        assert_eq!(10, reader.left());

    }
    #[test]
    fn test_case0_spdm_psk_exchange_response_payload() {
        let u8_slice = &mut [0u8; 280];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskExchangeResponsePayload {
            heartbeat_period: 0xaau8,
            rsp_session_id: 0xaa55u16,
            measurement_summary_hash: SpdmDigestStruct {
                data_size: 64,
                data: [100u8; SPDM_MAX_HASH_SIZE],
            },
            psk_context: SpdmPskContextStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_PSK_CONTEXT_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 64,
                data: [100u8; MAX_SPDM_OPAQUE_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: [100u8; SPDM_MAX_HASH_SIZE],
            },
        };

        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = common::SpdmContext::new(
            my_spdm_device_io,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_summary_hash = true;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(280, reader.left());
        let psk_exchange_response =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_exchange_response.heartbeat_period, 0xaau8);
        assert_eq!(psk_exchange_response.rsp_session_id, 0xaa55u16);

        assert_eq!(psk_exchange_response.measurement_summary_hash.data_size, 64);
        assert_eq!(psk_exchange_response.psk_context.data_size, 64);
        assert_eq!(psk_exchange_response.opaque.data_size, 64);
        assert_eq!(psk_exchange_response.verify_data.data_size, 64);

        for i in 0..64 {
            assert_eq!(psk_exchange_response.measurement_summary_hash.data[i], 100);
            assert_eq!(psk_exchange_response.psk_context.data[i], 100);
            assert_eq!(psk_exchange_response.opaque.data[i], 100);
            assert_eq!(psk_exchange_response.verify_data.data[i], 100u8);
        }
        assert_eq!(14, reader.left());

        let u8_slice = &mut [0u8; 420];
        let mut writer = Writer::init(u8_slice);

        context.runtime_info.need_measurement_summary_hash = false;
        
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(420, reader.left());
        let psk_exchange_response =
            SpdmPskExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_exchange_response.measurement_summary_hash.data_size, 0);
        for i in 0..64 {
            assert_eq!(psk_exchange_response.measurement_summary_hash.data[i], 0);
        }
        assert_eq!(218, reader.left());

    }
}
