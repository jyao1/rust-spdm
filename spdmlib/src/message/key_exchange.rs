// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::algo::{
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmMeasurementSummaryHashType, SpdmRandomStruct,
    SpdmSignatureStruct,
};
use crate::common::opaque::SpdmOpaqueStruct;
use crate::common::spdm_codec::SpdmCodec;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_key_exchange_mut_auth_attributes() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ;
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmKeyExchangeMutAuthAttributes::read(&mut reader).unwrap(),
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_key_exchange_request_payload() {
        let u8_slice = &mut [0u8; 680];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeRequestPayload {
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            slot_id: 100u8,
            req_session_id: 100u16,
            random: SpdmRandomStruct {
                data: [100u8; common::algo::SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: 512u16,
                data: [100u8; common::algo::SPDM_MAX_DHE_KEY_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 64u16,
                data: [100u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
            },
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = common::algo::SpdmDheAlgo::FFDHE_4096;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(680, reader.left());
        let exchange_request_payload =
            SpdmKeyExchangeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(
            exchange_request_payload.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        assert_eq!(exchange_request_payload.slot_id, 100);
        for i in 0..32 {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }
        assert_eq!(exchange_request_payload.exchange.data_size, 512);
        for i in 0..512 {
            assert_eq!(exchange_request_payload.exchange.data[i], 100);
        }
        assert_eq!(exchange_request_payload.opaque.data_size, 64);
        for i in 0..64 {
            assert_eq!(exchange_request_payload.opaque.data[i], 100);
        }
    }

    #[test]
    fn test_case0_spdm_key_exchange_response_payload() {
        let u8_slice = &mut [0u8; 1256];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeResponsePayload {
            heartbeat_period: 100u8,
            rsp_session_id: 100u16,
            mut_auth_req: SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
            req_slot_id: 100u8,
            random: SpdmRandomStruct {
                data: [100u8; common::algo::SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: 512u16,
                data: [0xa5u8; common::algo::SPDM_MAX_DHE_KEY_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct {
                data_size: 64u16,
                data: [0x11u8; common::algo::SPDM_MAX_HASH_SIZE],
            },
            opaque: SpdmOpaqueStruct {
                data_size: 64u16,
                data: [0x22u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: 512u16,
                data: [0x5au8; common::algo::SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 64u16,
                data: [0x33u8; common::algo::SPDM_MAX_HASH_SIZE],
            },
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = common::algo::SpdmDheAlgo::FFDHE_4096;
        context.negotiate_info.base_hash_sel = common::algo::SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.base_asym_sel = common::algo::SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        context.runtime_info.need_measurement_summary_hash = true;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(1256, reader.left());
        let exchange_request_payload =
            SpdmKeyExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(exchange_request_payload.heartbeat_period, 100);
        assert_eq!(exchange_request_payload.rsp_session_id, 100);
        assert_eq!(
            exchange_request_payload.mut_auth_req,
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(exchange_request_payload.req_slot_id, 100);
        for i in 0..32 {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }

        assert_eq!(exchange_request_payload.exchange.data_size, 512);
        assert_eq!(exchange_request_payload.signature.data_size, 512);
        for i in 0..512 {
            assert_eq!(exchange_request_payload.exchange.data[i], 0xa5);
            assert_eq!(exchange_request_payload.signature.data[i], 0x5a);
        }

        assert_eq!(
            exchange_request_payload.measurement_summary_hash.data_size,
            64
        );
        assert_eq!(exchange_request_payload.verify_data.data_size, 64);
        assert_eq!(exchange_request_payload.opaque.data_size, 64);
        for i in 0..64 {
            assert_eq!(
                exchange_request_payload.measurement_summary_hash.data[i],
                0x11
            );
            assert_eq!(exchange_request_payload.opaque.data[i], 0x22);
            assert_eq!(exchange_request_payload.verify_data.data[i], 0x33);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_key_exchange_response_payload() {
        let u8_slice = &mut [0u8; 1256];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyExchangeResponsePayload {
            heartbeat_period: 100u8,
            rsp_session_id: 100u16,
            mut_auth_req: SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
            req_slot_id: 100u8,
            random: SpdmRandomStruct {
                data: [100u8; common::algo::SPDM_RANDOM_SIZE],
            },
            exchange: SpdmDheExchangeStruct {
                data_size: 512u16,
                data: [0xa5u8; common::algo::SPDM_MAX_DHE_KEY_SIZE],
            },
            measurement_summary_hash: SpdmDigestStruct::default(),
            opaque: SpdmOpaqueStruct {
                data_size: 64u16,
                data: [0x22u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
            },
            signature: SpdmSignatureStruct {
                data_size: 512u16,
                data: [0x5au8; common::algo::SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 64u16,
                data: [0x33u8; common::algo::SPDM_MAX_HASH_SIZE],
            },
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = common::algo::SpdmDheAlgo::FFDHE_4096;
        context.negotiate_info.base_hash_sel = common::algo::SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.base_asym_sel = common::algo::SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        context.runtime_info.need_measurement_summary_hash = false;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(1256, reader.left());
        let exchange_request_payload =
            SpdmKeyExchangeResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(exchange_request_payload.heartbeat_period, 100);
        assert_eq!(exchange_request_payload.rsp_session_id, 100);
        assert_eq!(
            exchange_request_payload.mut_auth_req,
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ
        );
        assert_eq!(exchange_request_payload.req_slot_id, 100);
        for i in 0..32 {
            assert_eq!(exchange_request_payload.random.data[i], 100);
        }

        assert_eq!(exchange_request_payload.exchange.data_size, 512);
        assert_eq!(exchange_request_payload.signature.data_size, 512);
        for i in 0..512 {
            assert_eq!(exchange_request_payload.exchange.data[i], 0xa5);
            assert_eq!(exchange_request_payload.signature.data[i], 0x5a);
        }

        assert_eq!(
            exchange_request_payload.measurement_summary_hash.data_size,
            0
        );
        assert_eq!(exchange_request_payload.verify_data.data_size, 64);
        assert_eq!(exchange_request_payload.opaque.data_size, 64);
        for i in 0..64 {
            assert_eq!(exchange_request_payload.measurement_summary_hash.data[i], 0);
            assert_eq!(exchange_request_payload.opaque.data[i], 0x22);
            assert_eq!(exchange_request_payload.verify_data.data[i], 0x33);
        }
        assert_eq!(64, reader.left());
    }
}
