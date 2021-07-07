// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;
    use crate::msgs::*;

    #[test]
    fn test_case0_spdm_challenge_request_payload() {
        let u8_slice = &mut [0u8; 34];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmChallengeRequestPayload {
            slot_id: 100,
            measurement_summary_hash_type:
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
            nonce: SpdmNonceStruct { data: [100u8; 32] },
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
        assert_eq!(34, reader.left());
        let spdm_challenge_request_payload =
            SpdmChallengeRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_challenge_request_payload.slot_id, 100);
        assert_eq!(
            spdm_challenge_request_payload.measurement_summary_hash_type,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
        );
        for i in 0..32 {
            assert_eq!(spdm_challenge_request_payload.nonce.data[i], 100u8);
        }
        assert_eq!(0, reader.left());
    }
}
