// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::protocol::{gen_array_clone, SpdmDigestStruct, SPDM_MAX_SLOT_NUMBER};
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone, Default)]
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

        let mut digests = gen_array_clone(SpdmDigestStruct::default(), SPDM_MAX_SLOT_NUMBER);
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

#[cfg(all(test,))]
#[path = "mod_test.common.inc.rs"]
mod testlib;

#[cfg(all(test,))]
mod tests {
    use super::*;
    use crate::common::{SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
    use crate::protocol::*;
    use testlib::{create_spdm_context, DeviceIO, TransportEncap};

    #[test]
    fn test_case0_spdm_digests_response_payload() {
        let u8_slice = &mut [0u8; 514];
        let mut writer = Writer::init(u8_slice);

        let mut value = SpdmDigestsResponsePayload {
            slot_mask: 0b11111111,
            slot_count: 8,
            digests: gen_array_clone(
                SpdmDigestStruct {
                    data_size: 64,
                    data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
                },
                SPDM_MAX_SLOT_NUMBER,
            ),
        };
        for i in 0..8 {
            for j in 0..64 {
                value.digests[i].data[j] = (i * j) as u8;
            }
        }

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(514, reader.left());
        let spdm_digests_response_payload =
            SpdmDigestsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_digests_response_payload.slot_mask, 0b11111111);
        assert_eq!(spdm_digests_response_payload.slot_count, 8);
        for i in 0..8 {
            for j in 0..64 {
                assert_eq!(spdm_digests_response_payload.digests[i].data_size, 64u16);
                assert_eq!(
                    spdm_digests_response_payload.digests[i].data[j],
                    (i * j) as u8
                );
            }
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    #[should_panic]
    fn test_case1_spdm_digests_response_payload() {
        let u8_slice = &mut [0u8; 10];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmDigestsResponsePayload::default();
        value.slot_mask = 0b00000000;
        value.slot_count = 0;
        value.digests = gen_array_clone(SpdmDigestStruct::default(), SPDM_MAX_SLOT_NUMBER);

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        SpdmDigestsResponsePayload::spdm_read(&mut context, &mut reader).unwrap();

        let u8_slice = &mut [0u8; 10];
        let mut writer = Writer::init(u8_slice);
        let mut value = SpdmDigestsResponsePayload::default();
        value.slot_mask = 0b00011111;
        value.slot_count = 3;
        value.digests = gen_array_clone(SpdmDigestStruct::default(), SPDM_MAX_SLOT_NUMBER);

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        value.spdm_encode(&mut context, &mut writer);
    }
    #[test]
    fn test_case0_spdm_get_digests_request_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmGetDigestsRequestPayload {};

        create_spdm_context!(context);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        SpdmGetDigestsRequestPayload::spdm_read(&mut context, &mut reader);
    }
}
