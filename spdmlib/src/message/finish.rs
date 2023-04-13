// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use crate::error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL};
use crate::protocol::{
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
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmFinishRequestAttributes> {
        let bits = u8::read(r)?;

        SpdmFinishRequestAttributes::from_bits(bits)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmFinishRequestPayload {
    pub finish_request_attributes: SpdmFinishRequestAttributes,
    pub req_slot_id: u8,
    pub signature: SpdmSignatureStruct,
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmFinishRequestPayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .finish_request_attributes
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += self
            .req_slot_id
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        if self
            .finish_request_attributes
            .contains(SpdmFinishRequestAttributes::SIGNATURE_INCLUDED)
        {
            cnt += self.signature.spdm_encode(context, bytes)?;
        }
        cnt += self.verify_data.spdm_encode(context, bytes)?;
        Ok(cnt)
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

#[derive(Debug, Clone, Default)]
pub struct SpdmFinishResponsePayload {
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmFinishResponsePayload {
    fn spdm_encode(
        &self,
        context: &mut common::SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param1
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // param2
        let in_clear_text = context
            .negotiate_info
            .req_capabilities_sel
            .contains(SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP)
            && context
                .negotiate_info
                .rsp_capabilities_sel
                .contains(SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP);
        if in_clear_text {
            cnt += self.verify_data.spdm_encode(context, bytes)?;
        }
        Ok(cnt)
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
    fn test_case0_spdm_finish_request_payload() {
        let u8_slice = &mut [0u8; 680];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmFinishRequestPayload {
            finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
            req_slot_id: 100,
            signature: SpdmSignatureStruct {
                data_size: 512,
                data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(680, reader.left());
        let spdm_finish_request_payload =
            SpdmFinishRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_finish_request_payload.finish_request_attributes,
            SpdmFinishRequestAttributes::SIGNATURE_INCLUDED
        );
        assert_eq!(spdm_finish_request_payload.req_slot_id, 100);
        assert_eq!(spdm_finish_request_payload.signature.data_size, 512);
        for i in 0..512 {
            assert_eq!(spdm_finish_request_payload.signature.data[i], 0xa5u8);
        }
        assert_eq!(spdm_finish_request_payload.verify_data.data_size, 64);
        for i in 0..64 {
            assert_eq!(spdm_finish_request_payload.verify_data.data[i], 0x5au8);
        }
    }
    #[test]
    fn test_case1_spdm_finish_request_payload() {
        let u8_slice = &mut [0u8; 680];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmFinishRequestPayload {
            finish_request_attributes: SpdmFinishRequestAttributes::empty(),
            req_slot_id: 100,
            signature: SpdmSignatureStruct {
                data_size: 512,
                data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
            },
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: Box::new([0x5au8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(680, reader.left());
        let spdm_finish_request_payload =
            SpdmFinishRequestPayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(
            spdm_finish_request_payload.finish_request_attributes,
            SpdmFinishRequestAttributes::empty()
        );
        assert_eq!(spdm_finish_request_payload.req_slot_id, 100);
        assert_eq!(spdm_finish_request_payload.signature.data_size, 0);
        for i in 0..512 {
            assert_eq!(spdm_finish_request_payload.signature.data[i], 0);
        }
    }
    #[test]
    fn test_case0_spdm_finish_response_payload() {
        let u8_slice = &mut [0u8; 68];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmFinishResponsePayload {
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(68, reader.left());
        let spdm_read = SpdmFinishResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_read.verify_data.data_size, 64);
        for i in 0..64 {
            assert_eq!(spdm_read.verify_data.data[i], 100u8);
        }
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case1_spdm_finish_response_payload() {
        let u8_slice = &mut [0u8; 68];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmFinishResponsePayload {
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
            },
        };

        create_spdm_context!(context);

        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::KEY_UPD_CAP;

        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(68, reader.left());
        let spdm_read = SpdmFinishResponsePayload::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_read.verify_data.data_size, 0);
        for i in 0..64 {
            assert_eq!(spdm_read.verify_data.data[i], 0);
        }
        assert_eq!(66, reader.left());
    }
}

#[cfg(all(test,))]
#[path = "finish_test.rs"]
mod finish_test;
