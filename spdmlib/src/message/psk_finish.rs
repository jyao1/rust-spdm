// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::algo::SpdmDigestStruct;
use crate::common::spdm_codec::SpdmCodec;
use codec::{Codec, Reader, Writer};

#[derive(Debug, Clone, Default)]
pub struct SpdmPskFinishRequestPayload {
    pub verify_data: SpdmDigestStruct,
}

impl SpdmCodec for SpdmPskFinishRequestPayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
        self.verify_data.spdm_encode(context, bytes);
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskFinishRequestPayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2
        let verify_data = SpdmDigestStruct::spdm_read(context, r)?;

        Some(SpdmPskFinishRequestPayload { verify_data })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmPskFinishResponsePayload {}

impl SpdmCodec for SpdmPskFinishResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // param1
        0u8.encode(bytes); // param2
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmPskFinishResponsePayload> {
        u8::read(r)?; // param1
        u8::read(r)?; // param2

        Some(SpdmPskFinishResponsePayload {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_key_exchange_request_payload() {
        let u8_slice = &mut [0u8; 80];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskFinishRequestPayload {
            verify_data: SpdmDigestStruct {
                data_size: 64,
                data: Box::new([100u8; common::algo::SPDM_MAX_HASH_SIZE]),
            },
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = common::algo::SpdmBaseHashAlgo::TPM_ALG_SHA_512;

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(80, reader.left());
        let psk_finish_request =
            SpdmPskFinishRequestPayload::spdm_read(&mut context, &mut reader).unwrap();

        assert_eq!(psk_finish_request.verify_data.data_size, 64);
        for i in 0..64 {
            assert_eq!(psk_finish_request.verify_data.data[i], 100u8);
        }
        assert_eq!(14, reader.left());
    }
    #[test]
    fn test_case0_spdm_psk_finish_response_payload() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmPskFinishResponsePayload {};
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        SpdmPskFinishResponsePayload::spdm_read(&mut context, &mut reader);
    }
}
