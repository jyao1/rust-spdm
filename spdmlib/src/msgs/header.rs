// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::enum_builder;
use codec::{Codec, Reader, Writer};

enum_builder! {
    @U8
    EnumName: SpdmVersion;
    EnumVal{
        SpdmVersion10 => 0x10,
        SpdmVersion11 => 0x11
    }
}

enum_builder! {
    @U8
    EnumName: SpdmResponseResponseCode;
    EnumVal{
        // 1.0 response
        SpdmResponseDigests => 0x01,
        SpdmResponseCertificate => 0x02,
        SpdmResponseChallengeAuth => 0x03,
        SpdmResponseVersion => 0x04,
        SpdmResponseMeasurements => 0x60,
        SpdmResponseCapabilities => 0x61,
        SpdmResponseAlgorithms => 0x63,
        //SpdmResponseVendorDefinedResponse => 0x7E,
        SpdmResponseError => 0x7F,
        // 1.1 response
        SpdmResponseKeyExchangeRsp => 0x64,
        SpdmResponseFinishRsp => 0x65,
        SpdmResponsePskExchangeRsp => 0x66,
        SpdmResponsePskFinishRsp => 0x67,
        SpdmResponseHeartbeatAck => 0x68,
        SpdmResponseKeyUpdateAck => 0x69,
//        SpdmResponseEncapsulatedRequest => 0x6A,
//        SpdmResponseEncapsulatedResponseAck => 0x6B,
        SpdmResponseEndSessionAck => 0x6C,

        // 1.0 rerquest
        SpdmRequestGetDigests => 0x81,
        SpdmRequestGetCertificate => 0x82,
        SpdmRequestChallenge => 0x83,
        SpdmRequestGetVersion => 0x84,
        SpdmRequestGetMeasurements => 0xE0,
        SpdmRequestGetCapabilities => 0xE1,
        SpdmRequestNegotiateAlgorithms => 0xE3,
        SpdmRequestVendorDefinedRequest => 0xFE,
//        SpdmRequestResponseIfReady => 0xFF,
        // 1.1 request
        SpdmRequestKeyExchange => 0xE4,
        SpdmRequestFinish => 0xE5,
        SpdmRequestPskExchange => 0xE6,
        SpdmRequestPskFinish => 0xE7,
        SpdmRequestHeartbeat => 0xE8,
        SpdmRequestKeyUpdate => 0xE9,
//        SpdmRequestGetEncapsulatedRequest => 0xEA,
//        SpdmRequestDeliverEncapsulatedResponse => 0xEB,
        SpdmRequestEndSession => 0xEC
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmMessageHeader {
    pub version: SpdmVersion,
    pub request_response_code: SpdmResponseResponseCode,
}

impl Codec for SpdmMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.version.encode(bytes);
        self.request_response_code.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmMessageHeader> {
        let version = SpdmVersion::read(r)?;
        let request_response_code = SpdmResponseResponseCode::read(r)?;
        Some(SpdmMessageHeader {
            version,
            request_response_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_spdm_message_header() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmResponseResponseCode::SpdmRequestChallenge
        );
    }
}
