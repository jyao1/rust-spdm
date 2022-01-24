// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::enum_builder;
use codec::{Codec, Reader, Writer};

// SPDM 1.0
pub mod algorithm;
pub mod capability;
pub mod certificate;
pub mod challenge;
pub mod digest;
pub mod error;
pub mod measurement;
pub mod vendor;
pub mod version;

// SPDM 1.1
pub mod end_session;
pub mod finish;
pub mod heartbeat;
pub mod key_exchange;
pub mod key_update;
pub mod psk_exchange;
pub mod psk_finish;

pub use algorithm::*;
pub use capability::*;
pub use certificate::*;
pub use challenge::*;
pub use digest::*;
pub use end_session::*;
pub use error::*;
pub use finish::*;
pub use heartbeat::*;
pub use key_exchange::*;
pub use key_update::*;
pub use measurement::*;
pub use psk_exchange::*;
pub use psk_finish::*;
pub use version::*;
// Add new SPDM command here.
pub use vendor::*;

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
    EnumName: SpdmRequestResponseCode;
    EnumVal{
        // 1.0 response
        SpdmResponseDigests => 0x01,
        SpdmResponseCertificate => 0x02,
        SpdmResponseChallengeAuth => 0x03,
        SpdmResponseVersion => 0x04,
        SpdmResponseMeasurements => 0x60,
        SpdmResponseCapabilities => 0x61,
        SpdmResponseAlgorithms => 0x63,
        SpdmResponseVendorDefinedResponse => 0x7E,
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

#[derive(Debug, Clone, Default)]
pub struct SpdmMessageHeader {
    pub version: SpdmVersion,
    pub request_response_code: SpdmRequestResponseCode,
}

impl Codec for SpdmMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.version.encode(bytes);
        self.request_response_code.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmMessageHeader> {
        let version = SpdmVersion::read(r)?;
        let request_response_code = SpdmRequestResponseCode::read(r)?;
        Some(SpdmMessageHeader {
            version,
            request_response_code,
        })
    }
}

#[derive(Debug)]
pub struct SpdmMessage {
    pub header: SpdmMessageHeader,
    pub payload: SpdmMessagePayload,
}

//
// we have to define big payload to hold the possible data from responder,
// such as, cert_chain, measurement_record, etc.
//
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SpdmMessagePayload {
    SpdmGetVersionRequest(SpdmGetVersionRequestPayload),
    SpdmVersionResponse(SpdmVersionResponsePayload),

    SpdmGetCapabilitiesRequest(SpdmGetCapabilitiesRequestPayload),
    SpdmCapabilitiesResponse(SpdmCapabilitiesResponsePayload),

    SpdmNegotiateAlgorithmsRequest(SpdmNegotiateAlgorithmsRequestPayload),
    SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload),

    SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload),
    SpdmDigestsResponse(SpdmDigestsResponsePayload),

    SpdmGetCertificateRequest(SpdmGetCertificateRequestPayload),
    SpdmCertificateResponse(SpdmCertificateResponsePayload),

    SpdmChallengeRequest(SpdmChallengeRequestPayload),
    SpdmChallengeAuthResponse(SpdmChallengeAuthResponsePayload),

    SpdmGetMeasurementsRequest(SpdmGetMeasurementsRequestPayload),
    SpdmMeasurementsResponse(SpdmMeasurementsResponsePayload),

    SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload),
    SpdmKeyExchangeResponse(SpdmKeyExchangeResponsePayload),

    SpdmFinishRequest(SpdmFinishRequestPayload),
    SpdmFinishResponse(SpdmFinishResponsePayload),

    SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload),
    SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload),

    SpdmPskFinishRequest(SpdmPskFinishRequestPayload),
    SpdmPskFinishResponse(SpdmPskFinishResponsePayload),

    SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload),
    SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload),

    SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload),
    SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload),

    SpdmEndSessionRequest(SpdmEndSessionRequestPayload),
    SpdmEndSessionResponse(SpdmEndSessionResponsePayload),

    // Add new SPDM command here.
    SpdmErrorResponse(SpdmErrorResponsePayload),
    SpdmVendorDefinedRequest(SpdmVendorDefinedRequestPayload),
    SpdmVendorDefinedResponse(SpdmVendorDefinedResponsePayload),
}

impl SpdmMessage {
    pub fn read_with_detailed_error(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMessage> {
        let header = SpdmMessageHeader::read(r)?;

        let payload = match header.request_response_code {
            SpdmRequestResponseCode::SpdmResponseVersion => {
                Some(SpdmMessagePayload::SpdmVersionResponse(
                    SpdmVersionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetVersion => {
                Some(SpdmMessagePayload::SpdmGetVersionRequest(
                    SpdmGetVersionRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseCapabilities => {
                Some(SpdmMessagePayload::SpdmCapabilitiesResponse(
                    SpdmCapabilitiesResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetCapabilities => {
                Some(SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                    SpdmGetCapabilitiesRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseAlgorithms => {
                Some(SpdmMessagePayload::SpdmAlgorithmsResponse(
                    SpdmAlgorithmsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms => {
                Some(SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                    SpdmNegotiateAlgorithmsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseDigests => {
                Some(SpdmMessagePayload::SpdmDigestsResponse(
                    SpdmDigestsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetDigests => {
                Some(SpdmMessagePayload::SpdmGetDigestsRequest(
                    SpdmGetDigestsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseCertificate => {
                Some(SpdmMessagePayload::SpdmCertificateResponse(
                    SpdmCertificateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetCertificate => {
                Some(SpdmMessagePayload::SpdmGetCertificateRequest(
                    SpdmGetCertificateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseChallengeAuth => {
                Some(SpdmMessagePayload::SpdmChallengeAuthResponse(
                    SpdmChallengeAuthResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestChallenge => {
                Some(SpdmMessagePayload::SpdmChallengeRequest(
                    SpdmChallengeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseMeasurements => {
                Some(SpdmMessagePayload::SpdmMeasurementsResponse(
                    SpdmMeasurementsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestGetMeasurements => {
                Some(SpdmMessagePayload::SpdmGetMeasurementsRequest(
                    SpdmGetMeasurementsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseKeyExchangeRsp => {
                Some(SpdmMessagePayload::SpdmKeyExchangeResponse(
                    SpdmKeyExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestKeyExchange => {
                Some(SpdmMessagePayload::SpdmKeyExchangeRequest(
                    SpdmKeyExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseFinishRsp => {
                Some(SpdmMessagePayload::SpdmFinishResponse(
                    SpdmFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestFinish => {
                Some(SpdmMessagePayload::SpdmFinishRequest(
                    SpdmFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp => {
                Some(SpdmMessagePayload::SpdmPskExchangeResponse(
                    SpdmPskExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestPskExchange => {
                Some(SpdmMessagePayload::SpdmPskExchangeRequest(
                    SpdmPskExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponsePskFinishRsp => {
                Some(SpdmMessagePayload::SpdmPskFinishResponse(
                    SpdmPskFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestPskFinish => {
                Some(SpdmMessagePayload::SpdmPskFinishRequest(
                    SpdmPskFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseHeartbeatAck => {
                Some(SpdmMessagePayload::SpdmHeartbeatResponse(
                    SpdmHeartbeatResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestHeartbeat => {
                Some(SpdmMessagePayload::SpdmHeartbeatRequest(
                    SpdmHeartbeatRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck => {
                Some(SpdmMessagePayload::SpdmKeyUpdateResponse(
                    SpdmKeyUpdateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestKeyUpdate => {
                Some(SpdmMessagePayload::SpdmKeyUpdateRequest(
                    SpdmKeyUpdateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmRequestResponseCode::SpdmResponseEndSessionAck => {
                Some(SpdmMessagePayload::SpdmEndSessionResponse(
                    SpdmEndSessionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmRequestResponseCode::SpdmRequestEndSession => {
                Some(SpdmMessagePayload::SpdmEndSessionRequest(
                    SpdmEndSessionRequestPayload::spdm_read(context, r)?,
                ))
            }

            // Add new SPDM command here.
            SpdmRequestResponseCode::SpdmResponseError => {
                Some(SpdmMessagePayload::SpdmErrorResponse(
                    SpdmErrorResponsePayload::spdm_read(context, r)?,
                ))
            }

            _ => None,
        }?;

        Some(SpdmMessage { header, payload })
    }
}

impl SpdmCodec for SpdmMessage {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.header.encode(bytes);
        match &self.payload {
            SpdmMessagePayload::SpdmGetVersionRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmVersionResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmGetCapabilitiesRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmCapabilitiesResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmAlgorithmsResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmGetDigestsRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmDigestsResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmGetCertificateRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmCertificateResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmChallengeRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmChallengeAuthResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmGetMeasurementsRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmMeasurementsResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmKeyExchangeRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmKeyExchangeResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmFinishRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmFinishResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmPskExchangeRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmPskExchangeResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmPskFinishRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmPskFinishResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmEndSessionRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmEndSessionResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmHeartbeatRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmHeartbeatResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            SpdmMessagePayload::SpdmKeyUpdateRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmKeyUpdateResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }

            // Add new SPDM command here.
            SpdmMessagePayload::SpdmErrorResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmVendorDefinedRequest(payload) => {
                payload.spdm_encode(context, bytes);
            }
            SpdmMessagePayload::SpdmVendorDefinedResponse(payload) => {
                payload.spdm_encode(context, bytes);
            }
        }
    }

    fn spdm_read(context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmMessage> {
        SpdmMessage::read_with_detailed_error(context, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gen_array_clone;
    use crate::common::*;
    use crate::config;
    use crate::config::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_message_header() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );
    }

    #[test]
    fn test_case0_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVersion,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 0x02,
                versions: gen_array_clone(
                    SpdmVersionStruct {
                        update: 100,
                        version: SpdmVersion::SpdmVersion11,
                    },
                    config::MAX_SPDM_VERSION_COUNT,
                ),
            }),
        };

        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseVersion
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x02);
            for i in 0..2 {
                assert_eq!(payload.versions[i].update, 100);
                assert_eq!(payload.versions[i].version, SpdmVersion::SpdmVersion11);
            }
        }
    }
    #[test]
    fn test_case1_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: 0x02,
                    flags: SpdmRequestCapabilityFlags::CERT_CAP,
                },
            ),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCapabilities
        );
        if let SpdmMessagePayload::SpdmGetCapabilitiesRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x02);
            assert_eq!(payload.flags, SpdmRequestCapabilityFlags::CERT_CAP);
        }
    }
    #[test]
    fn test_case2_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCapabilities,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: 0x03,
                    flags: SpdmResponseCapabilityFlags::CACHE_CAP,
                },
            ),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCapabilities
        );
        if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x03);
            assert_eq!(payload.flags, SpdmResponseCapabilityFlags::CACHE_CAP);
        }
    }
    #[test]
    fn test_case3_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: SpdmMeasurementSpecification::DMTF,
                    base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                    base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    alg_struct_count: 4,
                    alg_struct: gen_array_clone(
                        SpdmAlgStruct {
                            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                            alg_fixed_count: 2,
                            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048),
                            alg_ext_count: 0,
                        },
                        config::MAX_SPDM_ALG_STRUCT_COUNT,
                    ),
                },
            ),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
        );
        if let SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.base_asym_algo,
                SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
            );
            assert_eq!(payload.base_hash_algo, SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count, 4);
            for i in 0..4 {
                assert_eq!(payload.alg_struct[i].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
                assert_eq!(payload.alg_struct[i].alg_fixed_count, 2);
                assert_eq!(
                    payload.alg_struct[1].alg_supported,
                    SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048)
                );
                assert_eq!(payload.alg_struct[i].alg_ext_count, 0);
            }
        }
    }
    #[test]
    fn test_case4_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseAlgorithms,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(SpdmAlgorithmsResponsePayload {
                measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
                measurement_hash_algo: SpdmMeasurementHashAlgo::RAW_BIT_STREAM,
                base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                alg_struct_count: 4,
                alg_struct: gen_array_clone(
                    SpdmAlgStruct {
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048),
                        alg_ext_count: 0,
                    },
                    MAX_SPDM_ALG_STRUCT_COUNT,
                ),
            }),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseAlgorithms
        );
        if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_specification_sel,
                SpdmMeasurementSpecification::DMTF
            );
            assert_eq!(
                payload.measurement_hash_algo,
                SpdmMeasurementHashAlgo::RAW_BIT_STREAM
            );
            assert_eq!(payload.base_asym_sel, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048);
            assert_eq!(payload.base_hash_sel, SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count, 4);
            for i in 0..4 {
                assert_eq!(payload.alg_struct[i].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
                assert_eq!(payload.alg_struct[i].alg_fixed_count, 2);
                assert_eq!(
                    payload.alg_struct[1].alg_supported,
                    SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048)
                );
                assert_eq!(payload.alg_struct[i].alg_ext_count, 0);
            }
        }
    }
    #[test]
    fn test_case5_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseCertificate,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(SpdmCertificateResponsePayload {
                slot_id: 100,
                portion_length: 512,
                remainder_length: 100,
                cert_chain: [100u8; MAX_SPDM_CERT_PORTION_LEN],
            }),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCertificate
        );
        if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.portion_length, 512);
            assert_eq!(payload.remainder_length, 100);
            for i in 0..512 {
                assert_eq!(payload.cert_chain[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case6_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(SpdmChallengeRequestPayload {
                slot_id: 100,
                measurement_summary_hash_type:
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                nonce: SpdmNonceStruct { data: [100u8; 32] },
            }),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );
        if let SpdmMessagePayload::SpdmChallengeRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
            );
            for i in 0..32 {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case7_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseChallengeAuth,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: 0x0f,
                    slot_mask: 100,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ,
                    cert_chain_hash: SpdmDigestStruct {
                        data_size: 64,
                        data: Box::new([0xAAu8; SPDM_MAX_HASH_SIZE]),
                    },
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    measurement_summary_hash: SpdmDigestStruct {
                        data_size: 64,
                        data: Box::new([0x55u8; SPDM_MAX_HASH_SIZE]),
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 64,
                        data: [0xAAu8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: 512,
                        data: [0x55u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.runtime_info.need_measurement_summary_hash = true;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseChallengeAuth
        );
        if let SpdmMessagePayload::SpdmChallengeAuthResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 0x0f);
            assert_eq!(payload.slot_mask, 100);
            assert_eq!(
                payload.challenge_auth_attribute,
                SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ
            );
            assert_eq!(payload.cert_chain_hash.data_size, 64);
            assert_eq!(payload.measurement_summary_hash.data_size, 64);
            assert_eq!(payload.opaque.data_size, 64);
            assert_eq!(payload.signature.data_size, 512);

            for i in 0..64 {
                assert_eq!(payload.cert_chain_hash.data[i], 0xAAu8);
                assert_eq!(payload.opaque.data[i], 0xAAu8);
                assert_eq!(payload.measurement_summary_hash.data[i], 0x55u8);
            }
            for i in 0..32 {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
            for i in 0..512 {
                assert_eq!(payload.signature.data[i], 0x55u8);
            }
        }
    }
    #[test]
    fn test_case8_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            },
            payload: SpdmMessagePayload::SpdmGetMeasurementsRequest(
                SpdmGetMeasurementsRequestPayload {
                    measurement_attributes: SpdmMeasurementeAttributes::INCLUDE_SIGNATURE,
                    measurement_operation:
                        SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    slot_id: 0xaau8,
                },
            ),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetMeasurements
        );
        if let SpdmMessagePayload::SpdmGetMeasurementsRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_attributes,
                SpdmMeasurementeAttributes::INCLUDE_SIGNATURE
            );
            assert_eq!(
                payload.measurement_operation,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            );
            assert_eq!(payload.slot_id, 0xaau8);
            for i in 0..32 {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case9_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseMeasurements,
            },
            payload: SpdmMessagePayload::SpdmMeasurementsResponse(
                SpdmMeasurementsResponsePayload {
                    number_of_measurement: 100u8,
                    slot_id: 100u8,
                    measurement_record: SpdmMeasurementRecordStructure {
                        number_of_blocks: 5,
                        record: gen_array_clone(
                            SpdmMeasurementBlockStructure {
                                index: 100u8,
                                measurement_specification: SpdmMeasurementSpecification::DMTF,
                                measurement_size: 67u16,
                                measurement: SpdmDmtfMeasurementStructure {
                                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                                    representation:
                                        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                                    value_size: 64u16,
                                    value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
                                },
                            },
                            MAX_SPDM_MEASUREMENT_BLOCK_COUNT,
                        ),
                    },
                    nonce: SpdmNonceStruct {
                        data: [100u8; SPDM_NONCE_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 64,
                        data: [100u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: 512,
                        data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_signature = true;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseMeasurements
        );
        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.number_of_measurement, 100);
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.measurement_record.number_of_blocks, 5);
            for i in 0..5 {
                assert_eq!(payload.measurement_record.record[i].index, 100);
                assert_eq!(
                    payload.measurement_record.record[i].measurement_specification,
                    SpdmMeasurementSpecification::DMTF
                );
                assert_eq!(payload.measurement_record.record[i].measurement_size, 67);
                assert_eq!(
                    payload.measurement_record.record[i].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
                );
                assert_eq!(
                    payload.measurement_record.record[i]
                        .measurement
                        .representation,
                    SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
                );
                assert_eq!(
                    payload.measurement_record.record[i].measurement.value_size,
                    64
                );
                for j in 0..64 {
                    assert_eq!(
                        payload.measurement_record.record[i].measurement.value[j],
                        100
                    );
                }
            }
            for i in 0..32 {
                assert_eq!(payload.nonce.data[i], 100);
            }
            assert_eq!(payload.opaque.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.opaque.data[i], 100);
            }
            assert_eq!(payload.signature.data_size, 512);
            for i in 0..512 {
                assert_eq!(payload.signature.data[i], 100);
            }
        }
    }
    #[test]
    fn test_case10_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyExchange,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeRequest(SpdmKeyExchangeRequestPayload {
                measurement_summary_hash_type:
                    SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                slot_id: 100u8,
                req_session_id: 100u16,
                random: SpdmRandomStruct {
                    data: [100u8; SPDM_RANDOM_SIZE],
                },
                exchange: SpdmDheExchangeStruct {
                    data_size: 512u16,
                    data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
                },
                opaque: SpdmOpaqueStruct {
                    data_size: 64u16,
                    data: [100u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
                },
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = SpdmDheAlgo::FFDHE_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestKeyExchange
        );
        if let SpdmMessagePayload::SpdmKeyExchangeRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone
            );
            assert_eq!(payload.slot_id, 100);
            for i in 0..32 {
                assert_eq!(payload.random.data[i], 100);
            }
            assert_eq!(payload.exchange.data_size, 512);
            for i in 0..512 {
                assert_eq!(payload.exchange.data[i], 100);
            }
            assert_eq!(payload.opaque.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.opaque.data[i], 100);
            }
        }
    }
    #[test]
    fn test_case12_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestFinish,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(SpdmFinishRequestPayload {
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
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestFinish
        );
        if let SpdmMessagePayload::SpdmFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.finish_request_attributes,
                SpdmFinishRequestAttributes::SIGNATURE_INCLUDED
            );
            assert_eq!(payload.req_slot_id, 100);
            assert_eq!(payload.signature.data_size, 512);
            for i in 0..512 {
                assert_eq!(payload.signature.data[i], 0xa5u8);
            }
            assert_eq!(payload.verify_data.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.verify_data.data[i], 0x5au8);
            }
        }
    }
    #[test]
    fn test_case13_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(SpdmFinishResponsePayload {
                verify_data: SpdmDigestStruct {
                    data_size: 64,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.req_capabilities_sel =
            SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseFinishRsp
        );
        if let SpdmMessagePayload::SpdmFinishResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case114_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskExchange,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(SpdmPskExchangeRequestPayload {
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
            }),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestPskExchange
        );
        if let SpdmMessagePayload::SpdmPskExchangeRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.measurement_summary_hash_type,
                SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            );
            assert_eq!(payload.psk_hint.data_size, 32);
            assert_eq!(payload.psk_context.data_size, 64);
            assert_eq!(payload.opaque.data_size, 64);
            for i in 0..32 {
                assert_eq!(payload.psk_hint.data[i], 100);
            }
            for i in 0..64 {
                assert_eq!(payload.psk_context.data[i], 100);
                assert_eq!(payload.opaque.data[i], 100);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskExchangeRsp,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(SpdmPskExchangeResponsePayload {
                heartbeat_period: 0xaau8,
                rsp_session_id: 0xaa55u16,
                measurement_summary_hash: SpdmDigestStruct {
                    data_size: 64,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
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
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_summary_hash = true;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponsePskExchangeRsp
        );
        if let SpdmMessagePayload::SpdmPskExchangeResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.heartbeat_period, 0xaau8);
            assert_eq!(payload.rsp_session_id, 0xaa55u16);

            assert_eq!(payload.measurement_summary_hash.data_size, 64);
            assert_eq!(payload.psk_context.data_size, 64);
            assert_eq!(payload.opaque.data_size, 64);
            assert_eq!(payload.verify_data.data_size, 64);

            for i in 0..64 {
                assert_eq!(payload.measurement_summary_hash.data[i], 100);
                assert_eq!(payload.psk_context.data[i], 100);
                assert_eq!(payload.opaque.data[i], 100);
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case15_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestPskFinish,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(SpdmPskFinishRequestPayload {
                verify_data: SpdmDigestStruct {
                    data_size: 64,
                    data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                },
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestPskFinish
        );
        if let SpdmMessagePayload::SpdmPskFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }
    }
    #[test]
    fn test_case17_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmKeyUpdateRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.key_update_operation,
                SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            );
            assert_eq!(payload.tag, 100);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                tag: 100u8,
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseKeyUpdateAck
        );
        if let SpdmMessagePayload::SpdmKeyUpdateResponse(payload) = &spdm_message.payload {
            assert_eq!(
                payload.key_update_operation,
                SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            );
            assert_eq!(payload.tag, 100);
        }
    }
    #[test]
    fn test_case18_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes:
                    SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
            }),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestEndSession
        );
        if let SpdmMessagePayload::SpdmEndSessionRequest(payload) = &spdm_message.payload {
            assert_eq!(
                payload.end_session_request_attributes,
                SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE
            );
        }
    }
    #[test]
    fn test_case19_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code: SpdmErrorCode::SpdmErrorResponseNotReady,
                error_data: 100,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                    SpdmErrorResponseNotReadyExtData {
                        rdt_exponent: 100,
                        request_code: 100,
                        token: 100,
                        tdtm: 100,
                    },
                ),
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseError
        );
        if let SpdmMessagePayload::SpdmErrorResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.error_code, SpdmErrorCode::SpdmErrorResponseNotReady);
            assert_eq!(payload.error_data, 100);
            if let SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) =
                &payload.extended_data
            {
                assert_eq!(extended_data.rdt_exponent, 100);
                assert_eq!(extended_data.request_code, 100);
                assert_eq!(extended_data.token, 100);
                assert_eq!(extended_data.tdtm, 100);
            }
        }
    }
    #[test]
    fn test_case20_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
            },
            payload: SpdmMessagePayload::SpdmGetVersionRequest(SpdmGetVersionRequestPayload {}),
        };

        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case21_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };

        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case22_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    slot_id: 100,
                    offset: 100,
                    length: 100,
                },
            ),
        };

        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCertificate
        );
        if let SpdmMessagePayload::SpdmGetCertificateRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.offset, 100);
            assert_eq!(payload.length, 100);
        }
    }
    #[test]
    fn test_case23_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponsePskFinishRsp,
            },
            payload: SpdmMessagePayload::SpdmPskFinishResponse(SpdmPskFinishResponsePayload {}),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case24_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestHeartbeat,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatRequest(SpdmHeartbeatRequestPayload {}),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case25_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseEndSessionAck,
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
    #[test]
    fn test_case26_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::Unknown(0),
            },
            payload: SpdmMessagePayload::SpdmEndSessionResponse(SpdmEndSessionResponsePayload {}),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        let spdm_message = SpdmMessage::spdm_read(&mut context, &mut reader);
        assert_eq!(spdm_message.is_none(), true);
    }

    #[test]
    fn test_case27_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask: 0b11111111,
                slot_count: 8,
                digests: gen_array_clone(
                    SpdmDigestStruct {
                        data_size: 64,
                        data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
                    },
                    SPDM_MAX_SLOT_NUMBER,
                ),
            }),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let spdm_message = new_spdm_message(value, context);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseDigests
        );
        if let SpdmMessagePayload::SpdmDigestsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_mask, 0b11111111);
            assert_eq!(payload.slot_count, 8);
            assert_eq!(payload.digests[1].data_size, 64u16);
            assert_eq!(payload.digests[1].data[1], 100u8);
        }
    }
    #[test]
    fn test_case28_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseHeartbeatAck,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload {}),
        };
        let context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        new_spdm_message(value, context);
    }
}
