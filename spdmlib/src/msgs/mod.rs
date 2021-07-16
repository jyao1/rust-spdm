// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod algo;
mod header;
mod opaque;
mod spdm_codec;
pub use algo::*;

use crate::cmds::digest as cmd_digest;
use crate::cmds::key_exchange as cmd_key_exchange;
use crate::cmds::*;
use crate::common;
use codec::{Codec, Reader, Writer};
pub use header::*;
pub use opaque::*;
pub use spdm_codec::SpdmCodec;

pub use algorithm::*;
pub use capability::*;
pub use certificate::*;
pub use challenge::*;
pub use cmd_digest::*;
pub use cmd_key_exchange::*;
pub use end_session::*;
pub use error::*;
pub use finish::*;
pub use heartbeat::*;
pub use key_update::*;
pub use measurement::*;
pub use psk_exchange::*;
pub use psk_finish::*;
pub use version::*;
// Add new SPDM command here.

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
}

impl SpdmMessage {
    pub fn read_with_detailed_error(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmMessage> {
        let header = SpdmMessageHeader::read(r)?;

        let payload = match header.request_response_code {
            SpdmResponseResponseCode::SpdmResponseVersion => {
                Some(SpdmMessagePayload::SpdmVersionResponse(
                    SpdmVersionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestGetVersion => {
                Some(SpdmMessagePayload::SpdmGetVersionRequest(
                    SpdmGetVersionRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseCapabilities => {
                Some(SpdmMessagePayload::SpdmCapabilitiesResponse(
                    SpdmCapabilitiesResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestGetCapabilities => {
                Some(SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                    SpdmGetCapabilitiesRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseAlgorithms => {
                Some(SpdmMessagePayload::SpdmAlgorithmsResponse(
                    SpdmAlgorithmsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestNegotiateAlgorithms => {
                Some(SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                    SpdmNegotiateAlgorithmsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseDigests => {
                Some(SpdmMessagePayload::SpdmDigestsResponse(
                    SpdmDigestsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestGetDigests => {
                Some(SpdmMessagePayload::SpdmGetDigestsRequest(
                    SpdmGetDigestsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseCertificate => {
                Some(SpdmMessagePayload::SpdmCertificateResponse(
                    SpdmCertificateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestGetCertificate => {
                Some(SpdmMessagePayload::SpdmGetCertificateRequest(
                    SpdmGetCertificateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseChallengeAuth => {
                Some(SpdmMessagePayload::SpdmChallengeAuthResponse(
                    SpdmChallengeAuthResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestChallenge => {
                Some(SpdmMessagePayload::SpdmChallengeRequest(
                    SpdmChallengeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseMeasurements => {
                Some(SpdmMessagePayload::SpdmMeasurementsResponse(
                    SpdmMeasurementsResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestGetMeasurements => {
                Some(SpdmMessagePayload::SpdmGetMeasurementsRequest(
                    SpdmGetMeasurementsRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseKeyExchangeRsp => {
                Some(SpdmMessagePayload::SpdmKeyExchangeResponse(
                    SpdmKeyExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestKeyExchange => {
                Some(SpdmMessagePayload::SpdmKeyExchangeRequest(
                    SpdmKeyExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseFinishRsp => {
                Some(SpdmMessagePayload::SpdmFinishResponse(
                    SpdmFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestFinish => {
                Some(SpdmMessagePayload::SpdmFinishRequest(
                    SpdmFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponsePskExchangeRsp => {
                Some(SpdmMessagePayload::SpdmPskExchangeResponse(
                    SpdmPskExchangeResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestPskExchange => {
                Some(SpdmMessagePayload::SpdmPskExchangeRequest(
                    SpdmPskExchangeRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponsePskFinishRsp => {
                Some(SpdmMessagePayload::SpdmPskFinishResponse(
                    SpdmPskFinishResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestPskFinish => {
                Some(SpdmMessagePayload::SpdmPskFinishRequest(
                    SpdmPskFinishRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseHeartbeatAck => {
                Some(SpdmMessagePayload::SpdmHeartbeatResponse(
                    SpdmHeartbeatResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestHeartbeat => {
                Some(SpdmMessagePayload::SpdmHeartbeatRequest(
                    SpdmHeartbeatRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseKeyUpdateAck => {
                Some(SpdmMessagePayload::SpdmKeyUpdateResponse(
                    SpdmKeyUpdateResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestKeyUpdate => {
                Some(SpdmMessagePayload::SpdmKeyUpdateRequest(
                    SpdmKeyUpdateRequestPayload::spdm_read(context, r)?,
                ))
            }

            SpdmResponseResponseCode::SpdmResponseEndSessionAck => {
                Some(SpdmMessagePayload::SpdmEndSessionResponse(
                    SpdmEndSessionResponsePayload::spdm_read(context, r)?,
                ))
            }
            SpdmResponseResponseCode::SpdmRequestEndSession => {
                Some(SpdmMessagePayload::SpdmEndSessionRequest(
                    SpdmEndSessionRequestPayload::spdm_read(context, r)?,
                ))
            }

            // Add new SPDM command here.
            SpdmResponseResponseCode::SpdmResponseError => {
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
        }
    }

    fn spdm_read(context: &mut common::SpdmContext, r: &mut Reader) -> Option<SpdmMessage> {
        SpdmMessage::read_with_detailed_error(context, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common::SpdmContext, testlib::*};

    #[test]
    fn test_case0_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 0x01,
                versions: [SpdmVersionStruct {
                    update: 100,
                    version: SpdmVersion::SpdmVersion10,
                }; crate::config::MAX_SPDM_VERSION_COUNT],
            }),
        };
        let mut context = fun_name(my_spdm_device_io, pcidoe_transport_encap);
        let mut spdm_message = fun_name_message(value, context);
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmResponseResponseCode::SpdmResponseDigests
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x01);
            for i in 0..2 {
                assert_eq!(payload.versions[i].update, 100);
                assert_eq!(payload.versions[i].version, SpdmVersion::SpdmVersion10);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmGetCapabilitiesRequest(
                SpdmGetCapabilitiesRequestPayload {
                    ct_exponent: 0x02,
                    flags: SpdmRequestCapabilityFlags::CERT_CAP,
                },
            ),
        };
        context = fun_name(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = fun_name_message(value, context);
        if let SpdmMessagePayload::SpdmGetCapabilitiesRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x02);
            assert_eq!(payload.flags, SpdmRequestCapabilityFlags::CERT_CAP);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: 0x03,
                    flags: SpdmResponseCapabilityFlags::CACHE_CAP,
                },
            ),
        };
        context = fun_name(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = fun_name_message(value, context);
        if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x03);
            assert_eq!(payload.flags, SpdmResponseCapabilityFlags::CACHE_CAP);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmCapabilitiesResponse(
                SpdmCapabilitiesResponsePayload {
                    ct_exponent: 0x03,
                    flags: SpdmResponseCapabilityFlags::CACHE_CAP,
                },
            ),
        };
        context = fun_name(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = fun_name_message(value, context);
        if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.ct_exponent, 0x03);
            assert_eq!(payload.flags, SpdmResponseCapabilityFlags::CACHE_CAP);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(
                SpdmNegotiateAlgorithmsRequestPayload {
                    measurement_specification: SpdmMeasurementSpecification::DMTF,
                    base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                    base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    alg_struct_count: 4,
                    alg_struct: [SpdmAlgStruct{
                        alg_type : SpdmAlgType::SpdmAlgTypeDHE,
                        alg_fixed_count :2,
                        alg_supported :SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048),
                        alg_ext_count :0, 
                    }; crate::config::MAX_SPDM_ALG_STRUCT_COUNT],
                 },
            ),
        };
        context = fun_name(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = fun_name_message(value, context);
        if let SpdmMessagePayload::SpdmNegotiateAlgorithmsRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.measurement_specification,SpdmMeasurementSpecification::DMTF);
            assert_eq!(payload.base_asym_algo,SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048);
            assert_eq!(payload.base_hash_algo,SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count,4);
            for i in 0..4{
                   assert_eq!(payload.alg_struct[i].alg_type,SpdmAlgType::SpdmAlgTypeDHE);
                   assert_eq!(payload.alg_struct[i].alg_fixed_count,2);
                   assert_eq!(payload.alg_struct[1].alg_supported,SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048));
                   assert_eq!(payload.alg_struct[i].alg_ext_count,0);
            }
        }
    }

    fn fun_name<'a>(
        my_spdm_device_io: &'a mut MySpdmDeviceIo,
        pcidoe_transport_encap: &'a mut PciDoeTransportEncap,
    ) -> SpdmContext<'a> {
        let (config_info, provision_info) = create_info();
        let context = SpdmContext::new(
            my_spdm_device_io,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context
    }

    fn fun_name_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
        spdm_message
    }
}
