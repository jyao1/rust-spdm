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
    use crate::config::*;

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
        println!("SpdmMessage :{:#?}",value);
        println!("SpdmMessagePayload  :{:#?}",value.payload);
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let mut spdm_message = new_spdm_message(value, context);
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
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
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
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
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
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
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
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
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
        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmAlgorithmsResponse(
                SpdmAlgorithmsResponsePayload {
                    measurement_specification_sel: SpdmMeasurementSpecification::DMTF,
                    measurement_hash_algo: SpdmMeasurementHashAlgo::RAW_BIT_STREAM,
                    base_asym_sel: SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
                    base_hash_sel: SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    alg_struct_count: 4,
                    alg_struct: [SpdmAlgStruct{
                        alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                        alg_fixed_count: 2,
                        alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048),
                        alg_ext_count: 0, 
                    }; MAX_SPDM_ALG_STRUCT_COUNT],
                    },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.measurement_specification_sel,SpdmMeasurementSpecification::DMTF);
            assert_eq!(payload.measurement_hash_algo,SpdmMeasurementHashAlgo::RAW_BIT_STREAM);
            assert_eq!(payload.base_asym_sel,SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048);
            assert_eq!(payload.base_hash_sel,SpdmBaseHashAlgo::TPM_ALG_SHA_256);
            assert_eq!(payload.alg_struct_count,4);
            for i in 0..4{
                    assert_eq!(payload.alg_struct[i].alg_type,SpdmAlgType::SpdmAlgTypeDHE);
                    assert_eq!(payload.alg_struct[i].alg_fixed_count,2);
                    assert_eq!(payload.alg_struct[1].alg_supported,SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::FFDHE_2048));
                    assert_eq!(payload.alg_struct[i].alg_ext_count,0);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmCertificateResponse(
                SpdmCertificateResponsePayload {
                    slot_id:100,
                    portion_length:512,
                    remainder_length:100,
                    cert_chain: [100u8; MAX_SPDM_CERT_PORTION_LEN],
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id,100);
            assert_eq!(payload.portion_length,512);
            assert_eq!(payload.remainder_length,100); 
            for i in 0..512{
            assert_eq!(payload.cert_chain[i],100u8); 
            };
        }
    }
    #[test]
    fn test_case1_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmChallengeRequest(
                SpdmChallengeRequestPayload {
                    slot_id: 100,
                    measurement_summary_hash_type:
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    nonce: SpdmNonceStruct { data: [100u8; 32] },
                },
            ),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        let mut spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmChallengeRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.measurement_summary_hash_type,SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone);
            for i in 0..32 {
                assert_eq!(payload.nonce.data[i], 100u8);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmChallengeAuthResponse(
                SpdmChallengeAuthResponsePayload {
                    slot_id: 0x0f,
                    slot_mask: 100,
                    challenge_auth_attribute: SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ,
                    cert_chain_hash: SpdmDigestStruct{
                        data_size: 64,
                        data: [0xAAu8; SPDM_MAX_HASH_SIZE],
                    },
                    nonce: SpdmNonceStruct { data: [100u8; SPDM_NONCE_SIZE] },
                    measurement_summary_hash:  SpdmDigestStruct {
                        data_size: 64,
                        data: [0x55u8; SPDM_MAX_HASH_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 64,
                        data: [0xAAu8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature:  SpdmSignatureStruct {
                        data_size: 512,
                        data: [0x55u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.runtime_info.need_measurement_summary_hash = true;
        context.negotiate_info.base_asym_sel=SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel=SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmChallengeAuthResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 0x0f);
            assert_eq!(payload.slot_mask, 100);
            assert_eq!(payload.challenge_auth_attribute,SpdmChallengeAuthAttribute::BASIC_MUT_AUTH_REQ);

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
    fn test_case2_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
        },
        payload: SpdmMessagePayload::SpdmGetMeasurementsRequest(
            SpdmGetMeasurementsRequestPayload {
                measurement_attributes: SpdmMeasurementeAttributes::INCLUDE_SIGNATURE,
                measurement_operation: SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                nonce: SpdmNonceStruct {
                    data: [100u8; SPDM_NONCE_SIZE],
                },
                slot_id: 0xaau8,
            },
        ),
    };
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    let mut spdm_message = new_spdm_message(value, context);
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

    let value = SpdmMessage {
        header: SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
        },
        payload: SpdmMessagePayload::SpdmMeasurementsResponse(
            SpdmMeasurementsResponsePayload {
                number_of_measurement: 100u8,
                slot_id: 100u8,
                measurement_record: SpdmMeasurementRecordStructure {
                    number_of_blocks: 5,
                    record: [SpdmMeasurementBlockStructure{
                        index: 100u8,
                        measurement_specification: SpdmMeasurementSpecification::DMTF,
                        measurement_size: 67u16,
                        measurement: SpdmDmtfMeasurementStructure {
                            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
                            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                            value_size: 64u16,
                            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
                        },
                    };MAX_SPDM_MEASUREMENT_BLOCK_COUNT],
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
    context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    context.runtime_info.need_measurement_signature = true;
    spdm_message = new_spdm_message(value, context);
    if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
        assert_eq!(payload.number_of_measurement, 100);
        assert_eq!(payload.slot_id, 100);
        assert_eq!(payload.measurement_record.number_of_blocks, 5);
        for i in 0..5{
            assert_eq!(payload.measurement_record.record[i].index, 100);
            assert_eq!(payload.measurement_record.record[i].measurement_specification, SpdmMeasurementSpecification::DMTF);
            assert_eq!(payload.measurement_record.record[i].measurement_size, 67);
            assert_eq!(payload.measurement_record.record[i].measurement.r#type,SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom);
            assert_eq!(payload.measurement_record.record[i].measurement.representation,SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest);
            assert_eq!(payload.measurement_record.record[i].measurement.value_size, 64);
            for j in 0..64 {
                assert_eq!(payload.measurement_record.record[i].measurement.value[j], 100);
            }
        }
        for i in 0..32{
            assert_eq!(payload.nonce.data[i], 100);   
        }
        assert_eq!(payload.opaque.data_size,64);
        for i in 0..64
        {
            assert_eq!(payload.opaque.data[i],100);
        }
        assert_eq!(payload.signature.data_size, 512);
        for i in 0..512 {
            assert_eq!(payload.signature.data[i], 100);
        }
    }
}
    #[test]
    fn test_case3_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeRequest(
                SpdmKeyExchangeRequestPayload {
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
                },
            ),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = SpdmDheAlgo::FFDHE_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let mut spdm_message = new_spdm_message(value, context);
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

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmKeyExchangeResponse(
                SpdmKeyExchangeResponsePayload {
                    heartbeat_period: 100u8,
                    rsp_session_id: 100u16,
                    mut_auth_req: SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ,
                    req_slot_id: 100u8,
                    random: SpdmRandomStruct {
                        data: [100u8; SPDM_RANDOM_SIZE],
                    },
                    exchange: SpdmDheExchangeStruct {
                        data_size: 512u16,
                        data: [0xa5u8; SPDM_MAX_DHE_KEY_SIZE],
                    },
                    measurement_summary_hash: SpdmDigestStruct {
                        data_size: 64u16,
                        data: [0x11u8; SPDM_MAX_HASH_SIZE],
                    },
                    opaque: SpdmOpaqueStruct {
                        data_size: 64u16,
                        data: [0x22u8; crate::config::MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: 512u16,
                        data: [0x5au8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                    verify_data: SpdmDigestStruct {
                        data_size: 64u16,
                        data: [0x33u8; SPDM_MAX_HASH_SIZE],
                    },
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.dhe_sel = SpdmDheAlgo::FFDHE_4096;
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        context.runtime_info.need_measurement_summary_hash=true;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmKeyExchangeResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.heartbeat_period, 100);
            assert_eq!(payload.rsp_session_id, 100);
            assert_eq!(payload.mut_auth_req,SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ);
            assert_eq!(payload.req_slot_id, 100);
            for i in 0..32 {
                assert_eq!(payload.random.data[i], 100);
            }

            assert_eq!(payload.exchange.data_size, 512);
            assert_eq!(payload.signature.data_size, 512);
            for i in 0..512 {
                assert_eq!(payload.exchange.data[i], 0xa5);
                assert_eq!(payload.signature.data[i], 0x5a);
            }

            assert_eq!(payload.measurement_summary_hash.data_size, 64);
            assert_eq!(payload.verify_data.data_size,64);
            assert_eq!(payload.opaque.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.measurement_summary_hash.data[i], 0x11);
                assert_eq!(payload.opaque.data[i], 0x22);
                assert_eq!(payload.verify_data.data[i], 0x33);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(
                SpdmFinishRequestPayload {
                    finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
                    req_slot_id: 100,
                    signature: SpdmSignatureStruct {
                        data_size: 512,
                        data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                    verify_data: SpdmDigestStruct {
                        data_size: 64,
                        data: [0x5au8; SPDM_MAX_HASH_SIZE],
                    },
                 },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_asym_sel=SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel=SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.finish_request_attributes,SpdmFinishRequestAttributes::SIGNATURE_INCLUDED);
            assert_eq!(payload.req_slot_id,100);
            assert_eq!(payload.signature.data_size,512);
            for i in 0..512{
                assert_eq!(payload.signature.data[i],0xa5u8);
            }
            assert_eq!(payload.verify_data.data_size,64);
            for i in 0..64{
                assert_eq!(payload.verify_data.data[i],0x5au8);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmFinishResponse(
                SpdmFinishResponsePayload {
                    verify_data: SpdmDigestStruct{
                        data_size: 64,
                        data: [100u8; SPDM_MAX_HASH_SIZE],
                    }
                 },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel=SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.negotiate_info.req_capabilities_sel=SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        context.negotiate_info.rsp_capabilities_sel=SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmFinishRequest(
                SpdmFinishRequestPayload {
                    finish_request_attributes: SpdmFinishRequestAttributes::SIGNATURE_INCLUDED,
                    req_slot_id: 100,
                    signature: SpdmSignatureStruct {
                        data_size: 512,
                        data: [0xa5u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                    verify_data: SpdmDigestStruct {
                        data_size: 64,
                        data: [0x5au8; SPDM_MAX_HASH_SIZE],
                    },
                 },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_asym_sel=SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        context.negotiate_info.base_hash_sel=SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.finish_request_attributes,SpdmFinishRequestAttributes::SIGNATURE_INCLUDED);
            assert_eq!(payload.req_slot_id,100);
            assert_eq!(payload.signature.data_size,512);
            for i in 0..512{
                assert_eq!(payload.signature.data[i],0xa5u8);
            }
            assert_eq!(payload.verify_data.data_size,64);
            for i in 0..64{
                assert_eq!(payload.verify_data.data[i],0x5au8);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeRequest(
                SpdmPskExchangeRequestPayload {
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
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmPskExchangeRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.measurement_summary_hash_type,SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll);
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
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmPskExchangeResponse(
                SpdmPskExchangeResponsePayload {
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
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        context.runtime_info.need_measurement_summary_hash = true;

        spdm_message = new_spdm_message(value, context);
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
    fn test_case4_spdm_message() {
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmPskFinishRequest(
                SpdmPskFinishRequestPayload {
                    verify_data: SpdmDigestStruct {
                        data_size: 64,
                        data: [100u8; SPDM_MAX_HASH_SIZE],
                    },
                },
            ),
        };
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        let mut spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmPskFinishRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.verify_data.data_size, 64);
            for i in 0..64 {
                assert_eq!(payload.verify_data.data[i], 100u8);
            }
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(
                SpdmKeyUpdateRequestPayload {
                    key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                    tag: 100u8,
                 },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmKeyUpdateRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.key_update_operation,SpdmKeyUpdateOperation::SpdmUpdateAllKeys);
            assert_eq!(payload.tag,100);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(
                SpdmKeyUpdateResponsePayload {
                    key_update_operation: SpdmKeyUpdateOperation::SpdmUpdateAllKeys,
                    tag: 100u8,
                 },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmKeyUpdateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.key_update_operation,SpdmKeyUpdateOperation::SpdmUpdateAllKeys);
            assert_eq!(payload.tag,100);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(
                SpdmEndSessionRequestPayload {
                    end_session_request_attributes: SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE,
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmEndSessionRequest(payload) = &spdm_message.payload {
            assert_eq!(payload.end_session_request_attributes,SpdmEndSessionRequestAttributes::PRESERVE_NEGOTIATED_STATE);
        }

        let value = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(
                SpdmErrorResponsePayload {
                    error_code: SpdmErrorCode::SpdmErrorResponseNotReady,
                    error_data: 100,
                    extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                        SpdmErrorResponseNotReadyExtData{
                            rdt_exponent: 100,
                            request_code: 100,
                            token: 100,
                            tdtm: 100,
                        }),
                },
            ),
        };
        context = new_context(my_spdm_device_io, pcidoe_transport_encap);
        context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
        spdm_message = new_spdm_message(value, context);
        if let SpdmMessagePayload::SpdmErrorResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.error_code, SpdmErrorCode::SpdmErrorResponseNotReady);
            assert_eq!(payload.error_data, 100);
            if let SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) 
            = &payload.extended_data {
                assert_eq!(extended_data.rdt_exponent, 100);
                assert_eq!(extended_data.request_code, 100);
                assert_eq!(extended_data.token, 100);
                assert_eq!(extended_data.tdtm, 100);
            } 
        }
    }


    fn new_spdm_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
        let u8_slice = &mut [0u8; 1000];
        let mut writer = Writer::init(u8_slice);
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
        spdm_message
    }
}
