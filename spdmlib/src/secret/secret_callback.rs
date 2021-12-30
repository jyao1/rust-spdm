// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::algo::{
    SpdmBaseHashAlgo, SpdmDigestStruct, SpdmHKDFKeyStruct, SpdmMeasurementRecordStructure,
    SpdmMeasurementSpecification, SpdmMeasurementSummaryHashType, SpdmReqAsymAlgo,
    SpdmSignatureStruct,
};
use crate::message::SpdmVersion;

type SpdmMeasurementCollectionCbType = fn(
    spdm_version: SpdmVersion,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmBaseHashAlgo,
    measurement_index: usize,
) -> Option<SpdmMeasurementRecordStructure>;

type SpdmGenerateMeasurementSummaryHashCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmBaseHashAlgo,
    measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
) -> Option<SpdmDigestStruct>;

type SpdmRequesterDataSignCbType = fn(
    spdm_version: SpdmVersion,
    op_code: u8,
    req_base_asym_alg: SpdmReqAsymAlgo,
    base_hash_algo: SpdmBaseHashAlgo,
    is_data_hash: bool,
    message: &[u8],
    message_size: u8,
) -> Option<SpdmSignatureStruct>;
type SpdmResponderDataSignCbType = fn(
    spdm_version: SpdmVersion,
    op_code: u8,
    req_base_asym_alg: SpdmReqAsymAlgo,
    base_hash_algo: SpdmBaseHashAlgo,
    is_data_hash: bool,
    message: &[u8],
    message_size: u8,
) -> Option<SpdmSignatureStruct>;
type SpdmPskHandshakeSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &[u8],
    psk_hint_size: Option<usize>,
    info: Option<&[u8]>,
    info_size: Option<usize>,
) -> Option<SpdmHKDFKeyStruct>;
type SpdmPskMasterSecretHkdfExpandCbType = fn(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &[u8],
    psk_hint_size: Option<usize>,
    info: Option<&[u8]>,
    info_size: Option<usize>,
) -> Option<SpdmHKDFKeyStruct>;

#[derive(Clone, Copy)]
pub struct SpdmSecret {
    pub spdm_measurement_collection_cb: SpdmMeasurementCollectionCbType,

    pub spdm_generate_measurement_summary_hash_cb: SpdmGenerateMeasurementSummaryHashCbType,

    pub spdm_requester_data_sign_cb: SpdmRequesterDataSignCbType,

    pub spdm_responder_data_sign_cb: SpdmResponderDataSignCbType,

    pub spdm_psk_handshake_secret_hkdf_expand_cb: SpdmPskHandshakeSecretHkdfExpandCbType,

    pub spdm_psk_master_secret_hkdf_expand_cb: SpdmPskMasterSecretHkdfExpandCbType,
}
