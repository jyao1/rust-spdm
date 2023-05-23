// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
mod secret_callback;

use crate::protocol::*;
use conquer_once::spin::OnceCell;
pub use secret_callback::{SpdmAsymSign, SpdmSecret};

pub static SECRET_INSTANCE: OnceCell<SpdmSecret> = OnceCell::uninit();
static CRYPTO_ASYM_SIGN: OnceCell<SpdmAsymSign> = OnceCell::uninit();

pub fn register(context: SpdmSecret) -> bool {
    SECRET_INSTANCE.try_init_once(|| context).is_ok()
}

static UNIMPLETEMTED: SpdmSecret = SpdmSecret {
    spdm_measurement_collection_cb: |_spdm_version: SpdmVersion,
                                     _measurement_specification: SpdmMeasurementSpecification,
                                     _measurement_hash_algo: SpdmBaseHashAlgo,
                                     _measurement_index: usize|
     -> Option<SpdmMeasurementRecordStructure> {
        unimplemented!()
    },

    spdm_generate_measurement_summary_hash_cb:
        |_spdm_version: SpdmVersion,
         _base_hash_algo: SpdmBaseHashAlgo,
         _measurement_specification: SpdmMeasurementSpecification,
         _measurement_hash_algo: SpdmBaseHashAlgo,
         _measurement_summary_hash_type: SpdmMeasurementSummaryHashType|
         -> Option<SpdmDigestStruct> { unimplemented!() },

    spdm_requester_data_sign_cb: |_spdm_version: SpdmVersion,
                                  _op_code: u8,
                                  _req_base_asym_alg: SpdmReqAsymAlgo,
                                  _base_hash_algo: SpdmBaseHashAlgo,
                                  _is_data_hash: bool,
                                  _message: &[u8],
                                  _message_size: u8|
     -> Option<SpdmSignatureStruct> { unimplemented!() },

    spdm_responder_data_sign_cb: |_spdm_version: SpdmVersion,
                                  _op_code: u8,
                                  _req_base_asym_alg: SpdmReqAsymAlgo,
                                  _base_hash_algo: SpdmBaseHashAlgo,
                                  _is_data_hash: bool,
                                  _message: &[u8],
                                  _message_size: u8|
     -> Option<SpdmSignatureStruct> { unimplemented!() },

    spdm_psk_handshake_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                               _base_hash_algo: SpdmBaseHashAlgo,
                                               _psk_hint: &[u8],
                                               _psk_hint_size: Option<usize>,
                                               _info: Option<&[u8]>,
                                               _info_size: Option<usize>|
     -> Option<SpdmHKDFKeyStruct> {
        unimplemented!()
    },

    spdm_psk_master_secret_hkdf_expand_cb: |_spdm_version: SpdmVersion,
                                            _base_hash_algo: SpdmBaseHashAlgo,
                                            _psk_hint: &[u8],
                                            _psk_hint_size: Option<usize>,
                                            _info: Option<&[u8]>,
                                            _info_size: Option<usize>|
     -> Option<SpdmHKDFKeyStruct> { unimplemented!() },
};

/*
    Function to get measurements.

    This function wraps SpdmSecret.spdm_measurement_collection_cb callback
    Device security lib is responsible for the implementation of SpdmSecret.
    If SECRET_INSTANCE got no registered, a panic with string "not implemented"
    will be emit.

    @When measurement_index == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
            A dummy Some(SpdmMeasurementRecordStructure) is returned, with its number_of_blocks
            field set and all other field reserved.
    @When measurement_index != SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
            A normal Some(SpdmMeasurementRecordStructure) is returned, with all fields valid.
*/
pub fn spdm_measurement_collection(
    spdm_version: SpdmVersion,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmBaseHashAlgo,
    measurement_index: usize,
) -> Option<SpdmMeasurementRecordStructure> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_measurement_collection_cb)(
        spdm_version,
        measurement_specification,
        measurement_hash_algo,
        measurement_index,
    )
}

pub fn spdm_generate_measurement_summary_hash(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmBaseHashAlgo,
    measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
) -> Option<SpdmDigestStruct> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_generate_measurement_summary_hash_cb)(
        spdm_version,
        base_hash_algo,
        measurement_specification,
        measurement_hash_algo,
        measurement_summary_hash_type,
    )
}

pub fn spdm_requester_data_sign(
    spdm_version: SpdmVersion,
    op_code: u8,
    req_base_asym_alg: SpdmReqAsymAlgo,
    base_hash_algo: SpdmBaseHashAlgo,
    is_data_hash: bool,
    message: &[u8],
    message_size: u8,
) -> Option<SpdmSignatureStruct> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_requester_data_sign_cb)(
        spdm_version,
        op_code,
        req_base_asym_alg,
        base_hash_algo,
        is_data_hash,
        message,
        message_size,
    )
}

pub fn spdm_responder_data_sign(
    spdm_version: SpdmVersion,
    op_code: u8,
    req_base_asym_alg: SpdmReqAsymAlgo,
    base_hash_algo: SpdmBaseHashAlgo,
    is_data_hash: bool,
    message: &[u8],
    message_size: u8,
) -> Option<SpdmSignatureStruct> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_responder_data_sign_cb)(
        spdm_version,
        op_code,
        req_base_asym_alg,
        base_hash_algo,
        is_data_hash,
        message,
        message_size,
    )
}

pub fn spdm_psk_handshake_secret_hkdf_expand(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &[u8],
    psk_hint_size: Option<usize>,
    info: Option<&[u8]>,
    info_size: Option<usize>,
) -> Option<SpdmHKDFKeyStruct> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_psk_handshake_secret_hkdf_expand_cb)(
        spdm_version,
        base_hash_algo,
        psk_hint,
        psk_hint_size,
        info,
        info_size,
    )
}

pub fn spdm_psk_master_secret_hkdf_expand(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &[u8],
    psk_hint_size: Option<usize>,
    info: Option<&[u8]>,
    info_size: Option<usize>,
) -> Option<SpdmHKDFKeyStruct> {
    (SECRET_INSTANCE
        .try_get_or_init(|| UNIMPLETEMTED.clone())
        .ok()?
        .spdm_psk_master_secret_hkdf_expand_cb)(
        spdm_version,
        base_hash_algo,
        psk_hint,
        psk_hint_size,
        info,
        info_size,
    )
}

pub mod asym_sign {
    use super::CRYPTO_ASYM_SIGN;
    use crate::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};
    use crate::secret::SpdmAsymSign;

    pub fn register(context: SpdmAsymSign) -> bool {
        CRYPTO_ASYM_SIGN.try_init_once(|| context).is_ok()
    }

    static DEFAULT: SpdmAsymSign = SpdmAsymSign {
        sign_cb: |_base_hash_algo: SpdmBaseHashAlgo,
                  _base_asym_algo: SpdmBaseAsymAlgo,
                  _data: &[u8]|
         -> Option<SpdmSignatureStruct> { unimplemented!() },
    };

    pub fn sign(
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct> {
        (CRYPTO_ASYM_SIGN
            .try_get_or_init(|| DEFAULT.clone())
            .ok()?
            .sign_cb)(base_hash_algo, base_asym_algo, data)
    }
}
