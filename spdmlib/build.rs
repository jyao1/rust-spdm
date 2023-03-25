// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use serde::Deserialize;
use std::assert;
use std::env;
use std::io::Write;
use std::path::Path;
use std::{fs, fs::File};

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmConfig {
    pub spdm_version_config: SpdmVersionConfig,
    pub spdm_capabilities_config: SpdmCapabilitiesConfig,
    pub spdm_algorithm_config: SpdmAlgorithmConfig,
    pub key_exchange: SpdmKeyExchangeConfig,
    pub psk_exchange: SpdmPskExchangeConfig,
    pub heartbeat: SpdmHeartbeatConfig,
    pub other_buffer_size: OtherBufferSizeConfig,
}

impl SpdmConfig {
    pub fn validate_config(&self) {
        // check for spdm version
        assert!(
            self.spdm_version_config.is_spdm_version_11_supported
                || self.spdm_version_config.is_spdm_version_12_supported
        );

        // check for spdm capabilities
        assert!(self.spdm_capabilities_config.requester_cap.req_ct_exponent <= 255);
        assert!(self.spdm_capabilities_config.responder_cap.rsp_ct_exponent <= 255);
        // required by Rust-SPDM implementation
        // remove this after CHUNK cap is implemented
        assert_eq!(
            self.spdm_capabilities_config.data_transfer_size,
            self.spdm_capabilities_config.max_spdm_msg_size,
            "Under current implementation of Rust-SPDM, these two value should be the same value!"
        );

        // **NOT SUPPORTED CAP**
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_encap_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_chunk_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_chal_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_cert_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_mut_auth_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_chunk_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_handshake_in_the_clear_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .requester_cap
                .is_requester_pub_key_id_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        // check conflict
        if self
            .spdm_capabilities_config
            .requester_cap
            .is_requester_key_ex_cap_supported
        {
            assert!(
                self.spdm_capabilities_config
                    .requester_cap
                    .is_requester_encrypt_cap_supported
            );
            assert!(
                self.spdm_capabilities_config
                    .requester_cap
                    .is_requester_mac_cap_supported
            );
        }

        // **NOT SUPPORTED CAP**
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_cache_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_meas_fresh_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_mut_auth_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_encap_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_handshake_in_the_clear_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_pub_key_id_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_chunk_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_alias_cert_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_set_cert_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_csr_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        assert!(
            !self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_cert_install_reset_cap_supported,
            "Not supported by Rust-SPDM yet!"
        );
        // check conflict
        if self
            .spdm_capabilities_config
            .responder_cap
            .is_responder_key_ex_cap_supported
        {
            assert!(
                self.spdm_capabilities_config
                    .responder_cap
                    .is_responder_encrypt_cap_supported
            );
            assert!(
                self.spdm_capabilities_config
                    .responder_cap
                    .is_responder_mac_cap_supported
            );
        }

        // check for algorithm
        if self
            .spdm_capabilities_config
            .responder_cap
            .is_responder_meas_with_sig_cap_supported
            || self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_meas_without_sig_cap_supported
        {
            assert!(
                self.spdm_algorithm_config
                    .measurement_specification
                    .is_dmtf_define_measurement_specification_supported,
                "It is the only one defined in SPDM spec, mut be used"
            );
        }
        assert_eq!(
            !self
                .spdm_algorithm_config
                .other_params_support
                .is_opaque_data_fmt0_supported,
            self.spdm_algorithm_config
                .other_params_support
                .is_opaque_data_fmt1_supported,
            "Must set only one of them!"
        );
        assert!(
            self.spdm_algorithm_config
                .algorithm_structure
                .key_schedule
                .is_spdm_key_schedule_supported,
            "This field is required to be set!"
        );

        if self
            .spdm_capabilities_config
            .responder_cap
            .is_responder_meas_without_sig_cap_supported
            || self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_meas_with_sig_cap_supported
        {
            let mut measurement_hash_count = 0;
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_raw_bit_stream_only
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha3_256_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha3_384_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha3_512_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha_256_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha_384_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sha_512_supported
            {
                measurement_hash_count += 1;
            }
            if self
                .spdm_algorithm_config
                .measurement_hash_algo
                .is_tpm_alg_sm3_256_supported
            {
                measurement_hash_count += 1;
            }

            assert_eq!(
                measurement_hash_count, 1,
                "Only one measurement_hash_algo type is required!"
            );
        }

        // check for key exchange
        // the only secure spdm version supported by Rust-SPDM
        if self
            .spdm_capabilities_config
            .requester_cap
            .is_requester_encrypt_cap_supported
            || self
                .spdm_capabilities_config
                .responder_cap
                .is_responder_encrypt_cap_supported
        {
            assert!(
                self.key_exchange.is_secure_spdm_version_11_supported,
                "secure spdm version 0x11 is required by Rust-SPDM"
            );
            assert!(
                !self.key_exchange.is_secure_spdm_version_10_supported,
                "Not supported by Rust-SPDM yet!"
            );
        }

        // check for psk exchange
        assert!(self.psk_exchange.max_psk_context_size > 32) // table 63
    }
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmVersionConfig {
    pub is_spdm_version_10_supported: bool,
    pub is_spdm_version_11_supported: bool,
    pub is_spdm_version_12_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmRequesterCapabilitiesConfig {
    pub req_ct_exponent: usize,
    pub is_requester_cert_cap_supported: bool,
    pub is_requester_chal_cap_supported: bool,
    pub is_requester_encrypt_cap_supported: bool,
    pub is_requester_mac_cap_supported: bool,
    pub is_requester_mut_auth_cap_supported: bool,
    pub is_requester_key_ex_cap_supported: bool,
    pub is_requester_psk_cap_supported: bool,
    pub is_requester_encap_cap_supported: bool,
    pub is_requester_hbeat_cap_supported: bool,
    pub is_requester_key_upd_cap_supported: bool,
    pub is_requester_handshake_in_the_clear_cap_supported: bool,
    pub is_requester_pub_key_id_cap_supported: bool,
    pub is_requester_chunk_cap_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmResponderCapabilitiesConfig {
    pub rsp_ct_exponent: usize,
    pub is_responder_cache_cap_supported: bool,
    pub is_responder_cert_cap_supported: bool,
    pub is_responder_chal_cap_supported: bool,
    pub is_responder_meas_without_sig_cap_supported: bool,
    pub is_responder_meas_with_sig_cap_supported: bool,
    pub is_responder_meas_fresh_cap_supported: bool,
    pub is_responder_encrypt_cap_supported: bool,
    pub is_responder_mac_cap_supported: bool,
    pub is_responder_mut_auth_cap_supported: bool,
    pub is_responder_key_ex_cap_supported: bool,
    pub is_responder_psk_cap_supported: bool,
    pub is_responder_encap_cap_supported: bool,
    pub is_responder_hbeat_cap_supported: bool,
    pub is_responder_key_upd_cap_supported: bool,
    pub is_responder_handshake_in_the_clear_cap_supported: bool,
    pub is_responder_pub_key_id_cap_supported: bool,
    pub is_responder_chunk_cap_supported: bool,
    pub is_responder_alias_cert_cap_supported: bool,
    pub is_responder_set_cert_cap_supported: bool,
    pub is_responder_csr_cap_supported: bool,
    pub is_responder_cert_install_reset_cap_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmCapabilitiesConfig {
    pub requester_cap: SpdmRequesterCapabilitiesConfig,
    pub responder_cap: SpdmResponderCapabilitiesConfig,
    pub data_transfer_size: usize,
    pub max_spdm_msg_size: usize,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmMeasurementSpecificationConfig {
    pub is_dmtf_define_measurement_specification_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmOtherParamsSupportConfig {
    pub is_opaque_data_fmt0_supported: bool,
    pub is_opaque_data_fmt1_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmBaseAsymAlgoConfig {
    pub is_tpm_alg_rsassa_2048_supported: bool,
    pub is_tpm_alg_rsapss_2048_supported: bool,
    pub is_tpm_alg_rsassa_3072_supported: bool,
    pub is_tpm_alg_rsapss_3072_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p256_supported: bool,
    pub is_tpm_alg_rsassa_4096_supported: bool,
    pub is_tpm_alg_rsapss_4096_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p384_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p521_supported: bool,
    pub is_tpm_alg_sm2_ecc_sm2_p256_supported: bool,
    pub is_tpm_alg_eddsa_ed25519_supported: bool,
    pub is_tpm_alg_eddsa_ed448_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmBaseHashAlgoConfig {
    pub is_tpm_alg_sha_256_supported: bool,
    pub is_tpm_alg_sha_384_supported: bool,
    pub is_tpm_alg_sha_512_supported: bool,
    pub is_tpm_alg_sha3_256_supported: bool,
    pub is_tpm_alg_sha3_384_supported: bool,
    pub is_tpm_alg_sha3_512_supported: bool,
    pub is_tpm_alg_sm3_256_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmDHEConfig {
    pub is_ffdhe2048_supported: bool,
    pub is_ffdhe3072_supported: bool,
    pub is_ffdhe4096_supported: bool,
    pub is_secp256r1_supported: bool,
    pub is_secp384r1_supported: bool,
    pub is_secp521r1_supported: bool,
    pub is_sm2_p256_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmAEADConfig {
    pub is_aes_128_gcm_supported: bool,
    pub is_aes_256_gcm_supported: bool,
    pub is_chacha20_poly1305_supported: bool,
    pub is_aead_sm4_gcm_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmReqBaseAsymAlgConfig {
    pub is_tpm_alg_rsassa_2048_supported: bool,
    pub is_tpm_alg_rsapss_2048_supported: bool,
    pub is_tpm_alg_rsassa_3072_supported: bool,
    pub is_tpm_alg_rsapss_3072_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p256_supported: bool,
    pub is_tpm_alg_rsassa_4096_supported: bool,
    pub is_tpm_alg_rsapss_4096_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p384_supported: bool,
    pub is_tpm_alg_ecdsa_ecc_nist_p521_supported: bool,
    pub is_tpm_alg_sm2_ecc_sm2_p256_supported: bool,
    pub is_tpm_alg_eddsa_ed25519_supported: bool,
    pub is_tpm_alg_eddsa_ed448_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmKeyScheduleConfig {
    pub is_spdm_key_schedule_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmAlgorithmStructureConfig {
    pub dhe: SpdmDHEConfig,
    pub aead: SpdmAEADConfig,
    pub req_base_asym_alg: SpdmReqBaseAsymAlgConfig,
    pub key_schedule: SpdmKeyScheduleConfig,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmMeasurementHashAlgoConfig {
    pub is_raw_bit_stream_only: bool,
    pub is_tpm_alg_sha_256_supported: bool,
    pub is_tpm_alg_sha_384_supported: bool,
    pub is_tpm_alg_sha_512_supported: bool,
    pub is_tpm_alg_sha3_256_supported: bool,
    pub is_tpm_alg_sha3_384_supported: bool,
    pub is_tpm_alg_sha3_512_supported: bool,
    pub is_tpm_alg_sm3_256_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmAlgorithmConfig {
    pub measurement_specification: SpdmMeasurementSpecificationConfig,
    pub other_params_support: SpdmOtherParamsSupportConfig,
    pub base_asym_algo: SpdmBaseAsymAlgoConfig,
    pub base_hash_algo: SpdmBaseHashAlgoConfig,
    pub algorithm_structure: SpdmAlgorithmStructureConfig,
    pub measurement_hash_algo: SpdmMeasurementHashAlgoConfig,
    pub extended_algorithm: String,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmKeyExchangeConfig {
    pub is_secure_spdm_version_10_supported: bool,
    pub is_secure_spdm_version_11_supported: bool,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmPskExchangeConfig {
    pub max_psk_context_size: usize,
    pub max_psk_hint_size: usize,
}

#[derive(Debug, PartialEq, Deserialize)]
struct SpdmHeartbeatConfig {
    pub responder_heartbeat_period: u8,
}

#[derive(Debug, PartialEq, Deserialize)]
struct OtherBufferSizeConfig {
    pub max_single_certificate_chain_size: usize,
    pub all_certificate_chains_buffer_size: usize,
    pub all_measurements_buffer_size: usize,
}

macro_rules! TEMPLATE {
    () => {
"// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Automatically generated by build scripts.
// It is not intended for manual editing.
// Please kindly configure via etc/config.json instead.

/// =========== Configurable Constant from etc/config.json =============
pub const USER_IS_SPDM_VERSION_10_SUPPORTED: bool = {is_spdm_version_10_supported};
pub const USER_IS_SPDM_VERSION_11_SUPPORTED: bool = {is_spdm_version_11_supported};
pub const USER_IS_SPDM_VERSION_12_SUPPORTED: bool = {is_spdm_version_12_supported};
pub const SPDM_VERSION_COUNT: usize = {spdm_version_cnt};

pub const USER_REQ_CT_EXPONENT: u8 = {req_ct_exponent};
pub const USER_RSP_CT_EXPONENT: u8 = {rsp_ct_exponent};

pub const USER_IS_REQUESTER_CERT_CAP_SUPPORTED: bool = {is_requester_cert_cap_supported};
pub const USER_IS_REQUESTER_CHAL_CAP_SUPPORTED: bool = {is_requester_chal_cap_supported};
pub const USER_IS_REQUESTER_ENCRYPT_CAP_SUPPORTED: bool = {is_requester_encrypt_cap_supported};
pub const USER_IS_REQUESTER_MAC_CAP_SUPPORTED: bool = {is_requester_mac_cap_supported};
pub const USER_IS_REQUESTER_MUT_AUTH_CAP_SUPPORTED: bool = {is_requester_mut_auth_cap_supported};
pub const USER_IS_REQUESTER_KEY_EX_CAP_SUPPORTED: bool = {is_requester_key_ex_cap_supported};
pub const USER_IS_REQUESTER_PSK_CAP_SUPPORTED: bool = {is_requester_psk_cap_supported};
pub const USER_IS_REQUESTER_ENCAP_CAP_SUPPORTED: bool = {is_requester_encap_cap_supported};
pub const USER_IS_REQUESTER_HBEAT_CAP_SUPPORTED: bool = {is_requester_hbeat_cap_supported};
pub const USER_IS_REQUESTER_KEY_UPD_CAP_SUPPORTED: bool = {is_requester_key_upd_cap_supported};
pub const USER_IS_REQUESTER_HANDSHAKE_IN_THE_CLEAR_CAP_SUPPORTED: bool = {is_requester_handshake_in_the_clear_cap_supported};
pub const USER_IS_REQUESTER_PUB_KEY_ID_CAP_SUPPORTED: bool = {is_requester_pub_key_id_cap_supported};
pub const USER_IS_REQUESTER_CHUNK_CAP_SUPPORTED: bool = {is_requester_chunk_cap_supported};

pub const USER_IS_RESPONDER_CACHE_CAP_SUPPORTED: bool = {is_responder_cache_cap_supported};
pub const USER_IS_RESPONDER_CERT_CAP_SUPPORTED: bool = {is_responder_cert_cap_supported};
pub const USER_IS_RESPONDER_CHAL_CAP_SUPPORTED: bool = {is_responder_chal_cap_supported};
pub const USER_IS_RESPONDER_MEAS_WITHOUT_SIG_CAP_SUPPORTED: bool = {is_responder_meas_without_sig_cap_supported};
pub const USER_IS_RESPONDER_MEAS_WITH_SIG_CAP_SUPPORTED: bool = {is_responder_meas_with_sig_cap_supported};
pub const USER_IS_RESPONDER_MEAS_FRESH_CAP_SUPPORTED: bool = {is_responder_meas_fresh_cap_supported};
pub const USER_IS_RESPONDER_ENCRYPT_CAP_SUPPORTED: bool = {is_responder_encrypt_cap_supported};
pub const USER_IS_RESPONDER_MAC_CAP_SUPPORTED: bool = {is_responder_mac_cap_supported};
pub const USER_IS_RESPONDER_MUT_AUTH_CAP_SUPPORTED: bool = {is_responder_mut_auth_cap_supported};
pub const USER_IS_RESPONDER_KEY_EX_CAP_SUPPORTED: bool = {is_responder_key_ex_cap_supported};
pub const USER_IS_RESPONDER_PSK_CAP_SUPPORTED: bool = {is_responder_psk_cap_supported};
pub const USER_IS_RESPONDER_ENCAP_CAP_SUPPORTED: bool = {is_responder_encap_cap_supported};
pub const USER_IS_RESPONDER_HBEAT_CAP_SUPPORTED: bool = {is_responder_hbeat_cap_supported};
pub const USER_IS_RESPONDER_KEY_UPD_CAP_SUPPORTED: bool = {is_responder_key_upd_cap_supported};
pub const USER_IS_RESPONDER_HANDSHAKE_IN_THE_CLEAR_CAP_SUPPORTED: bool = {is_responder_handshake_in_the_clear_cap_supported};
pub const USER_IS_RESPONDER_PUB_KEY_ID_CAP_SUPPORTED: bool = {is_responder_pub_key_id_cap_supported};
pub const USER_IS_RESPONDER_CHUNK_CAP_SUPPORTED: bool = {is_responder_chunk_cap_supported};
pub const USER_IS_RESPONDER_ALIAS_CERT_CAP_SUPPORTED: bool = {is_responder_alias_cert_cap_supported};
pub const USER_IS_RESPONDER_SET_CERT_CAP_SUPPORTED: bool = {is_responder_set_cert_cap_supported};
pub const USER_IS_RESPONDER_CSR_CAP_SUPPORTED: bool = {is_responder_csr_cap_supported};
pub const USER_IS_RESPONDER_CERT_INSTALL_RESET_CAP_SUPPORTED: bool = {is_responder_cert_install_reset_cap_supported};

pub const USER_DATA_TRANSFER_SIZE: usize = {data_transfer_size};
pub const USER_MAX_SPDM_MSG_SIZE: usize = {max_spdm_msg_size};

pub const USER_IS_DMTF_DEFINE_MEASUREMENT_SPECIFICATION_SUPPORTED: bool = {is_dmtf_define_measurement_specification_supported};

pub const USER_IS_OPAQUE_DATA_FMT0_SUPPORTED: bool = {is_opaque_data_fmt0_supported};
pub const USER_IS_OPAQUE_DATA_FMT1_SUPPORTED: bool = {is_opaque_data_fmt1_supported};

pub const USER_IS_TPM_ALG_RSASSA_2048_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsassa_2048_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_RSAPSS_2048_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsapss_2048_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_RSASSA_3072_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsassa_3072_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_RSAPSS_3072_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsapss_3072_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P256_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p256_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_RSASSA_4096_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsassa_4096_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_RSAPSS_4096_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_rsapss_4096_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P384_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p384_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P521_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p521_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_SM2_ECC_SM2_P256_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_sm2_ecc_sm2_p256_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_EDDSA_ED25519_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_eddsa_ed25519_for_base_asym_algo_supported};
pub const USER_IS_TPM_ALG_EDDSA_ED448_FOR_BASE_AYSM_ALGO_SUPPORTED: bool = {is_tpm_alg_eddsa_ed448_for_base_asym_algo_supported};

pub const USER_IS_TPM_ALG_SHA_256_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha_256_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SHA_384_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha_384_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SHA_512_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha_512_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SHA3_256_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha3_256_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SHA3_384_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha3_384_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SHA3_512_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sha3_512_for_base_hash_algo_supported};
pub const USER_IS_TPM_ALG_SM3_256_FOR_BASE_HASH_ALGO_SUPPORTED: bool = {is_tpm_alg_sm3_256_for_base_hash_algo_supported};

pub const USER_IS_FFDHE2048_FOR_DHE_SUPPORTED: bool = {is_ffdhe2048_for_dhe_supported};
pub const USER_IS_FFDHE3072_FOR_DHE_SUPPORTED: bool = {is_ffdhe3072_for_dhe_supported};
pub const USER_IS_FFDHE4096_FOR_DHE_SUPPORTED: bool = {is_ffdhe4096_for_dhe_supported};
pub const USER_IS_SECP256R1_FOR_DHE_SUPPORTED: bool = {is_secp256r1_for_dhe_supported};
pub const USER_IS_SECP384R1_FOR_DHE_SUPPORTED: bool = {is_secp384r1_for_dhe_supported};
pub const USER_IS_SECP521R1_FOR_DHE_SUPPORTED: bool = {is_secp521r1_for_dhe_supported};
pub const USER_IS_SM2_P256_FOR_DHE_SUPPORTED: bool = {is_sm2_p256_for_dhe_supported};
pub const IS_DHE_STRUCTURE_ACTIVE: bool = {is_dhe_structure_active};

pub const USER_IS_AES_128_GCM_FOR_AEAD_SUPPORTED: bool = {is_aes_128_gcm_for_aead_supported};
pub const USER_IS_AES_256_GCM_FOR_AEAD_SUPPORTED: bool = {is_aes_256_gcm_for_aead_supported};
pub const USER_IS_CHACHA20_POLY1305_FOR_AEAD_SUPPORTED: bool = {is_chacha20_poly1305_for_aead_supported};
pub const USER_IS_AEAD_SM4_GCM_FOR_AEAD_SUPPORTED: bool = {is_aead_sm4_gcm_for_aead_supported};
pub const IS_AEAD_STRUCTURE_ACTIVE: bool = {is_aead_structure_active};

pub const USER_IS_TPM_ALG_RSASSA_2048_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsassa_2048_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_RSAPSS_2048_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsapss_2048_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_RSASSA_3072_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsassa_3072_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_RSAPSS_3072_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsapss_3072_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P256_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p256_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_RSASSA_4096_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsassa_4096_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_RSAPSS_4096_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_rsapss_4096_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P384_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p384_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_ECDSA_ECC_NIST_P521_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_ecdsa_ecc_nist_p521_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_SM2_ECC_SM2_P256_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_sm2_ecc_sm2_p256_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_EDDSA_ED25519_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_eddsa_ed25519_for_req_base_aysm_alg_supported};
pub const USER_IS_TPM_ALG_EDDSA_ED448_FOR_REQBASEASYMALG_SUPPORTED: bool = {is_tpm_alg_eddsa_ed448_for_req_base_aysm_alg_supported};
pub const IS_REQ_BASE_ASYM_ALG_STRUCTURE_ACTIVE: bool = {is_req_base_asym_alg_structure_active};

pub const USER_IS_SPDM_KEY_SCHEDULE_SUPPORTED: bool = {is_spdm_key_schedule_supported};
pub const IS_KEY_SCHEDULE_STRUCTURE_ACTIVE: bool = {is_key_schedule_structure_active};

pub const USER_IS_RAW_BIT_STREAM_ONLY_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_raw_bit_stream_only_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA_256_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha_256_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA_384_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha_384_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA_512_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha_512_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA3_256_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha3_256_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA3_384_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha3_384_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SHA3_512_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sha3_512_for_measurement_hash_supported};
pub const USER_IS_TPM_ALG_SM3_256_FOR_MEASUREMENT_HASH_SUPPORTED: bool = {is_tpm_alg_sm3_256_for_measurement_hash_supported};

pub const USER_MAX_SPDM_ALG_STRUCT_COUNT: usize = {spdm_alg_struct_count};

pub const USER_IS_SECURE_SPDM_VERSION_10_SUPPORTED: bool = {is_secure_spdm_version_10_supported};
pub const USER_IS_SECURE_SPDM_VERSION_11_SUPPORTED: bool = {is_secure_spdm_version_11_supported};

pub const USER_MAX_PSK_CONTEXT_SIZE: usize = {max_psk_context_size};
pub const USER_MAX_PSK_HINT_SIZE: usize = {max_psk_hint_size};

pub const USER_RESPONDER_HEARTBEAT_PERIOD: u8 = {responder_heartbeat_period};

/// =========== Not Configurable Constant =============
/// Below defines the minimal buffer size referred from
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.1.pdf
pub const MAX_SPDM_VERSION_COUNT: usize = 3; // 0x10, 0x11, 0x12;
pub const MAX_GET_VERSION_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4;
pub const MAX_VERSION_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 6 + 2 * MAX_SPDM_VERSION_COUNT;

pub const MAX_GET_CAPABILITIES_REQUEST_MESSAGE_BUFFER_SIZE: usize = 20;
pub const MAX_CAPABILITIES_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 20;

pub const MAX_EXTENDED_ALGORITHM_COUND_A_E_EXTALGCOUNT2_3_4_5: usize = 20;
pub const MAX_ALG_SUPPORTED_FIXEDALGCOUNT: usize = 14; // 1. [7:4] 4 bits; 2. +2 be the multiple of 4
pub const MAX_SPDM_ALG_STRUCT_COUNT: usize = 4;
pub const MAX_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BUFFER_SIZE: usize = 32
    + 4 * MAX_EXTENDED_ALGORITHM_COUND_A_E_EXTALGCOUNT2_3_4_5
    + 2
    + MAX_ALG_SUPPORTED_FIXEDALGCOUNT;
pub const MAX_ALGORITHMS_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 36
    + 4 * MAX_EXTENDED_ALGORITHM_COUND_A_E_EXTALGCOUNT2_3_4_5
    + 2
    + MAX_ALG_SUPPORTED_FIXEDALGCOUNT;

pub const MAX_HASH_SIZE: usize = {max_hash_size};
pub const MAX_CERT_SLOT: usize = 8;
pub const MAX_GET_DIGESTS_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4;
pub const MAX_DIGESTS_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4 + MAX_CERT_SLOT * MAX_HASH_SIZE;

pub const MAX_AEAD_HEADER_TAG_SIZE: usize = {max_aead_size};
pub const MAX_GET_CERTIFICATE_REQUEST_MESSAGE_BUFFER_SIZE: usize = 8;
pub const MAX_PORTION_LENGTH: usize = USER_MAX_SPDM_MSG_SIZE - 4 - MAX_AEAD_HEADER_TAG_SIZE;
pub const MAX_SPDM_CERT_CHAIN_DATA_SIZE: usize = {single_cert};
pub const MAX_CERTIFICATE_RESPONSE_MESSAGE_BUFFER_SIZE: usize = USER_MAX_SPDM_MSG_SIZE;
pub const ALL_CERTIFICATE_CHAINS_BUFFER_SIZE: usize = {all_cert};

pub const MAX_CHALLENGE_REQUEST_MESSAGE_BUFFER_SIZE: usize = 36;
pub const MAX_SIGNATURE_SIZE: usize = {max_sig_size};
pub const MAX_OPAQUE_DATA_LENGTH: usize = {max_opaque_data_size};
pub const MAX_CHALLENGE_AUTH_RESPONSE_MESSAGE_BUFFER_SIZE: usize =
    4 + MAX_HASH_SIZE + 32 + MAX_HASH_SIZE + 2 + MAX_OPAQUE_DATA_LENGTH + MAX_SIGNATURE_SIZE;

pub const MAX_NONCE_SIZE: usize = 32;
pub const MAX_GET_MEASUREMENTS_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4 + MAX_NONCE_SIZE + 1;
pub const MAX_MEASUREMENT_RECORD_DATA_SIZE: usize = USER_MAX_SPDM_MSG_SIZE
    - 42
    - MAX_OPAQUE_DATA_LENGTH
    - MAX_SIGNATURE_SIZE
    - MAX_AEAD_HEADER_TAG_SIZE;
pub const MAX_MEASUREMENTS_RESPONSE_MESSAGE_BUFFER_SIZE: usize = USER_MAX_SPDM_MSG_SIZE;
pub const ALL_MEASUREMENTS_BUFFER_SIZE: usize = {all_meas};

pub const MAX_ERROR_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 36;

pub const MAX_RESPOND_IF_READY_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4;

pub const MAX_VENDOR_ID_LEN_SIZE: usize = 255; // 1 bytes
pub const MAX_VENDOR_DEFINED_PAYLOAD_SIZE: usize =
    USER_MAX_SPDM_MSG_SIZE - 7 - MAX_VENDOR_ID_LEN_SIZE - 2 - MAX_AEAD_HEADER_TAG_SIZE;
pub const MAX_VENDOR_DEFINED_REQUEST_MESSAGE_BUFFER_SIZE: usize = USER_MAX_SPDM_MSG_SIZE;
pub const MAX_VENDOR_DEFINED_RESPONSE_MESSAGE_BUFFER_SIZE: usize = USER_MAX_SPDM_MSG_SIZE;

pub const MAX_EXCHANGE_DATA_SIZE: usize = {max_exchange_data_size};
pub const MAX_KEY_EXCHANGE_REQUEST_MESSAGE_BUFFER_SIZE: usize =
    40 + MAX_EXCHANGE_DATA_SIZE + 2 + MAX_OPAQUE_DATA_LENGTH;
pub const MAX_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 40
    + MAX_EXCHANGE_DATA_SIZE
    + MAX_HASH_SIZE
    + 2
    + MAX_OPAQUE_DATA_LENGTH
    + MAX_SIGNATURE_SIZE
    + MAX_HASH_SIZE;

pub const MAX_FINISH_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4 + MAX_SIGNATURE_SIZE + MAX_HASH_SIZE;
pub const MAX_FINISH_RSP_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4 + MAX_HASH_SIZE;

pub const MAX_PSK_KEY_EXCHANGE_REQUEST_MESSAGE_BUFFER_SIZE: usize =
    12 + USER_MAX_PSK_HINT_SIZE + USER_MAX_PSK_CONTEXT_SIZE + MAX_OPAQUE_DATA_LENGTH;
pub const MAX_PSK_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_BUFFER_SIZE: usize =
    12 + MAX_HASH_SIZE + USER_MAX_PSK_CONTEXT_SIZE + MAX_OPAQUE_DATA_LENGTH + MAX_HASH_SIZE;

pub const MAX_PSK_FINISH_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4 + MAX_HASH_SIZE;
pub const MAX_PSK_FINISH_RSP_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4;

pub const MAX_HEARTBEAT_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4;
pub const MAX_HEARTBEAT_ACK_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4;

pub const MAX_KEY_UPDATE_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4;
pub const MAX_KEY_UPDATE_ACK_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4;

pub const MAX_END_SESSION_REQUEST_MESSAGE_BUFFER_SIZE: usize = 4;
pub const MAX_END_SESSION_ACK_RESPONSE_MESSAGE_BUFFER_SIZE: usize = 4;

pub const MAX_MESSAGE_A_TRANSCRIPT_SIZE: usize = MAX_GET_VERSION_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_VERSION_RESPONSE_MESSAGE_BUFFER_SIZE
    + MAX_GET_CAPABILITIES_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_CAPABILITIES_RESPONSE_MESSAGE_BUFFER_SIZE
    + MAX_NEGOTIATE_ALGORITHMS_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_ALGORITHMS_RESPONSE_MESSAGE_BUFFER_SIZE;

pub const MAX_MESSAGE_B_TRANSCRIPT_SIZE: usize = MAX_GET_DIGESTS_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_DIGESTS_RESPONSE_MESSAGE_BUFFER_SIZE
    + USER_MAX_SPDM_MSG_SIZE
    + ALL_CERTIFICATE_CHAINS_BUFFER_SIZE;

pub const MAX_MESSAGE_C_TRANSCRIPT_SIZE: usize =
    MAX_CHALLENGE_REQUEST_MESSAGE_BUFFER_SIZE + MAX_CHALLENGE_AUTH_RESPONSE_MESSAGE_BUFFER_SIZE;

pub const MAX_MESSAGE_M_TRANSCRIPT_SIZE: usize =
    USER_MAX_SPDM_MSG_SIZE + ALL_MEASUREMENTS_BUFFER_SIZE;

pub const MAX_MESSAGE_M1M2_TRANSCRIPT_SIZE: usize =
    MAX_MESSAGE_A_TRANSCRIPT_SIZE + MAX_MESSAGE_B_TRANSCRIPT_SIZE + MAX_MESSAGE_C_TRANSCRIPT_SIZE;

pub const MAX_MESSAGE_L_TRANSCRIPT_SIZE: usize =
    MAX_MESSAGE_A_TRANSCRIPT_SIZE + MAX_MESSAGE_M_TRANSCRIPT_SIZE;

pub const MAX_MESSAGE_K_TRANSCRIPT_SIZE: usize = MAX_KEY_EXCHANGE_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_KEY_EXCHANGE_RSP_RESPONSE_MESSAGE_BUFFER_SIZE;

pub const MAX_MESSAGE_F_TRANSCRIPT_SIZE: usize = MAX_FINISH_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_FINISH_RSP_RESPONSE_MESSAGE_BUFFER_SIZE
    + MAX_PSK_FINISH_REQUEST_MESSAGE_BUFFER_SIZE
    + MAX_PSK_FINISH_RSP_RESPONSE_MESSAGE_BUFFER_SIZE;

pub const MAX_MESSAGE_A_CERT_K_F_TRANSCRIPT_SIZE: usize = MAX_MESSAGE_A_TRANSCRIPT_SIZE
    + MAX_SPDM_CERT_CHAIN_DATA_SIZE
    + MAX_MESSAGE_K_TRANSCRIPT_SIZE
    + MAX_MESSAGE_F_TRANSCRIPT_SIZE;

pub const MAX_MESSAGE_MEASUREMENT_TRANSCRIPT_SIZE: usize = MAX_MESSAGE_L_TRANSCRIPT_SIZE;

/// =========== Implementation specific ===========
pub const MAX_SPDM_SESSION_COUNT: usize = 4;
pub const SECURE_SPDM_VERSION: u8 = 0x11;
"
};
}

const SPDM_CONFIG_ENV: &str = "SPDM_CONFIG";
const SPDM_CONFIG_JSON_DEFAULT_PATH: &str = "etc/config.json";
const SPDM_CONFIG_RS_OUT_DIR: &str = "src";
const SPDM_CONFIG_RS_OUT_FILE_NAME: &str = "config.rs";

fn main() {
    // Read and parse the SPDM configuration file.
    let spdm_config_json_file_path =
        env::var(SPDM_CONFIG_ENV).unwrap_or_else(|_| SPDM_CONFIG_JSON_DEFAULT_PATH.to_string());
    let spdm_config_json_file =
        File::open(spdm_config_json_file_path).expect("The SPDM configuration file does not exist");
    let spdm_config: SpdmConfig = serde_json::from_reader(spdm_config_json_file)
        .expect("It is not a valid SPDM configuration file.");

    // Do sanity checks.
    spdm_config.validate_config();

    // Do calculation
    let mut max_hash_size = 0usize;
    let mut max_sig_size = 0usize;
    let max_opaque_data_size = 0x100usize; // todo
    let mut max_exchange_data_size = 0usize;
    let mut max_aead_size = 0usize;
    let mut spdm_alg_struct_count = 0usize;

    let mut spdm_version_cnt = 0;
    if spdm_config.spdm_version_config.is_spdm_version_10_supported {
        spdm_version_cnt += 1;
    }
    if spdm_config.spdm_version_config.is_spdm_version_11_supported {
        spdm_version_cnt += 1;
    }
    if spdm_config.spdm_version_config.is_spdm_version_12_supported {
        spdm_version_cnt += 1;
    }

    let mut is_dhe_structure_active = false;
    if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_ffdhe2048_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_ffdhe3072_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_ffdhe4096_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp256r1_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp384r1_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp521r1_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_sm2_p256_supported
    {
        is_dhe_structure_active = true;
    }

    let mut is_aead_structure_active = false;
    if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .aead
        .is_aead_sm4_gcm_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_aes_128_gcm_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_aes_256_gcm_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_chacha20_poly1305_supported
    {
        is_aead_structure_active = true;
    }

    let mut is_req_base_asym_alg_structure_active = false;
    if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .req_base_asym_alg
        .is_tpm_alg_ecdsa_ecc_nist_p256_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p384_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p521_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed25519_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed448_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_2048_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_3072_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_4096_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_2048_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_3072_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_4096_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_sm2_ecc_sm2_p256_supported
    {
        is_req_base_asym_alg_structure_active = true;
    }

    let mut is_key_schedule_structure_active = false;
    if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .key_schedule
        .is_spdm_key_schedule_supported
    {
        is_key_schedule_structure_active = true;
    }

    if spdm_config
        .spdm_algorithm_config
        .base_hash_algo
        .is_tpm_alg_sha3_512_supported
        || spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_512_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_512_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_512_supported
    {
        max_hash_size = 64;
    } else if spdm_config
        .spdm_algorithm_config
        .base_hash_algo
        .is_tpm_alg_sha3_384_supported
        || spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_384_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_384_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_384_supported
    {
        max_hash_size = 48;
    } else if spdm_config
        .spdm_algorithm_config
        .base_hash_algo
        .is_tpm_alg_sha3_256_supported
        || spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_256_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_256_supported
        || spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_256_supported
    {
        max_hash_size = 32;
    }

    if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_rsapss_4096_supported
        || spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_4096_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_4096_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_4096_supported
    {
        max_sig_size = 512;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_rsapss_3072_supported
        || spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_3072_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_3072_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_3072_supported
    {
        max_sig_size = 384;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_rsapss_2048_supported
        || spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_2048_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_2048_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_2048_supported
    {
        max_sig_size = 256;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_ecdsa_ecc_nist_p521_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p521_supported
    {
        max_sig_size = 132;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_eddsa_ed448_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed448_supported
    {
        max_sig_size = 114;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_ecdsa_ecc_nist_p384_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p384_supported
    {
        max_sig_size = 96;
    } else if spdm_config
        .spdm_algorithm_config
        .base_asym_algo
        .is_tpm_alg_ecdsa_ecc_nist_p256_supported
        || spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_eddsa_ed25519_supported
        || spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_sm2_ecc_sm2_p256_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p256_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed25519_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_sm2_ecc_sm2_p256_supported
    {
        max_sig_size = 64;
    }

    if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_ffdhe4096_supported
    {
        max_exchange_data_size = 512;
    } else if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_ffdhe3072_supported
    {
        max_exchange_data_size = 384;
    } else if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_ffdhe2048_supported
    {
        max_exchange_data_size = 256;
    } else if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_secp521r1_supported
    {
        max_exchange_data_size = 131;
    } else if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_secp384r1_supported
    {
        max_exchange_data_size = 96;
    } else if spdm_config
        .spdm_algorithm_config
        .algorithm_structure
        .dhe
        .is_secp256r1_supported
        || spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_sm2_p256_supported
    {
        max_exchange_data_size = 64;
    }

    if spdm_config
        .spdm_capabilities_config
        .requester_cap
        .is_requester_encrypt_cap_supported
        || spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_encrypt_cap_supported
    {
        assert!(
            is_dhe_structure_active,
            "Please add the DHE structure in config!"
        );
        assert!(
            is_aead_structure_active,
            "Please add the AEAD structure in config!"
        );
        assert!(
            is_key_schedule_structure_active,
            "Please add the key_schedule structure in config!"
        );
        if spdm_config.key_exchange.is_secure_spdm_version_11_supported {
            max_aead_size = 4 + 32/*sequence number, AES 256*/ + 2 + 2 + 32/*Random Data, Nonce*/ + 32/*Mac, Tag*/;
        }
    }

    if is_dhe_structure_active {
        spdm_alg_struct_count += 1;
    }
    if is_aead_structure_active {
        spdm_alg_struct_count += 1;
    }
    if is_req_base_asym_alg_structure_active {
        spdm_alg_struct_count += 1;
    }
    if is_key_schedule_structure_active {
        spdm_alg_struct_count += 1;
    }
    assert!(
        spdm_config.spdm_capabilities_config.max_spdm_msg_size
            > 0x40
                + max_hash_size * 2
                + max_sig_size
                + max_opaque_data_size
                + spdm_config.psk_exchange.max_psk_context_size
                + spdm_config.psk_exchange.max_psk_hint_size,
        "max_spdm_msg_size is too small!"
    );

    // Generate config.rs file from the template and JSON inputs, then write to fs.
    let mut to_generate = Vec::new();
    write!(
        &mut to_generate,
        TEMPLATE!(),
        is_spdm_version_10_supported = spdm_config.spdm_version_config.is_spdm_version_10_supported,
        is_spdm_version_11_supported = spdm_config.spdm_version_config.is_spdm_version_11_supported,
        is_spdm_version_12_supported = spdm_config.spdm_version_config.is_spdm_version_12_supported,
        spdm_version_cnt = spdm_version_cnt,
        req_ct_exponent = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .req_ct_exponent,
        is_requester_cert_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_cert_cap_supported,
        is_requester_chal_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_chal_cap_supported,
        is_requester_encrypt_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_encrypt_cap_supported,
        is_requester_mac_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_mac_cap_supported,
        is_requester_mut_auth_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_mut_auth_cap_supported,
        is_requester_key_ex_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_key_ex_cap_supported,
        is_requester_psk_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_psk_cap_supported,
        is_requester_encap_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_encap_cap_supported,
        is_requester_hbeat_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_hbeat_cap_supported,
        is_requester_key_upd_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_key_upd_cap_supported,
        is_requester_handshake_in_the_clear_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_handshake_in_the_clear_cap_supported,
        is_requester_pub_key_id_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_pub_key_id_cap_supported,
        is_requester_chunk_cap_supported = spdm_config
            .spdm_capabilities_config
            .requester_cap
            .is_requester_chunk_cap_supported,
        rsp_ct_exponent = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .rsp_ct_exponent,
        is_responder_cache_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_cache_cap_supported,
        is_responder_cert_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_cert_cap_supported,
        is_responder_chal_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_chal_cap_supported,
        is_responder_meas_without_sig_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_meas_without_sig_cap_supported,
        is_responder_meas_with_sig_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_meas_with_sig_cap_supported,
        is_responder_meas_fresh_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_meas_fresh_cap_supported,
        is_responder_encrypt_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_encrypt_cap_supported,
        is_responder_mac_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_mac_cap_supported,
        is_responder_mut_auth_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_mut_auth_cap_supported,
        is_responder_key_ex_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_key_ex_cap_supported,
        is_responder_psk_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_psk_cap_supported,
        is_responder_encap_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_encap_cap_supported,
        is_responder_hbeat_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_hbeat_cap_supported,
        is_responder_key_upd_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_key_upd_cap_supported,
        is_responder_handshake_in_the_clear_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_handshake_in_the_clear_cap_supported,
        is_responder_pub_key_id_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_pub_key_id_cap_supported,
        is_responder_chunk_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_chunk_cap_supported,
        is_responder_alias_cert_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_alias_cert_cap_supported,
        is_responder_set_cert_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_set_cert_cap_supported,
        is_responder_csr_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_csr_cap_supported,
        is_responder_cert_install_reset_cap_supported = spdm_config
            .spdm_capabilities_config
            .responder_cap
            .is_responder_cert_install_reset_cap_supported,
        data_transfer_size = spdm_config.spdm_capabilities_config.data_transfer_size,
        max_spdm_msg_size = spdm_config.spdm_capabilities_config.max_spdm_msg_size,
        is_dmtf_define_measurement_specification_supported = spdm_config
            .spdm_algorithm_config
            .measurement_specification
            .is_dmtf_define_measurement_specification_supported,
        is_opaque_data_fmt0_supported = spdm_config
            .spdm_algorithm_config
            .other_params_support
            .is_opaque_data_fmt0_supported,
        is_opaque_data_fmt1_supported = spdm_config
            .spdm_algorithm_config
            .other_params_support
            .is_opaque_data_fmt1_supported,
        is_tpm_alg_rsassa_2048_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_2048_supported,
        is_tpm_alg_rsapss_2048_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsapss_2048_supported,
        is_tpm_alg_rsassa_3072_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_3072_supported,
        is_tpm_alg_rsapss_3072_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsapss_3072_supported,
        is_tpm_alg_ecdsa_ecc_nist_p256_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_ecdsa_ecc_nist_p256_supported,
        is_tpm_alg_rsassa_4096_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsassa_4096_supported,
        is_tpm_alg_rsapss_4096_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_rsapss_4096_supported,
        is_tpm_alg_ecdsa_ecc_nist_p384_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_ecdsa_ecc_nist_p384_supported,
        is_tpm_alg_ecdsa_ecc_nist_p521_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_ecdsa_ecc_nist_p521_supported,
        is_tpm_alg_sm2_ecc_sm2_p256_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_sm2_ecc_sm2_p256_supported,
        is_tpm_alg_eddsa_ed25519_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_eddsa_ed25519_supported,
        is_tpm_alg_eddsa_ed448_for_base_asym_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_asym_algo
            .is_tpm_alg_eddsa_ed448_supported,
        is_tpm_alg_sha_256_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_256_supported,
        is_tpm_alg_sha_384_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_384_supported,
        is_tpm_alg_sha_512_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha_512_supported,
        is_tpm_alg_sha3_256_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha3_256_supported,
        is_tpm_alg_sha3_384_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha3_384_supported,
        is_tpm_alg_sha3_512_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sha3_512_supported,
        is_tpm_alg_sm3_256_for_base_hash_algo_supported = spdm_config
            .spdm_algorithm_config
            .base_hash_algo
            .is_tpm_alg_sm3_256_supported,
        is_ffdhe2048_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_ffdhe2048_supported,
        is_ffdhe3072_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_ffdhe3072_supported,
        is_ffdhe4096_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_ffdhe4096_supported,
        is_secp256r1_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp256r1_supported,
        is_secp384r1_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp384r1_supported,
        is_secp521r1_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_secp521r1_supported,
        is_sm2_p256_for_dhe_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .dhe
            .is_sm2_p256_supported,
        is_dhe_structure_active = is_dhe_structure_active,
        is_aes_128_gcm_for_aead_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_aes_128_gcm_supported,
        is_aes_256_gcm_for_aead_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_aes_256_gcm_supported,
        is_chacha20_poly1305_for_aead_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_chacha20_poly1305_supported,
        is_aead_sm4_gcm_for_aead_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .aead
            .is_aead_sm4_gcm_supported,
        is_aead_structure_active = is_aead_structure_active,
        is_tpm_alg_rsassa_2048_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_2048_supported,
        is_tpm_alg_rsapss_2048_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_2048_supported,
        is_tpm_alg_rsassa_3072_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_3072_supported,
        is_tpm_alg_rsapss_3072_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_3072_supported,
        is_tpm_alg_ecdsa_ecc_nist_p256_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p256_supported,
        is_tpm_alg_rsassa_4096_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsassa_4096_supported,
        is_tpm_alg_rsapss_4096_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_rsapss_4096_supported,
        is_tpm_alg_ecdsa_ecc_nist_p384_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p384_supported,
        is_tpm_alg_ecdsa_ecc_nist_p521_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_ecdsa_ecc_nist_p521_supported,
        is_tpm_alg_sm2_ecc_sm2_p256_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_sm2_ecc_sm2_p256_supported,
        is_tpm_alg_eddsa_ed25519_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed25519_supported,
        is_tpm_alg_eddsa_ed448_for_req_base_aysm_alg_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .req_base_asym_alg
            .is_tpm_alg_eddsa_ed448_supported,
        is_req_base_asym_alg_structure_active = is_req_base_asym_alg_structure_active,
        is_spdm_key_schedule_supported = spdm_config
            .spdm_algorithm_config
            .algorithm_structure
            .key_schedule
            .is_spdm_key_schedule_supported,
        is_key_schedule_structure_active = is_key_schedule_structure_active,
        is_raw_bit_stream_only_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_raw_bit_stream_only,
        is_tpm_alg_sha_256_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_256_supported,
        is_tpm_alg_sha_384_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_384_supported,
        is_tpm_alg_sha_512_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha_512_supported,
        is_tpm_alg_sha3_256_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_256_supported,
        is_tpm_alg_sha3_384_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_384_supported,
        is_tpm_alg_sha3_512_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sha3_512_supported,
        is_tpm_alg_sm3_256_for_measurement_hash_supported = spdm_config
            .spdm_algorithm_config
            .measurement_hash_algo
            .is_tpm_alg_sm3_256_supported,
        spdm_alg_struct_count = spdm_alg_struct_count,
        is_secure_spdm_version_10_supported =
            spdm_config.key_exchange.is_secure_spdm_version_10_supported,
        is_secure_spdm_version_11_supported =
            spdm_config.key_exchange.is_secure_spdm_version_11_supported,
        max_psk_context_size = spdm_config.psk_exchange.max_psk_context_size,
        max_psk_hint_size = spdm_config.psk_exchange.max_psk_hint_size,
        max_hash_size = max_hash_size,
        max_aead_size = max_aead_size,
        max_sig_size = max_sig_size,
        max_opaque_data_size = max_opaque_data_size,
        max_exchange_data_size = max_exchange_data_size,
        responder_heartbeat_period = spdm_config.heartbeat.responder_heartbeat_period,
        single_cert = spdm_config
            .other_buffer_size
            .max_single_certificate_chain_size,
        all_cert = spdm_config
            .other_buffer_size
            .all_certificate_chains_buffer_size,
        all_meas = spdm_config.other_buffer_size.all_measurements_buffer_size
    )
    .expect("Failed to generate configuration code from the template and JSON config");

    let dest_path = Path::new(SPDM_CONFIG_RS_OUT_DIR).join(SPDM_CONFIG_RS_OUT_FILE_NAME);
    fs::write(dest_path, to_generate).unwrap();

    // Re-run the build script if the files at the given paths or envs have changed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../Cargo.lock");
    println!("cargo:rerun-if-changed={}", SPDM_CONFIG_JSON_DEFAULT_PATH);
    println!("cargo:rerun-if-env-changed={}", SPDM_CONFIG_ENV);
}
