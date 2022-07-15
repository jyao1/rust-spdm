use super::*;
// use crate::spdmlib::*;
// use spdmlib::common::*;
use spdmlib::message::SpdmMeasurementSpecification;
use spdmlib::message::SpdmVersion;
use spdmlib::message::*;

pub fn rsp_create_info() -> (common::SpdmConfigInfo, common::SpdmProvisionInfo) {
    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
        ],
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        //| SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP, // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: if USE_ECDH {
            SpdmDheAlgo::SECP_384_R1
        } else {
            SpdmDheAlgo::FFDHE_3072
        },
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = if USE_ECDSA {
        "test_key/EcP384/ca.cert.der"
    } else {
        "test_key/Rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(crate_dir.join(ca_file_path)).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/EcP384/inter.cert.der"
    } else {
        "test_key/Rsa3072/inter.cert.der"
    };
    let inter_cert =
        std::fs::read(crate_dir.join(inter_file_path)).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/EcP384/end_responder.cert.der"
    } else {
        "test_key/Rsa3072/end_responder.cert.der"
    };
    let leaf_cert =
        std::fs::read(crate_dir.join(leaf_file_path)).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    println!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: Some(my_cert_chain_data),
        my_cert_chain: None,
        peer_cert_chain_data: None,
        peer_cert_chain_root_hash: None,
        default_version: SpdmVersion::SpdmVersion12,
    };

    (config_info, provision_info)
}
