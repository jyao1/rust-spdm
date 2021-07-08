use super::*;

pub enum ReqProcess {
    ReqDigest(Vec<u8>),
    ReqCertificate(Vec<u8>),
}


pub fn req_create_info() -> (common::SpdmConfigInfo, common::SpdmProvisionInfo) {
    let config_info = common::SpdmConfigInfo {
        spdm_version: [SpdmVersion::SpdmVersion10, SpdmVersion::SpdmVersion11],
        req_capabilities: SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        //| SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP, // | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
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

    let mut peer_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let ca_file_path = if USE_ECDSA {
        "TestKey/EcP384/ca.cert.der"
    } else {
        "TestKey/Rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "TestKey/EcP384/inter.cert.der"
    } else {
        "TestKey/Rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "TestKey/EcP384/end_responder.cert.der"
    } else {
        "TestKey/Rsa3072/end_responder.cert.der"
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

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
    peer_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    peer_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    peer_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    peer_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: None,
        my_cert_chain: None,
        peer_cert_chain_data: Some(peer_cert_chain_data),
        peer_cert_chain_root_hash: None,
    };

    (config_info, provision_info)
}