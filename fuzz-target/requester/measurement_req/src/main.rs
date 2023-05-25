// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    spdmlib::message::SpdmMeasurementOperation,
    *,
};
use spdmlib::common::SpdmConnectionState;
use spdmlib::message::*;
use spdmlib::protocol::*;

fn fuzz_send_receive_spdm_measurement(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();
    let (rsp_config_info1, rsp_provision_info1) = rsp_create_info();
    let (req_config_info1, req_provision_info1) = req_create_info();
    let (rsp_config_info2, rsp_provision_info2) = rsp_create_info();
    let (req_config_info2, req_provision_info2) = req_create_info();
    let (rsp_config_info3, rsp_provision_info3) = rsp_create_info();
    let (req_config_info3, req_provision_info3) = req_create_info();
    let (rsp_config_info4, rsp_provision_info4) = rsp_create_info();
    let (req_config_info4, req_provision_info4) = req_create_info();
    let (rsp_config_info5, rsp_provision_info5) = rsp_create_info();
    let (req_config_info5, req_provision_info5) = req_create_info();
    let (rsp_config_info6, rsp_provision_info6) = rsp_create_info();
    let (req_config_info6, req_provision_info6) = req_create_info();
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info3,
            rsp_provision_info3,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info3,
            req_provision_info3,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        requester.common.reset_runtime_info();
        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        spdmlib::secret::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request with SIGNATURE_REQUESTED attribute and SpdmMeasurementRequestAll operation.</p>'
    // -
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info1,
            rsp_provision_info1,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info1,
            req_provision_info1,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.peer_info.peer_cert_chain[0] = Some(RSP_CERT_CHAIN_BUFF);

        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>No peer cert chain set, but request with SIGNATURE_REQUESTED.</p><p>When requester receive measurements, it will verify signature and return error.</p>'
    // -
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info2,
            rsp_provision_info2,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info2,
            req_provision_info2,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request raw bit stream measurement and signature verification is not required.</p>'
    // -
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info4,
            rsp_provision_info4,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info4,
            req_provision_info4,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::RAW_BIT_STREAM_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request with empty attribute and unknown operation value.</p>'
    // -
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info5,
            rsp_provision_info5,
        );

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info5,
            req_provision_info5,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;
        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.reset_runtime_info();

        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::empty(),
            SpdmMeasurementOperation::Unknown(4),
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement response'
    // - description: '<p>Request measurement in a session.</p>'
    // -
    {
        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info6,
            rsp_provision_info6,
        );

        spdmlib::crypto::aead::register(FAKE_AEAD.clone());

        responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        responder.common.negotiate_info.req_ct_exponent_sel = 0;
        responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
        responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
        responder.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        responder
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        responder.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        responder.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;

        responder.common.session[0] = SpdmSession::new();
        responder.common.session[0].setup(4294836221).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            responder.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            responder.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        responder.common.reset_runtime_info();
        responder
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester =
            fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = requester::RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info6,
            req_provision_info6,
        );

        requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        requester.common.negotiate_info.req_ct_exponent_sel = 0;
        requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;
        requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
        requester.common.negotiate_info.rsp_capabilities_sel =
            SpdmResponseCapabilityFlags::CERT_CAP;

        requester
            .common
            .negotiate_info
            .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        requester.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        requester.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;

        requester.common.session[0] = SpdmSession::new();
        requester.common.session[0].setup(4294836221).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);

        #[cfg(feature = "hashed-transcript-data")]
        {
            let mut dhe_secret = SpdmDheFinalKeyStruct::default();
            dhe_secret.data_size = SpdmDheAlgo::SECP_384_R1.get_size();
            requester.common.session[0]
                .set_dhe_secret(SpdmVersion::SpdmVersion12, dhe_secret)
                .unwrap();
            requester.common.session[0].runtime_info.digest_context_th =
                spdmlib::crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        }

        requester.common.peer_info.peer_cert_chain[0] = Some(RSP_CERT_CHAIN_BUFF);

        requester.common.reset_runtime_info();
        let mut total_number = 0;
        let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
        let _ = requester.send_receive_spdm_measurement(
            Some(4294836221),
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        );
    }
}

#[cfg(not(feature = "use_libfuzzer"))]
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    spdmlib::secret::register(fuzzlib::secret::SECRET_IMPL_INSTANCE.clone());
    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [
                01, 00, 01, 00, 0x0c, 00, 00, 00, 11, 0xe0, 01, 04, 0x0a, 0xfc, 04, 0xa0, 63, 0x5c,
                0x2e, 0x6c, 0x4b, 0x62, 0xd6, 0xc0, 0x1c, 0xf5, 0xc5, 0xa1, 0xb0, 0x9f, 0xff, 0x5a,
                0x1a, 68, 0xab, 78, 0xb1, 0xea, 25, 0xa8, 94, 0x6b, 0xac, 0xf4, 00, 00, 00, 00,
            ];
            fuzz_send_receive_spdm_measurement(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_receive_spdm_measurement(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_measurement(data);
    });
}
