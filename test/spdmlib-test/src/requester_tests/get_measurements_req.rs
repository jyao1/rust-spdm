// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, get_rsp_cert_chain_buff};
use spdmlib::common::SpdmConnectionState;
use spdmlib::message::{SpdmMeasurementAttributes, SpdmMeasurementOperation};
use spdmlib::protocol::*;
use spdmlib::requester::RequesterContext;
use spdmlib::{config, responder, secret};

#[test]
fn test_case0_send_receive_spdm_measurement() {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    responder.common.negotiate_info.req_ct_exponent_sel = 0;
    responder.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

    responder.common.negotiate_info.rsp_ct_exponent_sel = 0;
    responder.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP;

    responder
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;

    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    #[cfg(not(feature = "hashed-transcript-data"))]
    let message_m = &[0];
    #[cfg(not(feature = "hashed-transcript-data"))]
    responder
        .common
        .runtime_info
        .message_m
        .append_message(message_m);
    responder.common.reset_runtime_info();
    responder.common.provision_info.my_cert_chain = [
        Some(SpdmCertChainBuffer {
            data_size: 512u16,
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ];
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    requester.common.negotiate_info.req_ct_exponent_sel = 0;
    requester.common.negotiate_info.req_capabilities_sel = SpdmRequestCapabilityFlags::CERT_CAP;

    requester.common.negotiate_info.rsp_ct_exponent_sel = 0;
    requester.common.negotiate_info.rsp_capabilities_sel = SpdmResponseCapabilityFlags::CERT_CAP;
    requester
        .common
        .negotiate_info
        .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    requester.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    requester.common.peer_info.peer_cert_chain[0] = Some(get_rsp_cert_chain_buff());
    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    requester.common.reset_runtime_info();

    let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber;
    let mut total_number: u8 = 0;
    let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
    let status = requester
        .send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            measurement_operation,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        )
        .is_ok();
    assert!(status);

    let measurement_operation = SpdmMeasurementOperation::SpdmMeasurementRequestAll;
    let status = requester
        .send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            measurement_operation,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        )
        .is_ok();
    assert!(status);

    let measurement_operation = SpdmMeasurementOperation::Unknown(5);
    let status = requester
        .send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            measurement_operation,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        )
        .is_ok();
    assert!(status);
}
