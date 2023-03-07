// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod common;
use common::fake_device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve};
use common::shared_buffer::SharedBuffer;

use pcidoe_transport::PciDoeTransportEncap;
use spdmlib::protocol::SpdmMeasurementSummaryHashType;
use spdmlib::requester;
use spdmlib::responder;

#[test]
fn intergration_client_server() {
    spdmlib::crypto::asym_sign::register(common::crypto_callbacks::ASYM_SIGN_IMPL.clone());

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = &mut FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let transport_encap_responder = &mut PciDoeTransportEncap {};

    let (config_info, provision_info) = common::utils::rsp_create_info();
    let mut responder_context = responder::ResponderContext::new(config_info, provision_info);

    let device_io_requester = &mut FakeSpdmDeviceIo::new(
        &shared_buffer,
        &mut responder_context,
        transport_encap_responder,
        device_io_responder,
    );
    let transport_encap_requester = &mut PciDoeTransportEncap {};

    let (config_info, provision_info) = common::utils::req_create_info();
    let mut requester_context = requester::RequesterContext::new(config_info, provision_info);

    assert!(!requester_context
        .init_connection(transport_encap_requester, device_io_requester)
        .is_err());

    assert!(!requester_context
        .send_receive_spdm_digest(None, transport_encap_requester, device_io_requester)
        .is_err());

    assert!(!requester_context
        .send_receive_spdm_certificate(None, 0, transport_encap_requester, device_io_requester)
        .is_err());

    let result = requester_context.start_session(
        false,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        transport_encap_requester,
        device_io_requester,
    );
    assert!(result.is_ok());
    if let Ok(session_id) = result {
        log::info!(
            "\nSession established ... session_id is {:0x?}\n",
            session_id
        );
        log::info!("Key Information ...\n");

        let session = requester_context
            .common
            .get_session_via_id(session_id)
            .expect("get session failed!");
        let (request_direction, response_direction) = session.export_keys();
        log::info!(
            "request_direction.encryption_key {:0x?}\n",
            request_direction.encryption_key.as_ref()
        );
        log::info!(
            "request_direction.salt {:0x?}\n",
            request_direction.salt.as_ref()
        );
        log::info!(
            "response_direction.encryption_key {:0x?}\n",
            response_direction.encryption_key.as_ref()
        );
        log::info!(
            "response_direction.salt {:0x?}\n",
            response_direction.salt.as_ref()
        );
    } else {
        log::info!("\nSession session_id not got ????? \n");
    }
}
