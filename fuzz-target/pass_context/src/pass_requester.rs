// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
use spdmlib::protocol::SpdmMeasurementSummaryHashType;

pub fn fuzz_total_requesters() {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    if requester.init_connection().is_err() {
        return;
    }

    if requester.send_receive_spdm_digest(None).is_err() {
        return;
    }

    if requester.send_receive_spdm_certificate(None, 0).is_err() {
        return;
    }

    let result = requester.start_session(
        false,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    );
    if let Ok(session_id) = result {
        log::info!(
            "\nSession established ... session_id is {:0x?}\n",
            session_id
        );
        log::info!("Key Information ...\n");

        let session = requester.common.get_session_via_id(session_id).unwrap();
        let (request_direction, response_direction) = session.export_keys();
        log::info!(
            "equest_direction.encryption_key {:0x?}\n",
            request_direction.encryption_key.as_ref()
        );
        log::info!(
            "equest_direction.salt {:0x?}\n",
            request_direction.salt.as_ref()
        );
        log::info!(
            "esponse_direction.encryption_key {:0x?}\n",
            response_direction.encryption_key.as_ref()
        );
        log::info!(
            "esponse_direction.salt {:0x?}\n",
            response_direction.salt.as_ref()
        );
    } else {
        log::info!("\nSession session_id not got ????? \n");
    }
}
