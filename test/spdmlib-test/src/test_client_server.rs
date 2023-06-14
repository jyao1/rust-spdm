// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{get_rsp_cert_chain_buff, req_create_info, rsp_create_info};
use spdmlib::protocol::{
    SpdmMeasurementSummaryHashType, SpdmReqAsymAlgo, SpdmRequestCapabilityFlags,
    SpdmResponseCapabilityFlags,
};
use spdmlib::requester;
use spdmlib::responder;

#[test]
fn intergration_client_server() {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let device_io_responder = &mut FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let transport_encap_responder = &mut PciDoeTransportEncap {};

    let (config_info, provision_info) = rsp_create_info();
    let mut responder_context = responder::ResponderContext::new(
        device_io_responder,
        transport_encap_responder,
        config_info,
        provision_info,
    );

    #[cfg(feature = "mut-auth")]
    {
        responder_context.common.negotiate_info.rsp_capabilities_sel |=
            SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
        responder_context.common.negotiate_info.req_capabilities_sel |=
            SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
    }

    let device_io_requester = &mut FakeSpdmDeviceIo::new(&shared_buffer, &mut responder_context);
    let transport_encap_requester = &mut PciDoeTransportEncap {};

    let (config_info, provision_info) = req_create_info();
    let mut requester_context = requester::RequesterContext::new(
        device_io_requester,
        transport_encap_requester,
        config_info,
        provision_info,
    );

    assert!(!requester_context.init_connection().is_err());

    assert!(!requester_context.send_receive_spdm_digest(None).is_err());

    assert!(!requester_context
        .send_receive_spdm_certificate(None, 0)
        .is_err());

    #[cfg(feature = "mut-auth")]
    {
        requester_context.common.negotiate_info.rsp_capabilities_sel |=
            SpdmResponseCapabilityFlags::MUT_AUTH_CAP;
        requester_context.common.negotiate_info.req_capabilities_sel |=
            SpdmRequestCapabilityFlags::MUT_AUTH_CAP;
        requester_context.common.negotiate_info.req_asym_sel =
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        requester_context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
    }

    let result = requester_context.start_session(
        false,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
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
