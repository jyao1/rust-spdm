// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::common::SpdmConnectionState;
use spdmlib::requester::RequesterContext;
use spdmlib::{responder, secret};

#[test]
fn test_case0_send_receive_spdm_algorithm() {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );
    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    let status = requester.send_receive_spdm_algorithm().is_ok();
    assert!(status);
}
