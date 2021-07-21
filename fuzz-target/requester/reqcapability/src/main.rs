// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_capability(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let message_a = [
        0x10, 0x84, 0x00, 0x00, 0x11, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x11,
    ];
    // version_rsp
    responder.common.reset_runtime_info();
    responder
        .common
        .runtime_info
        .message_a
        .append_message(&message_a);

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    // version_req
    requester.common.reset_runtime_info();
    requester
        .common
        .runtime_info
        .message_a
        .append_message(&message_a);

    let _ = requester
        .send_receive_spdm_capability();
}



fn main() {
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_receive_spdm_capability(data);
    });
}
