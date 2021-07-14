// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_measurement(fuzzdata: &[u8]) {
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


    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info   
    );

    let _ = requester.send_receive_spdm_digest().is_err();

    let _ = requester.send_receive_spdm_certificate(0).is_err();

    let _ = requester.send_receive_spdm_challenge(0, SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone).is_err();

    let _ = requester.send_receive_spdm_measurement(SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber, 0).is_err();
}

fn main() {
    // afl::fuzz!(|data: &[u8]| {
    //     fuzz_send_receive_spdm_challenge(data);
    // });
        fuzz_send_receive_spdm_measurement(&[1,2,3,4,5,6,7,8]);
}
