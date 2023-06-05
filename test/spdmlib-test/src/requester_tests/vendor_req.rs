// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIo, FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::message::{
    RegistryOrStandardsBodyID, VendorDefinedReqPayloadStruct, VendorIDStruct,
    MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};
use spdmlib::requester::RequesterContext;
use spdmlib::responder::ResponderContext;
use spdmlib::{config, secret};

#[test]
fn test_case0_send_spdm_vendor_defined_request() {
    let (rsp_config_info, rsp_provision_info) = create_info();
    let (req_config_info, req_provision_info) = create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut responder = ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    let session_id: u32 = 0xff;
    let standard_id: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::DMTF;
    let vendor_idstruct: VendorIDStruct = VendorIDStruct {
        len: 0,
        vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
    };
    let req_payload_struct: VendorDefinedReqPayloadStruct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; config::MAX_SPDM_MSG_SIZE - 7 - 2],
    };

    let status = requester
        .send_spdm_vendor_defined_request(
            Some(session_id),
            standard_id,
            vendor_idstruct,
            req_payload_struct,
        )
        .is_ok();
    assert_eq!(status, false); //since vendor defined response payload is not implemented, so false is expected here.
}
