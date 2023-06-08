// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};

#[test]
fn test_case0_send_spdm_error() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    context.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
}
