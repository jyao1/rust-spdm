// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Writer};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, responder, secret};

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_digest() {
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
    context.common.provision_info.my_cert_chain = [
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
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
    };
    assert!(value.encode(&mut writer).is_ok());

    let bytes = &mut [0u8; 1024];
    context.handle_spdm_digest(bytes, None);
}
