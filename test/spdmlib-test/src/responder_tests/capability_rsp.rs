// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};

#[test]
fn test_case0_handle_spdm_capability() {
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
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion11;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterVersion);

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion11,
        request_response_code: SpdmRequestResponseCode::SpdmRequestGetCapabilities,
    };
    assert!(value.encode(&mut writer).is_ok());
    let capabilities = &mut [0u8; 1024];
    let mut writer = Writer::init(capabilities);
    let value = SpdmGetCapabilitiesRequestPayload {
        ct_exponent: 7,
        flags: SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP,
        data_transfer_size: 0,
        max_spdm_msg_size: 0,
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
    let bytes = &mut [0u8; 1024];
    bytes.copy_from_slice(&spdm_message_header[0..]);
    bytes[2..].copy_from_slice(&capabilities[0..1022]);
    context.handle_spdm_capability(bytes);

    let rsp_capabilities = SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP;
    let data = context.common.runtime_info.message_a.as_ref();
    let u8_slice = &mut [0u8; 2048];
    for (i, data) in data.iter().enumerate() {
        u8_slice[i] = *data;
    }
    let mut reader = Reader::init(u8_slice);
    let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
    assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion11);
    assert_eq!(
        spdm_message_header.request_response_code,
        SpdmRequestResponseCode::SpdmRequestGetCapabilities
    );
    let capabilities_slice = &u8_slice[2..];
    let mut reader = Reader::init(capabilities_slice);
    let capabilities_request =
        SpdmGetCapabilitiesRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
    assert_eq!(capabilities_request.ct_exponent, 7);
    assert_eq!(
        capabilities_request.flags,
        SpdmRequestCapabilityFlags::CERT_CAP | SpdmRequestCapabilityFlags::CHAL_CAP
    );
    let spdm_message_slice = &u8_slice[12..];
    let mut reader = Reader::init(spdm_message_slice);
    let spdm_message: SpdmMessage =
        SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
    assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
    assert_eq!(
        spdm_message.header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseCapabilities
    );
    if let SpdmMessagePayload::SpdmCapabilitiesResponse(payload) = &spdm_message.payload {
        assert_eq!(payload.ct_exponent, 0);
        assert_eq!(payload.flags, rsp_capabilities);
    }
}
