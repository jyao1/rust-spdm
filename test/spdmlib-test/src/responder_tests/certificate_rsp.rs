// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Writer};
use spdmlib::common::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{config, responder, secret};

#[test]
#[cfg(feature = "hashed-transcript-data")]
fn test_case0_handle_spdm_certificate() {
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

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
    };
    assert!(value.encode(&mut writer).is_ok());
    let capabilities = &mut [0u8; 1024];
    let mut writer = Writer::init(capabilities);
    let value = SpdmGetCertificateRequestPayload {
        slot_id: 100,
        offset: 100,
        length: 600,
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());
    let bytes = &mut [0u8; 1024];
    bytes.copy_from_slice(&spdm_message_header[0..]);
    bytes[2..].copy_from_slice(&capabilities[0..1022]);
    context.handle_spdm_certificate(bytes, None);

    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        let data = context.common.runtime_info.message_b.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestGetCertificate
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let spdm_get_certificate_request_payload =
            SpdmGetCertificateRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_get_certificate_request_payload.slot_id, 100);
        assert_eq!(spdm_get_certificate_request_payload.offset, 100);
        assert_eq!(spdm_get_certificate_request_payload.length, 600);

        let spdm_message_slice = &u8_slice[8..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseCertificate
        );
        if let SpdmMessagePayload::SpdmCertificateResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.slot_id, 100);
            assert_eq!(payload.portion_length, 412);
            assert_eq!(payload.remainder_length, 0);
            for i in 0..412 {
                assert_eq!(payload.cert_chain[i], 0u8);
            }
        }
    }
}
