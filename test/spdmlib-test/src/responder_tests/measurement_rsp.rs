// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::*;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmCodec;
use spdmlib::common::SpdmConnectionState;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};

#[test]
fn test_case0_handle_spdm_measurement() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.measurement_specification_sel =
        SpdmMeasurementSpecification::DMTF;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
    };
    assert!(value.encode(&mut writer).is_ok());

    let measurements_struct = &mut [0u8; 1024];
    let mut writer = Writer::init(measurements_struct);
    let value = SpdmGetMeasurementsRequestPayload {
        measurement_attributes: SpdmMeasurementAttributes::empty(),
        measurement_operation: SpdmMeasurementOperation::Unknown(5),
        nonce: SpdmNonceStruct {
            data: [100u8; SPDM_NONCE_SIZE],
        },
        slot_id: 0,
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

    let bytes = &mut [0u8; 1024];
    bytes.copy_from_slice(&spdm_message_header[0..]);
    bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
    context.handle_spdm_measurement(None, bytes);

    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        let data = context.common.runtime_info.message_m.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::Unknown(5)
        );

        let spdm_message_slice = &u8_slice[4..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseMeasurements
        );
        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            //assert_eq!(payload.number_of_measurement, 0);
            assert_eq!(payload.slot_id, 0);
            assert_eq!(payload.measurement_record.number_of_blocks, 1);
        }
    }
}

#[test]
fn test_case1_handle_spdm_measurement() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    context.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    context.common.negotiate_info.measurement_specification_sel =
        SpdmMeasurementSpecification::DMTF;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion10,
        request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
    };
    assert!(value.encode(&mut writer).is_ok());

    let measurements_struct = &mut [0u8; 1024];
    let mut writer = Writer::init(measurements_struct);
    let value = SpdmGetMeasurementsRequestPayload {
        measurement_attributes: SpdmMeasurementAttributes::empty(),
        measurement_operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
        nonce: SpdmNonceStruct {
            data: [100u8; SPDM_NONCE_SIZE],
        },
        slot_id: 0,
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

    let bytes = &mut [0u8; 1024];
    bytes.copy_from_slice(&spdm_message_header[0..]);
    bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
    context.handle_spdm_measurement(None, bytes);

    #[cfg(not(feature = "hashed-transcript-data"))]
    {
        let data = context.common.runtime_info.message_m.as_ref();
        let u8_slice = &mut [0u8; 2048];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut message_header_slice = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let spdm_struct_slice = &u8_slice[2..];
        let mut reader = Reader::init(spdm_struct_slice);
        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            get_measurements.measurement_attributes,
            SpdmMeasurementAttributes::empty()
        );
        assert_eq!(
            get_measurements.measurement_operation,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll
        );

        let spdm_message_slice = &u8_slice[4..];
        let mut reader = Reader::init(spdm_message_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseMeasurements
        );

        if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
            //assert_eq!(payload.number_of_measurement, 10);
            //if measurement_attributes == 0, it means responder donot need append signature,
            //and slot_id should be 0.
            assert_eq!(payload.slot_id, 0);
            assert_eq!(payload.measurement_record.number_of_blocks, 10);
        }
    }
}
