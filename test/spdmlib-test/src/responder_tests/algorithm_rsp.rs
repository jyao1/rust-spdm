// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::create_info;
use codec::{Codec, Reader, Writer};
use log::debug;
use spdmlib::common::*;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};

#[test]
fn test_case0_handle_spdm_algorithm() {
    let (config_info, provision_info) = create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

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
        .set_connection_state(SpdmConnectionState::SpdmConnectionAfterCapabilities);

    let spdm_message_header = &mut [0u8; 1024];
    let mut writer = Writer::init(spdm_message_header);
    let value = SpdmMessageHeader {
        version: SpdmVersion::SpdmVersion11,
        request_response_code: SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms,
    };
    assert!(value.encode(&mut writer).is_ok());

    let negotiate_algorithms = &mut [0u8; 1024];
    let mut writer = Writer::init(negotiate_algorithms);
    let value = SpdmNegotiateAlgorithmsRequestPayload {
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        other_params_support: SpdmOpaqueSupport::empty(),
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        alg_struct_count: 4,
        alg_struct: [
            SpdmAlgStruct {
                alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
            },
            SpdmAlgStruct {
                alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                alg_supported: SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM),
            },
            SpdmAlgStruct {
                alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                    SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ),
            },
            SpdmAlgStruct {
                alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                alg_supported: SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE),
            },
        ],
    };
    assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

    let bytes = &mut [0u8; 1024];
    bytes.copy_from_slice(&spdm_message_header[0..]);
    bytes[2..].copy_from_slice(&negotiate_algorithms[0..1022]);

    context.handle_spdm_algorithm(bytes);

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
        SpdmRequestResponseCode::SpdmRequestNegotiateAlgorithms
    );
    debug!("u8_slice: {:02X?}\n", u8_slice);
    let u8_slice = &u8_slice[2..];
    debug!("u8_slice: {:02X?}\n", u8_slice);
    let mut reader = Reader::init(u8_slice);
    let spdm_sturct_data =
        SpdmNegotiateAlgorithmsRequestPayload::spdm_read(&mut context.common, &mut reader).unwrap();
    assert_eq!(
        spdm_sturct_data.measurement_specification,
        SpdmMeasurementSpecification::DMTF
    );
    assert_eq!(
        spdm_sturct_data.base_asym_algo,
        SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
    );
    assert_eq!(
        spdm_sturct_data.base_hash_algo,
        SpdmBaseHashAlgo::TPM_ALG_SHA_384
    );
    assert_eq!(spdm_sturct_data.alg_struct_count, 4);
    assert_eq!(
        spdm_sturct_data.alg_struct[0].alg_type,
        SpdmAlgType::SpdmAlgTypeDHE
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[0].alg_supported,
        SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[1].alg_type,
        SpdmAlgType::SpdmAlgTypeAEAD
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[1].alg_supported,
        SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::AES_128_GCM)
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[2].alg_type,
        SpdmAlgType::SpdmAlgTypeReqAsym
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[2].alg_supported,
        SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,)
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[3].alg_type,
        SpdmAlgType::SpdmAlgTypeKeySchedule
    );
    assert_eq!(
        spdm_sturct_data.alg_struct[3].alg_supported,
        SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,)
    );

    let u8_slice = &u8_slice[46..];
    debug!("u8_slice: {:02X?}\n", u8_slice);
    let mut reader = Reader::init(u8_slice);
    let spdm_message: SpdmMessage =
        SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

    assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion11);
    assert_eq!(
        spdm_message.header.request_response_code,
        SpdmRequestResponseCode::SpdmResponseAlgorithms
    );
    if let SpdmMessagePayload::SpdmAlgorithmsResponse(payload) = &spdm_message.payload {
        assert_eq!(
            payload.measurement_specification_sel,
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(
            payload.measurement_hash_algo,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384
        );
        assert_eq!(
            payload.base_asym_sel,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        );
        assert_eq!(payload.base_hash_sel, SpdmBaseHashAlgo::TPM_ALG_SHA_384);
        assert_eq!(payload.alg_struct_count, 4);

        assert_eq!(payload.alg_struct[0].alg_type, SpdmAlgType::SpdmAlgTypeDHE);
        assert_eq!(
            payload.alg_struct[0].alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::empty())
        );

        assert_eq!(payload.alg_struct[1].alg_type, SpdmAlgType::SpdmAlgTypeAEAD);
        assert_eq!(
            payload.alg_struct[1].alg_supported,
            SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::empty())
        );

        assert_eq!(
            payload.alg_struct[2].alg_type,
            SpdmAlgType::SpdmAlgTypeReqAsym
        );
        assert_eq!(
            payload.alg_struct[2].alg_supported,
            SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::empty())
        );

        assert_eq!(
            payload.alg_struct[3].alg_type,
            SpdmAlgType::SpdmAlgTypeKeySchedule
        );
        assert_eq!(
            payload.alg_struct[3].alg_supported,
            SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE)
        );
    }
}
