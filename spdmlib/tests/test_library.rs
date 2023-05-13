mod common;

use codec::{u24, Codec};
use codec::{Reader, Writer};
use common::testlib::*;
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::config::{
    MAX_SPDM_CERT_CHAIN_DATA_SIZE, MAX_SPDM_MEASUREMENT_VALUE_LEN, MAX_SPDM_OPAQUE_SIZE,
};
use spdmlib::protocol::*;
use spdmlib::protocol::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertChain, SpdmCertChainData, SpdmDheAlgo,
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmDmtfMeasurementStructure, SpdmDmtfMeasurementType,
    SpdmMeasurementRecordStructure, SpdmMeasurementSpecification, SpdmSignatureStruct,
    ECDSA_ECC_NIST_P384_KEY_SIZE, SPDM_MAX_ASYM_KEY_SIZE, SPDM_MAX_DHE_KEY_SIZE,
    SPDM_MAX_HASH_SIZE,
};
use spdmlib::protocol::{SpdmDmtfMeasurementRepresentation, SpdmMeasurementBlockStructure};

#[test]
fn test_case0_spdm_opaque_struct() {
    let u8_slice = &mut [0u8; 2 + MAX_SPDM_OPAQUE_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmOpaqueStruct {
        data_size: MAX_SPDM_OPAQUE_SIZE as u16,
        data: [100u8; MAX_SPDM_OPAQUE_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(2 + MAX_SPDM_OPAQUE_SIZE, reader.left());
    let spdm_opaque_struct = SpdmOpaqueStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_opaque_struct.data_size, MAX_SPDM_OPAQUE_SIZE as u16);
    for i in 0..MAX_SPDM_OPAQUE_SIZE {
        assert_eq!(spdm_opaque_struct.data[i], 100);
    }
    assert_eq!(0, reader.left());
}

#[test]
fn test_case0_spdm_digest_struct() {
    let u8_slice = &mut [0u8; SPDM_MAX_HASH_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmDigestStruct {
        data_size: SPDM_MAX_HASH_SIZE as u16,
        data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_HASH_SIZE, reader.left());
    let spdm_digest_struct = SpdmDigestStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_digest_struct.data_size, SPDM_MAX_HASH_SIZE as u16);
    for i in 0..SPDM_MAX_HASH_SIZE {
        assert_eq!(spdm_digest_struct.data[i], 100u8);
    }
    assert_eq!(0, reader.left());
}
#[test]
fn test_case0_spdm_signature_struct() {
    let u8_slice = &mut [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmSignatureStruct {
        data_size: SPDM_MAX_ASYM_KEY_SIZE as u16,
        data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_ASYM_KEY_SIZE, reader.left());
    let spdm_signature_struct = SpdmSignatureStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_signature_struct.data_size, RSASSA_4096_KEY_SIZE as u16);
    for i in 0..RSASSA_4096_KEY_SIZE {
        assert_eq!(spdm_signature_struct.data[i], 100);
    }
}
#[test]
fn test_case0_spdm_cert_chain() {
    let u8_slice = &mut [0u8; 4 + SPDM_MAX_HASH_SIZE + MAX_SPDM_CERT_CHAIN_DATA_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmCertChain {
        root_hash: SpdmDigestStruct {
            data_size: SPDM_MAX_HASH_SIZE as u16,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        },
        cert_chain: SpdmCertChainData {
            data_size: MAX_SPDM_CERT_CHAIN_DATA_SIZE as u16,
            data: [100u8; MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        },
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(
        4 + SPDM_MAX_HASH_SIZE + MAX_SPDM_CERT_CHAIN_DATA_SIZE,
        reader.left()
    );
    let spdm_cert_chain = SpdmCertChain::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(
        spdm_cert_chain.root_hash.data_size,
        SHA512_DIGEST_SIZE as u16
    );
    for i in 0..SHA512_DIGEST_SIZE {
        assert_eq!(spdm_cert_chain.root_hash.data[i], 100);
    }
    assert_eq!(
        spdm_cert_chain.cert_chain.data_size,
        MAX_SPDM_CERT_CHAIN_DATA_SIZE as u16
    );
    for i in 0..MAX_SPDM_CERT_CHAIN_DATA_SIZE {
        assert_eq!(spdm_cert_chain.cert_chain.data[i], 100);
    }
}
#[test]
fn test_case0_spdm_measurement_record_structure() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    let spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
        index: 100u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SPDM_MAX_HASH_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SPDM_MAX_HASH_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        assert!(spdm_measurement_block_structure
            .encode(&mut measurement_record_data_writer)
            .is_ok());
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(512, reader.left());
    let measurement_record =
        SpdmMeasurementRecordStructure::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(measurement_record.number_of_blocks, 5);
}

#[test]
fn test_case1_spdm_measurement_record_structure() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    let spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
        index: 100u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SPDM_MAX_HASH_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SPDM_MAX_HASH_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        assert!(spdm_measurement_block_structure
            .encode(&mut measurement_record_data_writer)
            .is_ok());
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
}
#[test]
fn test_case0_spdm_dhe_exchange_struct() {
    let u8_slice = &mut [0u8; SPDM_MAX_DHE_KEY_SIZE];
    let mut writer = Writer::init(u8_slice);
    SpdmDheExchangeStruct::default();
    let value = SpdmDheExchangeStruct {
        data_size: SPDM_MAX_DHE_KEY_SIZE as u16,
        data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(SPDM_MAX_DHE_KEY_SIZE, reader.left());
    let spdm_dhe_exchange_struct =
        SpdmDheExchangeStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(
        spdm_dhe_exchange_struct.data_size,
        ECDSA_ECC_NIST_P384_KEY_SIZE as u16
    );
    for i in 0..ECDSA_ECC_NIST_P384_KEY_SIZE {
        assert_eq!(spdm_dhe_exchange_struct.data[i], 100);
    }
    assert_eq!(0, reader.left());
}
#[test]
fn test_case0_spdm_dmtf_measurement_structure() {
    let mut value = SpdmDmtfMeasurementStructure::default();
    let r#type = [
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
    ];
    let representation = [
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
    ];
    value.value_size = SPDM_MAX_HASH_SIZE as u16;
    value.value = [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    for i in 0..5 {
        value.r#type = r#type[i];
        if i < 2 {
            value.representation = representation[i];
        }
        let u8_slice = &mut [0u8; 3 + SPDM_MAX_HASH_SIZE];
        let mut writer = Writer::init(u8_slice);
        assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(3 + SPDM_MAX_HASH_SIZE, reader.left());
        let spdm_dmtf_measurement_structure =
            SpdmDmtfMeasurementStructure::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_dmtf_measurement_structure.r#type, r#type[i]);
        if i < 2 {
            assert_eq!(
                spdm_dmtf_measurement_structure.representation,
                representation[i]
            );
        }
        assert_eq!(
            spdm_dmtf_measurement_structure.value_size,
            SPDM_MAX_HASH_SIZE as u16
        );
        for j in 0..SPDM_MAX_HASH_SIZE {
            assert_eq!(spdm_dmtf_measurement_structure.value[j], 100);
        }
        assert_eq!(0, reader.left());
    }
}
#[test]
fn test_case0_spdm_measurement_block_structure() {
    let u8_slice = &mut [0u8; 4 + 3 + SPDM_MAX_HASH_SIZE];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmMeasurementBlockStructure {
        index: 100u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 3 + SPDM_MAX_HASH_SIZE as u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: SPDM_MAX_HASH_SIZE as u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

    assert!(value.spdm_encode(&mut context, &mut writer).is_ok());
    let mut reader = Reader::init(u8_slice);
    assert_eq!(4 + 3 + SPDM_MAX_HASH_SIZE, reader.left());
    let spdm_block_structure =
        SpdmMeasurementBlockStructure::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_block_structure.index, 100);
    assert_eq!(
        spdm_block_structure.measurement_specification,
        SpdmMeasurementSpecification::DMTF
    );
    assert_eq!(
        spdm_block_structure.measurement_size,
        3 + SPDM_MAX_HASH_SIZE as u16
    );
    assert_eq!(
        spdm_block_structure.measurement.r#type,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
    );
    assert_eq!(
        spdm_block_structure.measurement.representation,
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
    );
    assert_eq!(
        spdm_block_structure.measurement.value_size,
        SPDM_MAX_HASH_SIZE as u16
    );
    for i in 0..SPDM_MAX_HASH_SIZE {
        assert_eq!(spdm_block_structure.measurement.value[i], 100);
    }
    assert_eq!(0, reader.left());
}
