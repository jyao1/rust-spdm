mod common;

use codec::{u24, Codec};
use codec::{Reader, Writer};
use spdmlib::common::opaque::*;
use spdmlib::common::SpdmCodec;
use spdmlib::config::{
    MAX_SPDM_CERT_CHAIN_DATA_SIZE, MAX_SPDM_MEASUREMENT_VALUE_LEN, MAX_SPDM_OPAQUE_SIZE,
};
use spdmlib::protocol::{
    SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmCertChain, SpdmCertChainData, SpdmDheAlgo,
    SpdmDheExchangeStruct, SpdmDigestStruct, SpdmDmtfMeasurementStructure, SpdmDmtfMeasurementType,
    SpdmMeasurementRecordStructure, SpdmMeasurementSpecification, SpdmSignatureStruct,
    SPDM_MAX_ASYM_KEY_SIZE, SPDM_MAX_DHE_KEY_SIZE, SPDM_MAX_HASH_SIZE,
};
use spdmlib::protocol::{SpdmDmtfMeasurementRepresentation, SpdmMeasurementBlockStructure};

use common::testlib::*;

#[test]
fn test_case0_spdm_opaque_struct() {
    let u8_slice = &mut [0u8; 68];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmOpaqueStruct {
        data_size: 64,
        data: [100u8; MAX_SPDM_OPAQUE_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();

    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(68, reader.left());
    let spdm_opaque_struct = SpdmOpaqueStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_opaque_struct.data_size, 64);
    for i in 0..64 {
        assert_eq!(spdm_opaque_struct.data[i], 100);
    }
    assert_eq!(2, reader.left());
}

#[test]
fn test_case0_spdm_digest_struct() {
    let u8_slice = &mut [0u8; 68];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmDigestStruct {
        data_size: 64,
        data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;
    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(68, reader.left());
    let spdm_digest_struct = SpdmDigestStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_digest_struct.data_size, 64);
    for i in 0..64 {
        assert_eq!(spdm_digest_struct.data[i], 100u8);
    }
    assert_eq!(4, reader.left());
}
#[test]
fn test_case0_spdm_signature_struct() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmSignatureStruct {
        data_size: 512,
        data: [100u8; SPDM_MAX_ASYM_KEY_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    context.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;

    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(512, reader.left());
    let spdm_signature_struct = SpdmSignatureStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_signature_struct.data_size, 512);
    for i in 0..512 {
        assert_eq!(spdm_signature_struct.data[i], 100);
    }
}
#[test]
fn test_case0_spdm_cert_chain() {
    let u8_slice = &mut [0u8; 4192];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmCertChain {
        root_hash: SpdmDigestStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        },
        cert_chain: SpdmCertChainData {
            data_size: 4096u16,
            data: [100u8; MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        },
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(4192, reader.left());
    let spdm_cert_chain = SpdmCertChain::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_cert_chain.root_hash.data_size, 64);
    for i in 0..64 {
        assert_eq!(spdm_cert_chain.root_hash.data[i], 100);
    }
    assert_eq!(spdm_cert_chain.cert_chain.data_size, 4096);
    for i in 0..4096 {
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
        measurement_size: 67u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: 64u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        spdm_measurement_block_structure.encode(&mut measurement_record_data_writer);
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();

    value.spdm_encode(&mut context, &mut writer);
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
        measurement_size: 67u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: 64u16,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let mut measurement_record_data = [0u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];
    let mut measurement_record_data_writer = Writer::init(&mut measurement_record_data);

    for _i in 0..5 {
        spdm_measurement_block_structure.encode(&mut measurement_record_data_writer);
    }

    let value = SpdmMeasurementRecordStructure {
        number_of_blocks: 5,
        measurement_record_length: u24::new(measurement_record_data_writer.used() as u32),
        measurement_record_data,
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    value.spdm_encode(&mut context, &mut writer);
}
#[test]
fn test_case0_spdm_dhe_exchange_struct() {
    let u8_slice = &mut [0u8; 512];
    let mut writer = Writer::init(u8_slice);
    SpdmDheExchangeStruct::default();
    let value = SpdmDheExchangeStruct {
        data_size: 512,
        data: [100u8; SPDM_MAX_DHE_KEY_SIZE],
    };

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    context.negotiate_info.dhe_sel = SpdmDheAlgo::FFDHE_4096;

    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(512, reader.left());
    let spdm_dhe_exchange_struct =
        SpdmDheExchangeStruct::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_dhe_exchange_struct.data_size, 512);
    for i in 0..512 {
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
    value.value_size = 64u16;
    value.value = [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN];

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    for i in 0..5 {
        value.r#type = r#type[i];
        if i < 2 {
            value.representation = representation[i];
        }
        let u8_slice = &mut [0u8; 68];
        let mut writer = Writer::init(u8_slice);
        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(68, reader.left());
        let spdm_dmtf_measurement_structure =
            SpdmDmtfMeasurementStructure::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_dmtf_measurement_structure.r#type, r#type[i]);
        if i < 2 {
            assert_eq!(
                spdm_dmtf_measurement_structure.representation,
                representation[i]
            );
        }
        assert_eq!(spdm_dmtf_measurement_structure.value_size, 64);
        for j in 0..64 {
            assert_eq!(spdm_dmtf_measurement_structure.value[j], 100);
        }
        assert_eq!(1, reader.left());
    }
}
#[test]
fn test_case0_spdm_measurement_block_structure() {
    let u8_slice = &mut [0u8; 80];
    let mut writer = Writer::init(u8_slice);
    let value = SpdmMeasurementBlockStructure {
        index: 100u8,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_size: 100u16,
        measurement: SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: 64,
            value: [100u8; MAX_SPDM_MEASUREMENT_VALUE_LEN],
        },
    };
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let my_spdm_device_io = &mut MySpdmDeviceIo;
    let mut context = new_context();
    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_512;

    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    assert_eq!(80, reader.left());
    let spdm_block_structure =
        SpdmMeasurementBlockStructure::spdm_read(&mut context, &mut reader).unwrap();
    assert_eq!(spdm_block_structure.index, 100);
    assert_eq!(
        spdm_block_structure.measurement_specification,
        SpdmMeasurementSpecification::DMTF
    );
    assert_eq!(spdm_block_structure.measurement_size, 100);
    assert_eq!(
        spdm_block_structure.measurement.r#type,
        SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
    );
    assert_eq!(
        spdm_block_structure.measurement.representation,
        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
    );
    assert_eq!(spdm_block_structure.measurement.value_size, 64);
    for i in 0..64 {
        assert_eq!(spdm_block_structure.measurement.value[i], 100);
    }
    assert_eq!(9, reader.left());
}
