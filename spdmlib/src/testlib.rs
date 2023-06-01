// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]

use crate::common::key_schedule::SpdmKeySchedule;
use crate::common::*;
use crate::config;
use crate::crypto;
use crate::crypto::{hash, SpdmCryptoRandom, SpdmHmac};
pub use crate::protocol::*;
use crate::secret::SpdmSecretAsymSign;
use crate::secret::SpdmSecretMeasurement;
use crate::secret::SpdmSecretPsk;
use crate::{common, responder};

use crate::error::{
    SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_FAIL, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use codec::enum_builder;
use codec::{u24, Codec, Reader, Writer};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;

pub fn get_test_key_directory() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = crate_dir.parent().expect("can't find parent dir");
    crate_dir.to_path_buf()
}

pub fn new_context<'a>(
    my_spdm_device_io: &'a mut MySpdmDeviceIo,
    pcidoe_transport_encap: &'a mut PciDoeTransportEncap,
) -> SpdmContext<'a> {
    let (config_info, provision_info) = create_info();
    let mut context = SpdmContext::new(
        my_spdm_device_io,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
    context.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
    context
}

pub fn new_spdm_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
    let u8_slice = &mut [0u8; 1000];
    let mut writer = Writer::init(u8_slice);
    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
    spdm_message
}

pub fn create_info() -> (common::SpdmConfigInfo, common::SpdmProvisionInfo) {
    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
        ],
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
            | SpdmResponseCapabilityFlags::CHAL_CAP
            | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
            | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
            | SpdmResponseCapabilityFlags::ENCRYPT_CAP
            | SpdmResponseCapabilityFlags::MAC_CAP
            | SpdmResponseCapabilityFlags::KEY_EX_CAP
            | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
            | SpdmResponseCapabilityFlags::ENCAP_CAP
            | SpdmResponseCapabilityFlags::HBEAT_CAP
            | SpdmResponseCapabilityFlags::KEY_UPD_CAP,
        req_capabilities: SpdmRequestCapabilityFlags::CERT_CAP
            | SpdmRequestCapabilityFlags::ENCRYPT_CAP
            | SpdmRequestCapabilityFlags::MAC_CAP
            | SpdmRequestCapabilityFlags::KEY_EX_CAP
            | SpdmRequestCapabilityFlags::ENCAP_CAP
            | SpdmRequestCapabilityFlags::HBEAT_CAP
            | SpdmRequestCapabilityFlags::KEY_UPD_CAP,
        rsp_ct_exponent: 0,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,

        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: 0x1200,
        max_spdm_msg_size: 0x1200,
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };
    let mut peer_root_cert_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = crate_dir.join("test_key/EcP384/ca.cert.der");
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = crate_dir.join("test_key/EcP384/inter.cert.der");
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = crate_dir.join("test_key/EcP384/end_responder.cert.der");
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();

    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    peer_root_cert_data.data_size = (ca_len) as u16;
    peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: [
            Some(my_cert_chain_data.clone()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
        my_cert_chain: [None, None, None, None, None, None, None, None],
        peer_root_cert_data: Some(peer_root_cert_data),
    };

    (config_info, provision_info)
}

pub struct MySpdmDeviceIo;

impl SpdmDeviceIo for MySpdmDeviceIo {
    fn send(&mut self, _buffer: &[u8]) -> SpdmResult {
        todo!()
    }

    fn receive(&mut self, _buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        todo!()
    }

    fn flush_all(&mut self) -> SpdmResult {
        todo!()
    }
}

enum_builder! {
    @U16
    EnumName: PciDoeVendorId;
    EnumVal{
        PciDoeVendorIdPciSig => 0x0001
    }
}
impl Default for PciDoeVendorId {
    fn default() -> PciDoeVendorId {
        PciDoeVendorId::Unknown(0)
    }
}

enum_builder! {
    @U8
    EnumName: PciDoeDataObjectType;
    EnumVal{
        PciDoeDataObjectTypeDoeDiscovery => 0x00,
        PciDoeDataObjectTypeSpdm => 0x01,
        PciDoeDataObjectTypeSecuredSpdm => 0x02
    }
}
impl Default for PciDoeDataObjectType {
    fn default() -> PciDoeDataObjectType {
        PciDoeDataObjectType::Unknown(0)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PciDoeMessageHeader {
    pub vendor_id: PciDoeVendorId,
    pub data_object_type: PciDoeDataObjectType,
    pub payload_length: u32, // in bytes
}

impl Codec for PciDoeMessageHeader {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.vendor_id.encode(bytes)?;
        cnt += self.data_object_type.encode(bytes)?;
        cnt += 0u8.encode(bytes)?;
        let mut length = (self.payload_length + 8) >> 2;
        if length > 0x40000 {
            panic!();
        }
        if length == 0x40000 {
            length = 0;
        }
        cnt += length.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<PciDoeMessageHeader> {
        let vendor_id = PciDoeVendorId::read(r)?;
        let data_object_type = PciDoeDataObjectType::read(r)?;
        u8::read(r)?;
        let mut length = u32::read(r)?;
        length &= 0x3ffff;
        if length == 0 {
            length = 0x40000;
        }
        if length < 2 {
            return None;
        }
        let payload_length = (length << 2).checked_sub(8)?;
        Some(PciDoeMessageHeader {
            vendor_id,
            data_object_type,
            payload_length,
        })
    }
}
pub struct PciDoeTransportEncap {}

impl SpdmTransportEncap for PciDoeTransportEncap {
    fn encap(
        &mut self,
        spdm_buffer: &[u8],
        transport_buffer: &mut [u8],
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let aligned_payload_len = (payload_len + 3) / 4 * 4;
        let mut writer = Writer::init(&mut *transport_buffer);
        let pcidoe_header = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: if secured_message {
                PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm
            } else {
                PciDoeDataObjectType::PciDoeDataObjectTypeSpdm
            },
            payload_length: aligned_payload_len as u32,
        };
        pcidoe_header
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_ENCAP_FAIL)?;
        let header_size = writer.used();
        if transport_buffer.len() < header_size + aligned_payload_len {
            return Err(SPDM_STATUS_ENCAP_FAIL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + aligned_payload_len)
    }

    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(transport_buffer);
        let pcidoe_header: PciDoeMessageHeader =
            PciDoeMessageHeader::read(&mut reader).ok_or(SPDM_STATUS_DECAP_FAIL)?;
        match pcidoe_header.vendor_id {
            PciDoeVendorId::PciDoeVendorIdPciSig => {}
            _ => return Err(SPDM_STATUS_DECAP_FAIL),
        }
        let secured_message = match pcidoe_header.data_object_type {
            PciDoeDataObjectType::PciDoeDataObjectTypeSpdm => false,
            PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm => true,
            _ => return Err(SPDM_STATUS_DECAP_FAIL),
        };
        let header_size = reader.used();
        let payload_size = pcidoe_header.payload_length as usize;
        if transport_buffer.len() < header_size + payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..(header_size + payload_size)];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    fn encap_app(
        &mut self,
        spdm_buffer: &[u8],
        app_buffer: &mut [u8],
        _is_app_message: bool,
    ) -> SpdmResult<usize> {
        app_buffer[0..spdm_buffer.len()].copy_from_slice(spdm_buffer);
        Ok(spdm_buffer.len())
    }

    fn decap_app(
        &mut self,
        app_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        spdm_buffer[0..app_buffer.len()].copy_from_slice(app_buffer);
        Ok((app_buffer.len(), false))
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        0
    }
    fn get_max_random_count(&mut self) -> u16 {
        0
    }
}

pub static SECRET_ASYM_IMPL_INSTANCE: SpdmSecretAsymSign =
    SpdmSecretAsymSign { sign_cb: asym_sign };

fn asym_sign(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
            sign_ecdsa_asym_algo(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, data)
        }
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => {
            sign_ecdsa_asym_algo(&ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING, data)
        }
        _ => {
            panic!();
        }
    }
}

fn sign_ecdsa_asym_algo(
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    let crate_dir = get_test_key_directory();
    let key_file_path = crate_dir.join("test_key/EcP384/end_responder.key.p8");
    let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
    let key_bytes = der_file.as_slice();

    let key_pair: ring::signature::EcdsaKeyPair =
        ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_bytes).unwrap();

    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data).unwrap();
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_KEY_SIZE] = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
}

pub static SECRET_MEASUREMENT_IMPL_INSTANCE: SpdmSecretMeasurement = SpdmSecretMeasurement {
    measurement_collection_cb: measurement_collection_impl,
    generate_measurement_summary_hash_cb: generate_measurement_summary_hash_impl,
};

#[allow(clippy::field_reassign_with_default)]
fn measurement_collection_impl(
    spdm_version: SpdmVersion,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_index: usize,
) -> Option<SpdmMeasurementRecordStructure> {
    if measurement_specification != SpdmMeasurementSpecification::DMTF {
        None
    } else {
        let base_hash_algo = match measurement_hash_algo {
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_256 => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384 => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_512 => SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_256
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_384
            | SpdmMeasurementHashAlgo::TPM_ALG_SHA3_512
            | SpdmMeasurementHashAlgo::TPM_ALG_SM3 => return None,
            _ => return None,
        };
        let hashsize = base_hash_algo.get_size();
        if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize
        {
            let mut dummy_spdm_measurement_record_structure =
                SpdmMeasurementRecordStructure::default();
            dummy_spdm_measurement_record_structure.number_of_blocks = 10;
            Some(dummy_spdm_measurement_record_structure)
        } else if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize
        {
            let mut firmware1: [u8; 8] = [0; 8];
            let mut firmware2: [u8; 8] = [0; 8];
            let mut firmware3: [u8; 8] = [0; 8];
            let mut firmware4: [u8; 8] = [0; 8];
            let mut firmware5: [u8; 8] = [0; 8];
            let mut firmware6: [u8; 8] = [0; 8];
            let mut firmware7: [u8; 8] = [0; 8];
            let mut firmware8: [u8; 8] = [0; 8];
            let mut firmware9: [u8; 8] = [0; 8];
            let mut firmware10: [u8; 8] = [0; 8];
            firmware1.copy_from_slice("deadbeef".as_bytes());
            firmware2.copy_from_slice("eadbeefd".as_bytes());
            firmware3.copy_from_slice("adbeefde".as_bytes());
            firmware4.copy_from_slice("dbeefdea".as_bytes());
            firmware5.copy_from_slice("beefdead".as_bytes());
            firmware6.copy_from_slice("deadbeef".as_bytes());
            firmware7.copy_from_slice("eadbeefd".as_bytes());
            firmware8.copy_from_slice("adbeefde".as_bytes());
            firmware9.copy_from_slice("dbeefdea".as_bytes());
            firmware10.copy_from_slice("beefdead".as_bytes());
            let digest1 = hash::hash_all(base_hash_algo, &firmware1).expect("hash_all failed!");
            let digest2 = hash::hash_all(base_hash_algo, &firmware2).expect("hash_all failed!");
            let digest3 = hash::hash_all(base_hash_algo, &firmware3).expect("hash_all failed!");
            let digest4 = hash::hash_all(base_hash_algo, &firmware4).expect("hash_all failed!");
            let digest5 = hash::hash_all(base_hash_algo, &firmware5).expect("hash_all failed!");
            let digest6 = hash::hash_all(base_hash_algo, &firmware6).expect("hash_all failed!");
            let digest7 = hash::hash_all(base_hash_algo, &firmware7).expect("hash_all failed!");
            let digest8 = hash::hash_all(base_hash_algo, &firmware8).expect("hash_all failed!");
            let digest9 = hash::hash_all(base_hash_algo, &firmware9).expect("hash_all failed!");
            let digest10 = hash::hash_all(base_hash_algo, &firmware10).expect("hash_all failed!");
            let mut digest_value1: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value2: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value3: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value4: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value5: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value6: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value7: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value8: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value9: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            let mut digest_value10: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            digest_value1[..64].copy_from_slice(digest1.data.as_ref());
            digest_value2[..64].copy_from_slice(digest2.data.as_ref());
            digest_value3[..64].copy_from_slice(digest3.data.as_ref());
            digest_value4[..64].copy_from_slice(digest4.data.as_ref());
            digest_value5[..64].copy_from_slice(digest5.data.as_ref());
            digest_value6[..64].copy_from_slice(digest6.data.as_ref());
            digest_value7[..64].copy_from_slice(digest7.data.as_ref());
            digest_value8[..64].copy_from_slice(digest8.data.as_ref());
            digest_value9[..64].copy_from_slice(digest9.data.as_ref());
            digest_value10[..64].copy_from_slice(digest10.data.as_ref());

            let mut spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
                index: 1u8,
                measurement_specification,
                measurement_size: digest1.data_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                    value_size: digest1.data_size,
                    value: digest_value1,
                },
            };

            let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
            let mut writer = Writer::init(&mut measurement_record_data);
            for i in 0..10 {
                spdm_measurement_block_structure.encode(&mut writer).ok()?;
                spdm_measurement_block_structure.index += 1;
            }

            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 10,
                measurement_record_length: u24::new(writer.used() as u32),
                measurement_record_data,
            })
        } else if measurement_index > 10 {
            None
        } else {
            let mut firmware: [u8; 8] = [0; 8];
            firmware.copy_from_slice("deadbeef".as_bytes());

            let digest = hash::hash_all(base_hash_algo, &firmware)?;

            let mut digest_value: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN] =
                [0; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
            digest_value[(measurement_index) * SPDM_MAX_HASH_SIZE
                ..(measurement_index + 1) * SPDM_MAX_HASH_SIZE]
                .copy_from_slice(digest.data.as_ref());

            let spdm_measurement_block_structure = SpdmMeasurementBlockStructure {
                index: measurement_index as u8,
                measurement_specification,
                measurement_size: digest.data_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                    value_size: digest.data_size,
                    value: digest_value,
                },
            };

            let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
            let mut writer = Writer::init(&mut measurement_record_data);
            spdm_measurement_block_structure.encode(&mut writer).ok()?;

            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 1,
                measurement_record_length: u24::new(writer.used() as u32),
                measurement_record_data,
            })
        }
    }
}

fn generate_measurement_summary_hash_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    measurement_specification: SpdmMeasurementSpecification,
    measurement_hash_algo: SpdmMeasurementHashAlgo,
    measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
) -> Option<SpdmDigestStruct> {
    match measurement_summary_hash_type {
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll => {
            let mut dummyall: [u8; 8] = [0; 8];
            dummyall.copy_from_slice("dummyall".as_bytes());
            let digest = hash::hash_all(base_hash_algo, &dummyall)?;
            Some(digest)
        }
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
            let mut dummytcb: [u8; 8] = [0; 8];
            dummytcb.copy_from_slice("dummytcb".as_bytes());
            let digest = hash::hash_all(base_hash_algo, &dummytcb)?;
            Some(digest)
        }
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => None,
        _ => None,
    }
}

pub static SECRET_PSK_IMPL_INSTANCE: SpdmSecretPsk = SpdmSecretPsk {
    handshake_secret_hkdf_expand_cb: handshake_secret_hkdf_expand_impl,
    master_secret_hkdf_expand_cb: master_secret_hkdf_expand_impl,
};

const MAX_BIN_CONCAT_BUF_SIZE: usize = 2 + 8 + 12 + SPDM_MAX_HASH_SIZE;
const SALT_0: [u8; SPDM_MAX_HASH_SIZE] = [0u8; SPDM_MAX_HASH_SIZE];
const ZERO_FILLED: [u8; SPDM_MAX_HASH_SIZE] = [0u8; SPDM_MAX_HASH_SIZE];
const BIN_STR0_LABEL: &[u8] = b"derived";

fn handshake_secret_hkdf_expand_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmDigestStruct> {
    let mut psk_key: SpdmDheFinalKeyStruct = SpdmDheFinalKeyStruct {
        data_size: b"TestPskData\0".len() as u16,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskData\0");

    let hs_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        &SALT_0[0..base_hash_algo.get_size() as usize],
        psk_key.as_ref(),
    )?;
    crypto::hkdf::hkdf_expand(
        base_hash_algo,
        hs_sec.as_ref(),
        info,
        base_hash_algo.get_size(),
    )
}

fn master_secret_hkdf_expand_impl(
    spdm_version: SpdmVersion,
    base_hash_algo: SpdmBaseHashAlgo,
    psk_hint: &SpdmPskHintStruct,
    info: &[u8],
) -> Option<SpdmDigestStruct> {
    let mut psk_key: SpdmDheFinalKeyStruct = SpdmDheFinalKeyStruct {
        data_size: b"TestPskData\0".len() as u16,
        data: Box::new([0; SPDM_MAX_DHE_KEY_SIZE]),
    };
    psk_key.data[0..(psk_key.data_size as usize)].copy_from_slice(b"TestPskData\0");

    let buffer = &mut [0; MAX_BIN_CONCAT_BUF_SIZE];
    let bin_str0 = SpdmKeySchedule::binconcat(
        &SpdmKeySchedule::default(),
        base_hash_algo.get_size(),
        spdm_version,
        BIN_STR0_LABEL,
        None,
        buffer,
    )?;

    let hs_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        &SALT_0[0..base_hash_algo.get_size() as usize],
        psk_key.as_ref(),
    )?;
    let salt_1 = crypto::hkdf::hkdf_expand(
        base_hash_algo,
        hs_sec.as_ref(),
        bin_str0,
        base_hash_algo.get_size(),
    )?;

    let mst_sec = crypto::hkdf::hkdf_extract(
        base_hash_algo,
        salt_1.as_ref(),
        &ZERO_FILLED[0..base_hash_algo.get_size() as usize],
    )?;
    crypto::hkdf::hkdf_expand(
        base_hash_algo,
        mst_sec.as_ref(),
        info,
        base_hash_algo.get_size(),
    )
}

pub struct FakeSpdmDeviceIo<'a> {
    pub data: &'a SharedBuffer,
    pub responder: &'a mut responder::ResponderContext<'a>,
}

impl<'a> FakeSpdmDeviceIo<'a> {
    pub fn new(data: &'a SharedBuffer, responder: &'a mut responder::ResponderContext<'a>) -> Self {
        FakeSpdmDeviceIo { data, responder }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIo<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(buffer);
        log::info!("requester send    RAW - {:02x?}\n", buffer);

        if self.responder.process_message(ST1, &[0]).is_err() {
            return Err(SPDM_STATUS_ERROR_PEER);
        }
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
    fuzzdata: &'a [u8],
}

impl<'a> SpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer, fuzzdata: &'a [u8]) -> Self {
        SpdmDeviceIoReceve { data, fuzzdata }
    }
}

impl SpdmDeviceIo for SpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(self.fuzzdata);
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FakeSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
}

impl<'a> FakeSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer) -> Self {
        FakeSpdmDeviceIoReceve { data }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(buffer);
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct SharedBuffer {
    queue: RefCell<VecDeque<u8>>,
}

impl SharedBuffer {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SharedBuffer {
            queue: RefCell::new(VecDeque::<u8>::new()),
        }
    }
    pub fn set_buffer(&self, b: &[u8]) {
        log::info!("send    {:02x?}\n", b);
        let mut queue = self.queue.borrow_mut();
        for i in b {
            queue.push_back(*i);
        }
    }

    pub fn get_buffer(&self, b: &mut [u8]) -> usize {
        let mut queue = self.queue.borrow_mut();
        let mut len = 0usize;
        for i in b.iter_mut() {
            if queue.is_empty() {
                break;
            }
            *i = queue.pop_front().unwrap();
            len += 1;
        }
        log::info!("recieve {:02x?}\n", &b[..len]);
        len
    }
}

pub static HMAC_TEST: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(_base_hash_algo: SpdmBaseHashAlgo, _key: &[u8], _data: &[u8]) -> Option<SpdmDigestStruct> {
    let tag = SpdmDigestStruct {
        data_size: 48,
        data: Box::new([10u8; SPDM_MAX_HASH_SIZE]),
    };
    Some(tag)
}

fn hmac_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _key: &[u8],
    _data: &[u8],
    hmac: &SpdmDigestStruct,
) -> SpdmResult {
    let SpdmDigestStruct { data_size, .. } = hmac;
    match data_size {
        48 => Ok(()),
        _ => Err(SPDM_STATUS_VERIF_FAIL),
    }
}

pub static DEFAULT_TEST: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    #[allow(clippy::needless_range_loop)]
    for i in 0..data.len() {
        data[i] = 0xff;
    }

    Ok(data.len())
}

pub fn get_rsp_cert_chain_buff() -> SpdmCertChainBuffer {
    let hash_algo = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    let cert_chain = include_bytes!("../../test_key/EcP384/bundle_responder.certchain.der");

    let (root_cert_begin, root_cert_end) =
        crypto::cert_operation::get_cert_from_cert_chain(cert_chain, 0)
            .expect("Get provisioned root cert failed");

    let root_cert_hash =
        crypto::hash::hash_all(hash_algo, &cert_chain[root_cert_begin..root_cert_end])
            .expect("Must provide hash algo");
    SpdmCertChainBuffer::new(cert_chain, root_cert_hash.as_ref())
        .expect("Create format certificate chain failed.")
}
