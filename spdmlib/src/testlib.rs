// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent


use crate::crypto::{SpdmAsymSign, SpdmCryptoRandom, SpdmHmac};
use crate::{common, responder};
use crate::common::*;

use crate::msgs::*;
use crate::error::SpdmResult;
use crate::{spdm_err, spdm_result_err};
use codec::enum_builder;
use codec::{Codec, Reader, Writer};
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
    let context = SpdmContext::new(
        my_spdm_device_io,
        pcidoe_transport_encap,
        config_info,
        provision_info,
    );
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
        spdm_version: [SpdmVersion::SpdmVersion10, SpdmVersion::SpdmVersion11],
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
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,

        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = crate_dir.join("test_key/EcP384/ca.cert.der");
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path =crate_dir.join("test_key/EcP384/inter.cert.der");
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

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: Some(my_cert_chain_data),
        my_cert_chain: None,
        peer_cert_chain_data: None,
        peer_cert_chain_root_hash: None,
    };

    (config_info, provision_info)
}

pub struct MySpdmDeviceIo;

impl SpdmDeviceIo for MySpdmDeviceIo {
    fn send(&mut self, _buffer: &[u8]) -> SpdmResult {
        todo!()
    }

    fn receive(&mut self, _buffer: &mut [u8]) -> Result<usize, usize> {
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

enum_builder! {
    @U8
    EnumName: PciDoeDataObjectType;
    EnumVal{
        PciDoeDataObjectTypeDoeDiscovery => 0x00,
        PciDoeDataObjectTypeSpdm => 0x01,
        PciDoeDataObjectTypeSecuredSpdm => 0x02
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct PciDoeMessageHeader {
    pub vendor_id: PciDoeVendorId,
    pub data_object_type: PciDoeDataObjectType,
    pub payload_length: u32, // in bytes
}

impl Codec for PciDoeMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.vendor_id.encode(bytes);
        self.data_object_type.encode(bytes);
        0u8.encode(bytes);
        let mut length = (self.payload_length + 8) >> 2;
        if length > 0x100000 {
            panic!();
        }
        if length == 0x100000 {
            length = 0;
        }
        length.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<PciDoeMessageHeader> {
        let vendor_id = PciDoeVendorId::read(r)?;
        let data_object_type = PciDoeDataObjectType::read(r)?;
        u8::read(r)?;
        let mut length = u32::read(r)?;
        if length == 0 {
            length = 0x40000;
        }
        if length < 2 {
            return None;
        }
        let payload_length = (length << 2) - 8;
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
        let mut writer = Writer::init(&mut transport_buffer[..]);
        let pcidoe_header = PciDoeMessageHeader {
            vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
            data_object_type: if secured_message {
                PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm
            } else {
                PciDoeDataObjectType::PciDoeDataObjectTypeSpdm
            },
            payload_length: aligned_payload_len as u32,
        };
        pcidoe_header.encode(&mut writer);
        let header_size = writer.used();
        if transport_buffer.len() < header_size + aligned_payload_len {
            return spdm_result_err!(EINVAL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + aligned_payload_len)
    }

    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&transport_buffer[..]);
        let secured_message;
        match PciDoeMessageHeader::read(&mut reader) {
            Some(pcidoe_header) => {
                match pcidoe_header.vendor_id {
                    PciDoeVendorId::PciDoeVendorIdPciSig => {}
                    _ => return spdm_result_err!(EINVAL),
                }
                match pcidoe_header.data_object_type {
                    PciDoeDataObjectType::PciDoeDataObjectTypeSpdm => secured_message = false,
                    PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm => secured_message = true,
                    _ => return spdm_result_err!(EINVAL),
                }
            }
            None => return spdm_result_err!(EIO),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        if spdm_buffer.len() < payload_size {
            return spdm_result_err!(EINVAL);
        }
        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    fn encap_app(&mut self, spdm_buffer: &[u8], app_buffer: &mut [u8]) -> SpdmResult<usize> {
        app_buffer[0..spdm_buffer.len()].copy_from_slice(spdm_buffer);
        Ok(spdm_buffer.len())
    }

    fn decap_app(&mut self, app_buffer: &[u8], spdm_buffer: &mut [u8]) -> SpdmResult<usize> {
        spdm_buffer[0..app_buffer.len()].copy_from_slice(app_buffer);
        Ok(app_buffer.len())
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        0
    }

    fn get_max_random_count(&mut self) -> u16 {
        0
    }
}

pub static ASYM_SIGN_IMPL: SpdmAsymSign = SpdmAsymSign {
    sign_cb: asym_sign,
};

fn asym_sign(
    base_hash_algo: SpdmBaseHashAlgo,
    base_asym_algo: SpdmBaseAsymAlgo,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    match (base_hash_algo, base_asym_algo) {
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => sign_ecdsa_asym_algo(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384) => sign_ecdsa_asym_algo(&ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PKCS1_SHA256, base_asym_algo.get_size() as usize, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PSS_SHA256, base_asym_algo.get_size() as usize, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PKCS1_SHA384, base_asym_algo.get_size() as usize, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PSS_SHA384, base_asym_algo.get_size() as usize, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PKCS1_SHA512, base_asym_algo.get_size() as usize, data),
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072) |
        (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => sign_rsa_asym_algo(&ring::signature::RSA_PSS_SHA512, base_asym_algo.get_size() as usize, data),
        _ => {panic!();}
    }
}

fn sign_ecdsa_asym_algo(
    algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
    // or  openssl.exe ecparam -name prime256v1 -genkey -out private.der -outform der
    // openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8
    
    let crate_dir = get_test_key_directory();
    let key_file_path =crate_dir.join("test_key/EcP384/end_responder.key.p8");
    let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
    let key_bytes = der_file.as_slice();

    let key_pair: ring::signature::EcdsaKeyPair = ring::signature::EcdsaKeyPair::from_pkcs8(
        algorithm,
        key_bytes,
    )
    .unwrap();

    let rng = ring::rand::SystemRandom::new();

    let signature = key_pair.sign(&rng, data).unwrap();
    let signature = signature.as_ref();

    let mut full_signature: [u8; SPDM_MAX_ASYM_KEY_SIZE] = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    full_signature[..signature.len()].copy_from_slice(signature);

    //debug!("ecdsa signature len - 0x{:x?}\n", signature.len());
    //debug!("ecdsa signature - {:x?}\n", signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })

}

fn sign_rsa_asym_algo(
    padding_alg: &'static dyn ring::signature::RsaEncoding,
    key_len: usize,
    data: &[u8],
) -> Option<SpdmSignatureStruct> {
    // openssl.exe genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der

    let crate_dir = get_test_key_directory();
    let key_file_path = crate_dir.join("test_key/Rsa3072/end_responder.key.der") ;
    let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
    let key_bytes = der_file.as_slice();
    
    let key_pair: ring::signature::RsaKeyPair = ring::signature::RsaKeyPair::from_der(key_bytes).unwrap();

    if key_len != key_pair.public_modulus_len() {
        panic!();
    }

    let rng = ring::rand::SystemRandom::new();

    let mut full_sign = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
    key_pair.sign(padding_alg, &rng, data, &mut full_sign[0..key_len]).unwrap();

    Some(SpdmSignatureStruct {
        data_size: key_len as u16,
        data: full_sign,
    })
}

pub struct FakeSpdmDeviceIo<'a> {
    pub data: &'a SharedBuffer,
    pub responder: &'a mut responder::ResponderContext<'a>,
}

impl<'a> FakeSpdmDeviceIo<'a> {
    pub fn new(data: &'a SharedBuffer, responder: &'a mut responder::ResponderContext<'a>) -> Self {
        FakeSpdmDeviceIo {
            data: data,
            responder,
        }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIo<'_> {
    fn receive(&mut self, read_buffer: &mut [u8]) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(buffer);
        log::info!("requester send    RAW - {:02x?}\n", buffer);

        if self.responder
            .process_message().is_err() {
                return spdm_result_err!(ENOMEM);
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
    pub fn new(data: &'a SharedBuffer, fuzzdata: &'a[u8]) -> Self {
        SpdmDeviceIoReceve {
            data: data,
            fuzzdata,
        }
    }
}

impl SpdmDeviceIo for SpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8]) -> Result<usize, usize> {
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
        FakeSpdmDeviceIoReceve { data: data }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8]) -> Result<usize, usize> {
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

pub fn cert_chain_array() -> [u8; 1492] {
    let cert_chain = [
        0x30u8, 0x82u8, 0x01u8, 0xcfu8, 0x30u8, 0x82u8, 0x01u8, 0x56u8, 0xa0u8, 0x03u8, 0x02u8,
        0x01u8, 0x02u8, 0x02u8, 0x14u8, 0x20u8, 0x3au8, 0xc2u8, 0x59u8, 0xccu8, 0xdau8, 0xcbu8,
        0xf6u8, 0x72u8, 0xf1u8, 0xc0u8, 0x1au8, 0x62u8, 0x1au8, 0x45u8, 0x82u8, 0x90u8, 0x24u8,
        0xb8u8, 0xafu8, 0x30u8, 0x0au8, 0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8,
        0x04u8, 0x03u8, 0x03u8, 0x30u8, 0x1fu8, 0x31u8, 0x1du8, 0x30u8, 0x1bu8, 0x06u8, 0x03u8,
        0x55u8, 0x04u8, 0x03u8, 0x0cu8, 0x14u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x6cu8, 0x20u8,
        0x74u8, 0x65u8, 0x73u8, 0x74u8, 0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8, 0x35u8, 0x36u8,
        0x20u8, 0x43u8, 0x41u8, 0x30u8, 0x1eu8, 0x17u8, 0x0du8, 0x32u8, 0x31u8, 0x30u8, 0x32u8,
        0x30u8, 0x39u8, 0x30u8, 0x30u8, 0x35u8, 0x30u8, 0x35u8, 0x38u8, 0x5au8, 0x17u8, 0x0du8,
        0x33u8, 0x31u8, 0x30u8, 0x32u8, 0x30u8, 0x37u8, 0x30u8, 0x30u8, 0x35u8, 0x30u8, 0x35u8,
        0x38u8, 0x5au8, 0x30u8, 0x1fu8, 0x31u8, 0x1du8, 0x30u8, 0x1bu8, 0x06u8, 0x03u8, 0x55u8,
        0x04u8, 0x03u8, 0x0cu8, 0x14u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x6cu8, 0x20u8, 0x74u8,
        0x65u8, 0x73u8, 0x74u8, 0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8, 0x35u8, 0x36u8, 0x20u8,
        0x43u8, 0x41u8, 0x30u8, 0x76u8, 0x30u8, 0x10u8, 0x06u8, 0x07u8, 0x2au8, 0x86u8, 0x48u8,
        0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x05u8, 0x2bu8, 0x81u8, 0x04u8, 0x00u8, 0x22u8,
        0x03u8, 0x62u8, 0x00u8, 0x04u8, 0x99u8, 0x8fu8, 0x81u8, 0x68u8, 0x9au8, 0x83u8, 0x9bu8,
        0x83u8, 0x39u8, 0xadu8, 0x0eu8, 0x32u8, 0x8du8, 0xb9u8, 0x42u8, 0x0du8, 0xaeu8, 0xccu8,
        0x91u8, 0xa9u8, 0xbcu8, 0x4au8, 0xe1u8, 0xbbu8, 0x79u8, 0x4cu8, 0x22u8, 0xfau8, 0x3fu8,
        0x0cu8, 0x9du8, 0x93u8, 0x3cu8, 0x1au8, 0x02u8, 0x5cu8, 0xc2u8, 0x73u8, 0x05u8, 0xecu8,
        0x43u8, 0x5du8, 0x04u8, 0x02u8, 0xb1u8, 0x68u8, 0xb3u8, 0xf4u8, 0xd8u8, 0xdeu8, 0x0cu8,
        0x8du8, 0x53u8, 0xb7u8, 0x04u8, 0x8eu8, 0xa1u8, 0x43u8, 0x9au8, 0xebu8, 0x31u8, 0x0du8,
        0xaau8, 0xceu8, 0x89u8, 0x2du8, 0xbau8, 0x73u8, 0xdau8, 0x4fu8, 0x1eu8, 0x39u8, 0x5du8,
        0x92u8, 0x11u8, 0x21u8, 0x38u8, 0xb4u8, 0x00u8, 0xd4u8, 0xf5u8, 0x55u8, 0x8cu8, 0xe8u8,
        0x71u8, 0x30u8, 0x3du8, 0x46u8, 0x83u8, 0xf4u8, 0xc4u8, 0x52u8, 0x50u8, 0xdau8, 0x12u8,
        0x5bu8, 0xa3u8, 0x53u8, 0x30u8, 0x51u8, 0x30u8, 0x1du8, 0x06u8, 0x03u8, 0x55u8, 0x1du8,
        0x0eu8, 0x04u8, 0x16u8, 0x04u8, 0x14u8, 0xcfu8, 0x09u8, 0xd4u8, 0x7au8, 0xeeu8, 0x08u8,
        0x90u8, 0x62u8, 0xbfu8, 0xe6u8, 0x9cu8, 0xb4u8, 0xb9u8, 0xdfu8, 0xe1u8, 0x41u8, 0x33u8,
        0x1cu8, 0x03u8, 0xa5u8, 0x30u8, 0x1fu8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x23u8, 0x04u8,
        0x18u8, 0x30u8, 0x16u8, 0x80u8, 0x14u8, 0xcfu8, 0x09u8, 0xd4u8, 0x7au8, 0xeeu8, 0x08u8,
        0x90u8, 0x62u8, 0xbfu8, 0xe6u8, 0x9cu8, 0xb4u8, 0xb9u8, 0xdfu8, 0xe1u8, 0x41u8, 0x33u8,
        0x1cu8, 0x03u8, 0xa5u8, 0x30u8, 0x0fu8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x13u8, 0x01u8,
        0x01u8, 0xffu8, 0x04u8, 0x05u8, 0x30u8, 0x03u8, 0x01u8, 0x01u8, 0xffu8, 0x30u8, 0x0au8,
        0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x04u8, 0x03u8, 0x03u8, 0x03u8,
        0x67u8, 0x00u8, 0x30u8, 0x64u8, 0x02u8, 0x30u8, 0x5au8, 0xb4u8, 0xf5u8, 0x95u8, 0x25u8,
        0x82u8, 0xf6u8, 0x68u8, 0x3eu8, 0x49u8, 0xc7u8, 0xb4u8, 0xbbu8, 0x42u8, 0x81u8, 0x91u8,
        0x7eu8, 0x38u8, 0xd0u8, 0x2du8, 0xacu8, 0x53u8, 0xaeu8, 0x8eu8, 0xb0u8, 0x51u8, 0x50u8,
        0xaau8, 0xf8u8, 0x7eu8, 0xffu8, 0xc0u8, 0x30u8, 0xabu8, 0xd5u8, 0x08u8, 0x5bu8, 0x06u8,
        0xf7u8, 0xe1u8, 0xbfu8, 0x39u8, 0xd2u8, 0x3eu8, 0xaeu8, 0xbfu8, 0x8eu8, 0x48u8, 0x02u8,
        0x30u8, 0x09u8, 0x75u8, 0xa8u8, 0xc0u8, 0x6fu8, 0x4fu8, 0x3cu8, 0xadu8, 0x5du8, 0x4eu8,
        0x4fu8, 0xf8u8, 0x2cu8, 0x3bu8, 0x39u8, 0x46u8, 0xa0u8, 0xdfu8, 0x83u8, 0x8eu8, 0xb5u8,
        0xd3u8, 0x61u8, 0x61u8, 0x59u8, 0xbcu8, 0x39u8, 0xd7u8, 0xadu8, 0x68u8, 0x5eu8, 0x0du8,
        0x4fu8, 0x3fu8, 0xe2u8, 0xcau8, 0xc1u8, 0x74u8, 0x8fu8, 0x47u8, 0x37u8, 0x11u8, 0xc8u8,
        0x22u8, 0x59u8, 0x6fu8, 0x64u8, 0x52u8, 0x30u8, 0x82u8, 0x01u8, 0xd7u8, 0x30u8, 0x82u8,
        0x01u8, 0x5du8, 0xa0u8, 0x03u8, 0x02u8, 0x01u8, 0x02u8, 0x02u8, 0x01u8, 0x01u8, 0x30u8,
        0x0au8, 0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x04u8, 0x03u8, 0x03u8,
        0x30u8, 0x1fu8, 0x31u8, 0x1du8, 0x30u8, 0x1bu8, 0x06u8, 0x03u8, 0x55u8, 0x04u8, 0x03u8,
        0x0cu8, 0x14u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x6cu8, 0x20u8, 0x74u8, 0x65u8, 0x73u8,
        0x74u8, 0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8, 0x35u8, 0x36u8, 0x20u8, 0x43u8, 0x41u8,
        0x30u8, 0x1eu8, 0x17u8, 0x0du8, 0x32u8, 0x31u8, 0x30u8, 0x32u8, 0x30u8, 0x39u8, 0x30u8,
        0x30u8, 0x35u8, 0x30u8, 0x35u8, 0x39u8, 0x5au8, 0x17u8, 0x0du8, 0x33u8, 0x31u8, 0x30u8,
        0x32u8, 0x30u8, 0x37u8, 0x30u8, 0x30u8, 0x35u8, 0x30u8, 0x35u8, 0x39u8, 0x5au8, 0x30u8,
        0x2eu8, 0x31u8, 0x2cu8, 0x30u8, 0x2au8, 0x06u8, 0x03u8, 0x55u8, 0x04u8, 0x03u8, 0x0cu8,
        0x23u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x6cu8, 0x20u8, 0x74u8, 0x65u8, 0x73u8, 0x74u8,
        0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8, 0x35u8, 0x36u8, 0x20u8, 0x69u8, 0x6eu8, 0x74u8,
        0x65u8, 0x72u8, 0x6du8, 0x65u8, 0x64u8, 0x69u8, 0x61u8, 0x74u8, 0x65u8, 0x20u8, 0x63u8,
        0x65u8, 0x72u8, 0x74u8, 0x30u8, 0x76u8, 0x30u8, 0x10u8, 0x06u8, 0x07u8, 0x2au8, 0x86u8,
        0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x05u8, 0x2bu8, 0x81u8, 0x04u8, 0x00u8,
        0x22u8, 0x03u8, 0x62u8, 0x00u8, 0x04u8, 0x77u8, 0x1bu8, 0x24u8, 0xf6u8, 0xc6u8, 0x76u8,
        0x1fu8, 0xb8u8, 0x30u8, 0x07u8, 0x8bu8, 0xb8u8, 0xa3u8, 0x9eu8, 0xc0u8, 0x26u8, 0xc1u8,
        0xeau8, 0x7du8, 0xfcu8, 0x29u8, 0x7du8, 0xe0u8, 0x59u8, 0xb2u8, 0x64u8, 0x32u8, 0x75u8,
        0x4au8, 0xe3u8, 0x02u8, 0x64u8, 0x3cu8, 0xbcu8, 0x85u8, 0x8eu8, 0xc6u8, 0xecu8, 0xefu8,
        0xb0u8, 0x79u8, 0xf4u8, 0xc1u8, 0xa4u8, 0xb9u8, 0xbbu8, 0x29u8, 0x6bu8, 0xaeu8, 0xadu8,
        0xf0u8, 0x7du8, 0x63u8, 0xc6u8, 0xafu8, 0xb3u8, 0x73u8, 0x5eu8, 0x4fu8, 0x3fu8, 0xfeu8,
        0x89u8, 0x8au8, 0xbbu8, 0x7du8, 0x2bu8, 0x60u8, 0x3eu8, 0x16u8, 0xbau8, 0x82u8, 0xcfu8,
        0xa4u8, 0x70u8, 0x04u8, 0x85u8, 0xc3u8, 0xa3u8, 0x3cu8, 0x5eu8, 0x6au8, 0xa0u8, 0xefu8,
        0xdau8, 0xd5u8, 0x20u8, 0x30u8, 0x19u8, 0xbau8, 0x79u8, 0x95u8, 0xb0u8, 0xc2u8, 0x7fu8,
        0x4cu8, 0xddu8, 0xa3u8, 0x5eu8, 0x30u8, 0x5cu8, 0x30u8, 0x0cu8, 0x06u8, 0x03u8, 0x55u8,
        0x1du8, 0x13u8, 0x04u8, 0x05u8, 0x30u8, 0x03u8, 0x01u8, 0x01u8, 0xffu8, 0x30u8, 0x0bu8,
        0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x0fu8, 0x04u8, 0x04u8, 0x03u8, 0x02u8, 0x01u8, 0xfeu8,
        0x30u8, 0x1du8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x0eu8, 0x04u8, 0x16u8, 0x04u8, 0x14u8,
        0x12u8, 0xe0u8, 0x1au8, 0x23u8, 0xc6u8, 0x23u8, 0xe4u8, 0x02u8, 0x58u8, 0x0bu8, 0x06u8,
        0xacu8, 0x90u8, 0xfau8, 0x4bu8, 0x80u8, 0x3du8, 0xc9u8, 0xf1u8, 0x1du8, 0x30u8, 0x20u8,
        0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x25u8, 0x01u8, 0x01u8, 0xffu8, 0x04u8, 0x16u8, 0x30u8,
        0x14u8, 0x06u8, 0x08u8, 0x2bu8, 0x06u8, 0x01u8, 0x05u8, 0x05u8, 0x07u8, 0x03u8, 0x01u8,
        0x06u8, 0x08u8, 0x2bu8, 0x06u8, 0x01u8, 0x05u8, 0x05u8, 0x07u8, 0x03u8, 0x02u8, 0x30u8,
        0x0au8, 0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x04u8, 0x03u8, 0x03u8,
        0x03u8, 0x68u8, 0x00u8, 0x30u8, 0x65u8, 0x02u8, 0x30u8, 0x03u8, 0x32u8, 0xb1u8, 0x8bu8,
        0x20u8, 0xf4u8, 0x76u8, 0xdau8, 0x8cu8, 0x83u8, 0x96u8, 0x87u8, 0x55u8, 0xd9u8, 0x12u8,
        0x72u8, 0xbdu8, 0x58u8, 0x4du8, 0x0au8, 0x37u8, 0xafu8, 0x29u8, 0x95u8, 0x1du8, 0x36u8,
        0xc4u8, 0x9eu8, 0xa5u8, 0xcdu8, 0xe2u8, 0x3bu8, 0xf5u8, 0xe0u8, 0x7au8, 0x64u8, 0x36u8,
        0x1eu8, 0xd4u8, 0xf1u8, 0xe1u8, 0xbbu8, 0x14u8, 0x57u8, 0x9eu8, 0x86u8, 0x82u8, 0x72u8,
        0x02u8, 0x31u8, 0x00u8, 0xc0u8, 0xd6u8, 0x02u8, 0x99u8, 0x50u8, 0x76u8, 0x34u8, 0x16u8,
        0xd6u8, 0x51u8, 0x9cu8, 0xc4u8, 0x86u8, 0x08u8, 0x68u8, 0x94u8, 0xbfu8, 0x3cu8, 0x09u8,
        0x7eu8, 0x10u8, 0xe5u8, 0x62u8, 0x8au8, 0xbau8, 0x48u8, 0x0au8, 0xa5u8, 0xedu8, 0x1au8,
        0x6au8, 0xf6u8, 0x3cu8, 0x2fu8, 0x4du8, 0x38u8, 0x5du8, 0x7du8, 0x5cu8, 0x60u8, 0x63u8,
        0x88u8, 0x84u8, 0x5du8, 0x49u8, 0x33u8, 0xe2u8, 0xa7u8, 0x30u8, 0x82u8, 0x02u8, 0x22u8,
        0x30u8, 0x82u8, 0x01u8, 0xa8u8, 0xa0u8, 0x03u8, 0x02u8, 0x01u8, 0x02u8, 0x02u8, 0x01u8,
        0x03u8, 0x30u8, 0x0au8, 0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x04u8,
        0x03u8, 0x03u8, 0x30u8, 0x2eu8, 0x31u8, 0x2cu8, 0x30u8, 0x2au8, 0x06u8, 0x03u8, 0x55u8,
        0x04u8, 0x03u8, 0x0cu8, 0x23u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x6cu8, 0x20u8, 0x74u8,
        0x65u8, 0x73u8, 0x74u8, 0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8, 0x35u8, 0x36u8, 0x20u8,
        0x69u8, 0x6eu8, 0x74u8, 0x65u8, 0x72u8, 0x6du8, 0x65u8, 0x64u8, 0x69u8, 0x61u8, 0x74u8,
        0x65u8, 0x20u8, 0x63u8, 0x65u8, 0x72u8, 0x74u8, 0x30u8, 0x1eu8, 0x17u8, 0x0du8, 0x32u8,
        0x31u8, 0x30u8, 0x32u8, 0x30u8, 0x39u8, 0x30u8, 0x30u8, 0x35u8, 0x30u8, 0x35u8, 0x39u8,
        0x5au8, 0x17u8, 0x0du8, 0x32u8, 0x32u8, 0x30u8, 0x32u8, 0x30u8, 0x39u8, 0x30u8, 0x30u8,
        0x35u8, 0x30u8, 0x35u8, 0x39u8, 0x5au8, 0x30u8, 0x2bu8, 0x31u8, 0x29u8, 0x30u8, 0x27u8,
        0x06u8, 0x03u8, 0x55u8, 0x04u8, 0x03u8, 0x0cu8, 0x20u8, 0x69u8, 0x6eu8, 0x74u8, 0x65u8,
        0x6cu8, 0x20u8, 0x74u8, 0x65u8, 0x73u8, 0x74u8, 0x20u8, 0x45u8, 0x43u8, 0x50u8, 0x32u8,
        0x35u8, 0x36u8, 0x20u8, 0x72u8, 0x65u8, 0x73u8, 0x70u8, 0x6fu8, 0x6eu8, 0x64u8, 0x65u8,
        0x72u8, 0x20u8, 0x63u8, 0x65u8, 0x72u8, 0x74u8, 0x30u8, 0x76u8, 0x30u8, 0x10u8, 0x06u8,
        0x07u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x05u8, 0x2bu8,
        0x81u8, 0x04u8, 0x00u8, 0x22u8, 0x03u8, 0x62u8, 0x00u8, 0x04u8, 0x6cu8, 0x22u8, 0x41u8,
        0xdfu8, 0xb7u8, 0xe4u8, 0xd6u8, 0x8du8, 0x53u8, 0x72u8, 0x4eu8, 0x4au8, 0x1bu8, 0x99u8,
        0x82u8, 0xe6u8, 0x56u8, 0xd2u8, 0x2du8, 0x97u8, 0x4bu8, 0x98u8, 0x40u8, 0xa9u8, 0x99u8,
        0xd6u8, 0x0du8, 0xd8u8, 0xe9u8, 0xa6u8, 0xfcu8, 0x74u8, 0xb9u8, 0xceu8, 0x89u8, 0x48u8,
        0xa7u8, 0xb5u8, 0x09u8, 0xb6u8, 0x24u8, 0x49u8, 0xd6u8, 0x23u8, 0xb3u8, 0x5fu8, 0x3au8,
        0xf0u8, 0x99u8, 0xb0u8, 0xcau8, 0x63u8, 0x7du8, 0x24u8, 0xfeu8, 0xe9u8, 0x12u8, 0x19u8,
        0x0fu8, 0xc2u8, 0x73u8, 0x1cu8, 0xe3u8, 0x76u8, 0x91u8, 0xecu8, 0x57u8, 0x6cu8, 0xcdu8,
        0x7bu8, 0xabu8, 0x32u8, 0xfdu8, 0x6du8, 0x6eu8, 0x92u8, 0x7du8, 0x37u8, 0x60u8, 0x01u8,
        0xdbu8, 0x13u8, 0x92u8, 0x3bu8, 0x77u8, 0xf7u8, 0x12u8, 0x97u8, 0x1du8, 0x5eu8, 0xe3u8,
        0xb9u8, 0x15u8, 0x83u8, 0xafu8, 0x89u8, 0xa3u8, 0x81u8, 0x9cu8, 0x30u8, 0x81u8, 0x99u8,
        0x30u8, 0x0cu8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x13u8, 0x01u8, 0x01u8, 0xffu8, 0x04u8,
        0x02u8, 0x30u8, 0x00u8, 0x30u8, 0x0bu8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x0fu8, 0x04u8,
        0x04u8, 0x03u8, 0x02u8, 0x05u8, 0xe0u8, 0x30u8, 0x1du8, 0x06u8, 0x03u8, 0x55u8, 0x1du8,
        0x0eu8, 0x04u8, 0x16u8, 0x04u8, 0x14u8, 0x48u8, 0x1fu8, 0x5du8, 0x95u8, 0xceu8, 0x89u8,
        0xd4u8, 0x7du8, 0xa4u8, 0x4cu8, 0x21u8, 0x8fu8, 0x5bu8, 0xd5u8, 0x50u8, 0x96u8, 0xffu8,
        0xbau8, 0xe2u8, 0xeeu8, 0x30u8, 0x31u8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x11u8, 0x04u8,
        0x2au8, 0x30u8, 0x28u8, 0xa0u8, 0x26u8, 0x06u8, 0x0au8, 0x2bu8, 0x06u8, 0x01u8, 0x04u8,
        0x01u8, 0x83u8, 0x1cu8, 0x82u8, 0x12u8, 0x01u8, 0xa0u8, 0x18u8, 0x0cu8, 0x16u8, 0x41u8,
        0x43u8, 0x4du8, 0x45u8, 0x3au8, 0x57u8, 0x49u8, 0x44u8, 0x47u8, 0x45u8, 0x54u8, 0x3au8,
        0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x30u8, 0x30u8,
        0x2au8, 0x06u8, 0x03u8, 0x55u8, 0x1du8, 0x25u8, 0x01u8, 0x01u8, 0xffu8, 0x04u8, 0x20u8,
        0x30u8, 0x1eu8, 0x06u8, 0x08u8, 0x2bu8, 0x06u8, 0x01u8, 0x05u8, 0x05u8, 0x07u8, 0x03u8,
        0x01u8, 0x06u8, 0x08u8, 0x2bu8, 0x06u8, 0x01u8, 0x05u8, 0x05u8, 0x07u8, 0x03u8, 0x02u8,
        0x06u8, 0x08u8, 0x2bu8, 0x06u8, 0x01u8, 0x05u8, 0x05u8, 0x07u8, 0x03u8, 0x09u8, 0x30u8,
        0x0au8, 0x06u8, 0x08u8, 0x2au8, 0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x04u8, 0x03u8, 0x03u8,
        0x03u8, 0x68u8, 0x00u8, 0x30u8, 0x65u8, 0x02u8, 0x30u8, 0x08u8, 0xe6u8, 0x1fu8, 0x0du8,
        0xdfu8, 0x18u8, 0xd3u8, 0x2fu8, 0x50u8, 0x49u8, 0x99u8, 0xb0u8, 0xe2u8, 0x64u8, 0x95u8,
        0x30u8, 0xa9u8, 0x5au8, 0xbfu8, 0x83u8, 0x76u8, 0xaeu8, 0x4au8, 0x39u8, 0xd8u8, 0xe2u8,
        0x51u8, 0x12u8, 0x84u8, 0x9cu8, 0xbeu8, 0x11u8, 0x1du8, 0x3bu8, 0x77u8, 0x20u8, 0x6fu8,
        0x05u8, 0x6cu8, 0xc7u8, 0x98u8, 0xb2u8, 0xbau8, 0xb8u8, 0x96u8, 0x75u8, 0x25u8, 0xcfu8,
        0x02u8, 0x31u8, 0x00u8, 0x93u8, 0x12u8, 0x5bu8, 0x66u8, 0x93u8, 0xc0u8, 0xe7u8, 0x56u8,
        0x1bu8, 0x68u8, 0x28u8, 0x27u8, 0xd8u8, 0x8eu8, 0x69u8, 0xaau8, 0x30u8, 0x76u8, 0x05u8,
        0x6fu8, 0x4bu8, 0xd0u8, 0xceu8, 0x10u8, 0x0fu8, 0xf8u8, 0xdfu8, 0x4au8, 0xabu8, 0x9bu8,
        0x4du8, 0xb1u8, 0x47u8, 0xe4u8, 0xcdu8, 0xceu8, 0xceu8, 0x48u8, 0x0du8, 0xf8u8, 0x35u8,
        0x3du8, 0xbcu8, 0x25u8, 0xceu8, 0xecu8, 0xb9u8, 0xcau8,
    ];
    cert_chain
}

pub static HMAC_TEST: SpdmHmac = SpdmHmac {
    hmac_cb: hmac,
    hmac_verify_cb: hmac_verify,
};

fn hmac(
    base_hash_algo: SpdmBaseHashAlgo,
    key: &[u8],
    data: &[u8],
) -> Option<SpdmDigestStruct> {
    // Some(SpdmDigestStruct::default())
    let algorithm = match base_hash_algo {
        SpdmBaseHashAlgo::TPM_ALG_SHA_384 => ring::hmac::HMAC_SHA384,
        _ => {
            panic!();
        }
    };
    let s_key = ring::hmac::Key::new(algorithm, key);
    let tag = ring::hmac::sign(&s_key, data);
    let tag = tag.as_ref();
    Some(SpdmDigestStruct::from(tag))
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
        _ => spdm_result_err!(EFAULT),
    }
}

pub static DEFAULT_TEST: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    Ok(data.len())
}
