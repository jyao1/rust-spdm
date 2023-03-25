// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]

use crate::common::*;
use crate::crypto::{SpdmAsymSign, SpdmCryptoRandom, SpdmHmac};
pub use crate::protocol::*;
use crate::{common, responder};

use crate::error::{
    SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_FAIL, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
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
    let provision_info = create_info();
    let mut context = SpdmContext::new(my_spdm_device_io, pcidoe_transport_encap, provision_info);
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

pub fn create_info() -> common::SpdmProvisionInfo {
    let mut my_cert_chain_data = SpdmCertChainData {
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

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: Some(my_cert_chain_data.clone()),
        my_cert_chain: None,
        peer_cert_chain_data: Some(my_cert_chain_data),
        peer_cert_chain_root_hash: None,
        default_version: SpdmVersion::SpdmVersion11,
    };

    provision_info
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

enum_builder! {
    @U8
    EnumName: PciDoeDataObjectType;
    EnumVal{
        PciDoeDataObjectTypeDoeDiscovery => 0x00,
        PciDoeDataObjectTypeSpdm => 0x01,
        PciDoeDataObjectTypeSecuredSpdm => 0x02
    }
}

#[derive(Debug, Clone, Default)]
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
        pcidoe_header.encode(&mut writer);
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
        let secured_message;
        match PciDoeMessageHeader::read(&mut reader) {
            Some(pcidoe_header) => {
                match pcidoe_header.vendor_id {
                    PciDoeVendorId::PciDoeVendorIdPciSig => {}
                    _ => return Err(SPDM_STATUS_DECAP_FAIL),
                }
                match pcidoe_header.data_object_type {
                    PciDoeDataObjectType::PciDoeDataObjectTypeSpdm => secured_message = false,
                    PciDoeDataObjectType::PciDoeDataObjectTypeSecuredSpdm => secured_message = true,
                    _ => return Err(SPDM_STATUS_DECAP_FAIL),
                }
            }
            None => return Err(SPDM_STATUS_DECAP_FAIL),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        if spdm_buffer.len() < payload_size {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }
        let payload = &transport_buffer[header_size..];
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

pub static ASYM_SIGN_IMPL: SpdmAsymSign = SpdmAsymSign { sign_cb: asym_sign };

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

    //debug!("ecdsa signature len - 0x{:x?}\n", signature.len());
    //debug!("ecdsa signature - {:x?}\n", signature);

    Some(SpdmSignatureStruct {
        data_size: signature.len() as u16,
        data: full_signature,
    })
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

pub const REQ_CERT_CHAIN_DATA: SpdmCertChainData = SpdmCertChainData {
    data_size: 1545,
    data: [
        0x09, 0x06, 0x00, 0x00, 0x4e, 0x75, 0x0a, 0x31, 0x8a, 0x1c, 0x58, 0x20, 0x15, 0xa2, 0x8c,
        0x03, 0x4d, 0xb2, 0x96, 0x25, 0x7d, 0x8f, 0xef, 0x31, 0x47, 0x45, 0x3e, 0x40, 0x76, 0xfc,
        0x45, 0x92, 0x12, 0x66, 0xa8, 0x6e, 0x27, 0xfc, 0x41, 0x31, 0x7e, 0x72, 0x32, 0x53, 0x54,
        0x15, 0x3a, 0x92, 0x54, 0xff, 0xbd, 0xcd, 0x30, 0x82, 0x01, 0xD0, 0x30, 0x82, 0x01, 0x56,
        0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x00, 0xCA, 0x2F, 0x39, 0xE8, 0xFA, 0x16, 0xFD,
        0xB0, 0x34, 0x0C, 0x85, 0x50, 0x8F, 0x5D, 0x07, 0xE2, 0x6E, 0x48, 0x34, 0x30, 0x0A, 0x06,
        0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65,
        0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17,
        0x0D, 0x32, 0x32, 0x30, 0x31, 0x30, 0x35, 0x30, 0x36, 0x30, 0x38, 0x33, 0x33, 0x5A, 0x17,
        0x0D, 0x33, 0x32, 0x30, 0x31, 0x30, 0x33, 0x30, 0x36, 0x30, 0x38, 0x33, 0x33, 0x5A, 0x30,
        0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74,
        0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20,
        0x43, 0x41, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x92, 0x2F, 0xD3, 0xBD,
        0x8B, 0x60, 0xBB, 0xF7, 0x5E, 0xE4, 0x80, 0x25, 0x14, 0x10, 0x47, 0x8C, 0x79, 0xAD, 0x82,
        0xFB, 0x41, 0x3A, 0xC4, 0xAD, 0x39, 0xF8, 0x01, 0x1A, 0x9D, 0x47, 0x29, 0x90, 0xD6, 0xBB,
        0x86, 0x41, 0x07, 0x8D, 0x86, 0x66, 0x11, 0xDA, 0x6D, 0xC9, 0xED, 0x9B, 0x0E, 0x2A, 0xA1,
        0x2A, 0x51, 0xC2, 0xDD, 0x55, 0xAB, 0x3D, 0x1D, 0x7B, 0x3C, 0x3D, 0x38, 0x28, 0x80, 0x72,
        0x61, 0x20, 0x3E, 0x25, 0xF9, 0x99, 0x39, 0x82, 0x4E, 0x4A, 0xBA, 0x93, 0xD1, 0xAB, 0x1F,
        0xCE, 0x5A, 0x9B, 0x3D, 0xBE, 0xA5, 0xBC, 0x1B, 0x96, 0xF0, 0xB7, 0xB5, 0xFB, 0x10, 0xF9,
        0x23, 0x90, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16,
        0x04, 0x14, 0x14, 0xC4, 0xE7, 0xA6, 0x7C, 0x63, 0x3F, 0xDF, 0x13, 0xF2, 0xB1, 0x36, 0x56,
        0x63, 0xF9, 0xC1, 0xEA, 0xDD, 0x78, 0x10, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
        0x18, 0x30, 0x16, 0x80, 0x14, 0x14, 0xC4, 0xE7, 0xA6, 0x7C, 0x63, 0x3F, 0xDF, 0x13, 0xF2,
        0xB1, 0x36, 0x56, 0x63, 0xF9, 0xC1, 0xEA, 0xDD, 0x78, 0x10, 0x30, 0x0F, 0x06, 0x03, 0x55,
        0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0A, 0x06,
        0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02,
        0x31, 0x00, 0xD7, 0x9C, 0x7F, 0x26, 0x91, 0x34, 0xA5, 0x2B, 0x79, 0xEA, 0x66, 0x15, 0x00,
        0x88, 0x0A, 0x4D, 0xE7, 0xAD, 0x71, 0xC6, 0x2E, 0xE4, 0x7E, 0x37, 0xE1, 0x86, 0xEB, 0xE8,
        0x55, 0xB0, 0x2F, 0xC5, 0xF3, 0xA9, 0xE0, 0x90, 0xF9, 0x0B, 0x82, 0xC5, 0xDF, 0x4A, 0x35,
        0x9A, 0x0D, 0x35, 0x38, 0x4B, 0x02, 0x30, 0x40, 0xA7, 0xFE, 0x70, 0x39, 0x7B, 0x4B, 0xD7,
        0xC2, 0x28, 0x72, 0x93, 0x93, 0x0C, 0x62, 0x12, 0x14, 0xF0, 0x70, 0x74, 0x0F, 0xFC, 0xB1,
        0x21, 0x60, 0x40, 0x6D, 0x13, 0xA3, 0x59, 0x0E, 0x27, 0x06, 0xC1, 0x73, 0x4E, 0xCA, 0x40,
        0x4C, 0x2D, 0xF5, 0x96, 0x48, 0x66, 0x05, 0xB1, 0xA6, 0x08, 0x30, 0x82, 0x01, 0xD7, 0x30,
        0x82, 0x01, 0x5D, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0A, 0x06, 0x08,
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x14, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73,
        0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x43, 0x41, 0x30, 0x1E, 0x17, 0x0D,
        0x32, 0x32, 0x30, 0x31, 0x30, 0x35, 0x30, 0x36, 0x30, 0x38, 0x33, 0x34, 0x5A, 0x17, 0x0D,
        0x33, 0x32, 0x30, 0x31, 0x30, 0x33, 0x30, 0x36, 0x30, 0x38, 0x33, 0x34, 0x5A, 0x30, 0x2E,
        0x31, 0x2C, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x23, 0x69, 0x6E, 0x74, 0x65,
        0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x69,
        0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x63, 0x65, 0x72,
        0x74, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
        0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x12, 0xAF, 0x50, 0xBF, 0xAF,
        0xFB, 0xC8, 0x03, 0x23, 0x41, 0x27, 0xFA, 0xEF, 0xEC, 0x35, 0xC4, 0xAE, 0x96, 0xCB, 0xF4,
        0xAE, 0xFB, 0x74, 0x58, 0x6B, 0xF5, 0x8F, 0x60, 0x38, 0x28, 0x76, 0x0B, 0x29, 0xA4, 0xCA,
        0xF4, 0x6C, 0x2D, 0x59, 0x28, 0xF5, 0xAB, 0x92, 0xB7, 0x6B, 0x6F, 0x3A, 0xC0, 0x91, 0x9F,
        0x45, 0xD1, 0x3C, 0xA0, 0xC8, 0x80, 0x67, 0xFF, 0x4B, 0x9F, 0xE8, 0x01, 0x17, 0x08, 0xCB,
        0x4C, 0x17, 0x23, 0xC2, 0xF0, 0x07, 0xE4, 0xCD, 0x37, 0x26, 0x9F, 0x41, 0xA4, 0xFE, 0x7D,
        0x80, 0x1C, 0x23, 0x43, 0xCB, 0x53, 0x6C, 0xC1, 0x0F, 0x5F, 0x4A, 0xC8, 0x6A, 0x31, 0xE6,
        0xEE, 0xA3, 0x5E, 0x30, 0x5C, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30,
        0x03, 0x01, 0x01, 0xFF, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02,
        0x01, 0xFE, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x42, 0xBC,
        0xED, 0xBA, 0xD1, 0x5A, 0x68, 0xDF, 0x71, 0x41, 0xF8, 0xA5, 0x0E, 0x36, 0xCA, 0xF5, 0xDF,
        0x52, 0x50, 0x09, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x16,
        0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x04, 0x03, 0x03, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0x9A, 0xFD, 0xD5,
        0x7E, 0x34, 0x74, 0x19, 0x09, 0xE1, 0x26, 0x45, 0xF2, 0xBC, 0x3F, 0x25, 0xD4, 0x47, 0x22,
        0x19, 0x68, 0x23, 0xE4, 0x6A, 0xE5, 0x35, 0xD6, 0x9A, 0x4E, 0xA5, 0x23, 0xB2, 0xD3, 0xC0,
        0x9A, 0x68, 0x88, 0xCE, 0x99, 0x59, 0x9D, 0x55, 0x18, 0x96, 0x4D, 0xD3, 0x1C, 0x3B, 0x52,
        0x02, 0x30, 0x1C, 0x08, 0xDE, 0x61, 0x7F, 0x5B, 0xA7, 0xC8, 0x6B, 0xAF, 0x8D, 0x9D, 0xF5,
        0x3A, 0xC1, 0x54, 0xE5, 0x5F, 0x21, 0xC7, 0x69, 0x57, 0xDB, 0x63, 0xC4, 0x45, 0x09, 0x66,
        0xAB, 0x70, 0xAB, 0xC0, 0xBF, 0xB2, 0xC0, 0x6A, 0x7F, 0x51, 0xDA, 0xE8, 0xAE, 0x93, 0xC4,
        0x43, 0x33, 0x4A, 0x07, 0xA4, 0x30, 0x82, 0x02, 0x22, 0x30, 0x82, 0x01, 0xA8, 0xA0, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x04, 0x03, 0x03, 0x30, 0x2E, 0x31, 0x2C, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
        0x23, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x43, 0x50,
        0x32, 0x35, 0x36, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74,
        0x65, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x31, 0x30,
        0x35, 0x30, 0x36, 0x30, 0x38, 0x33, 0x34, 0x5A, 0x17, 0x0D, 0x33, 0x32, 0x30, 0x31, 0x30,
        0x33, 0x30, 0x36, 0x30, 0x38, 0x33, 0x34, 0x5A, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x6C, 0x20, 0x74, 0x65, 0x73,
        0x74, 0x20, 0x45, 0x43, 0x50, 0x32, 0x35, 0x36, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E,
        0x64, 0x65, 0x72, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62,
        0x00, 0x04, 0x8C, 0xF8, 0x84, 0x9D, 0x11, 0x07, 0x49, 0xCA, 0x1C, 0xD0, 0xB5, 0x11, 0xBC,
        0xE3, 0x4F, 0x38, 0x3C, 0xF0, 0xC5, 0x8D, 0x73, 0x5A, 0xA7, 0x63, 0x7E, 0x5F, 0x62, 0x60,
        0x7F, 0x10, 0x43, 0x34, 0xC8, 0x4F, 0x2C, 0xBC, 0x70, 0x8F, 0x4D, 0xA2, 0xFD, 0x4E, 0x03,
        0x89, 0x16, 0x49, 0xCA, 0x40, 0x6A, 0x91, 0x18, 0x09, 0x7F, 0x27, 0xEF, 0xE4, 0xA6, 0x26,
        0x1A, 0xFD, 0xD4, 0xD1, 0x57, 0xDB, 0x5B, 0x1B, 0x75, 0x05, 0xF9, 0x15, 0x9D, 0x33, 0x34,
        0xBE, 0x90, 0xB7, 0x5E, 0xD7, 0x05, 0xB9, 0x73, 0x85, 0x1E, 0x4A, 0xD3, 0x00, 0x5B, 0x7D,
        0x10, 0x68, 0xBF, 0x4F, 0xCA, 0xE6, 0x38, 0x4C, 0xA3, 0x81, 0x9C, 0x30, 0x81, 0x99, 0x30,
        0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B,
        0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xE0, 0x30, 0x1D, 0x06, 0x03,
        0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x1D, 0xEE, 0x4B, 0x09, 0x37, 0x82, 0xED, 0x77,
        0x92, 0x71, 0xA7, 0x4E, 0x3C, 0xAD, 0x32, 0xAD, 0xB8, 0xF7, 0x8E, 0x9B, 0x30, 0x31, 0x06,
        0x03, 0x55, 0x1D, 0x11, 0x04, 0x2A, 0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01,
        0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45,
        0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x30, 0x2A, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x01, 0x01, 0xFF, 0x04, 0x20,
        0x30, 0x1E, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07,
        0x03, 0x09, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03,
        0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x09, 0x0D, 0x98, 0x7A, 0xD6, 0xD1, 0x9A, 0x43, 0x45,
        0x1E, 0xBB, 0xC1, 0x0B, 0x23, 0x2E, 0xA4, 0x8A, 0x10, 0x32, 0xDB, 0xE1, 0x89, 0xBE, 0xDA,
        0x6A, 0x51, 0x36, 0x24, 0x48, 0x1F, 0x2F, 0x66, 0xA2, 0x6B, 0xDB, 0xAB, 0x78, 0x5E, 0x4A,
        0x5C, 0x57, 0x36, 0x9E, 0xAE, 0x72, 0x80, 0x6E, 0x2D, 0x02, 0x31, 0x00, 0x86, 0xD5, 0xD5,
        0x6C, 0x2B, 0x90, 0xFB, 0x3D, 0xB6, 0x84, 0x68, 0x93, 0xD3, 0xBD, 0xD8, 0xFC, 0x0D, 0x64,
        0x77, 0x36, 0x90, 0x8A, 0xE4, 0xBB, 0xD9, 0x60, 0x3B, 0x78, 0x9B, 0x58, 0x9A, 0x31, 0x71,
        0xCB, 0x83, 0xB8, 0xFE, 0x54, 0x6A, 0xAB, 0xF8, 0x3B, 0x07, 0x8B, 0xE0, 0xCE, 0x26, 0x6F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
};
