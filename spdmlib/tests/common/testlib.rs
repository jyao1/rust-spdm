// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]

use spdmlib::common::*;
use spdmlib::crypto::{self, SpdmCryptoRandom, SpdmHmac};
use spdmlib::protocol::*;
use spdmlib::secret::SpdmSecretAsymSign;
use spdmlib::{common, responder};

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use spdmlib::error::{
    SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_ENCAP_FAIL, SPDM_STATUS_SEND_FAIL,
    SPDM_STATUS_VERIF_FAIL,
};
use spdmlib::message::*;
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
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,

        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
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
            return Err(SPDM_STATUS_SEND_FAIL);
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
    let cert_chain = include_bytes!("../../../test_key/EcP384/bundle_responder.certchain.der");

    let (root_cert_begin, root_cert_end) =
        crypto::cert_operation::get_cert_from_cert_chain(cert_chain, 0)
            .expect("Get provisioned root cert failed");

    let root_cert_hash =
        crypto::hash::hash_all(hash_algo, &cert_chain[root_cert_begin..root_cert_end])
            .expect("Must provide hash algo");
    SpdmCertChainBuffer::new(cert_chain, root_cert_hash.as_ref())
        .expect("Create format certificate chain failed.")
}
