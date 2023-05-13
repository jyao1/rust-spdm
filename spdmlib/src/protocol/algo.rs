// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::config;
use bytes::BytesMut;
use codec::{enum_builder, u24, Codec, Reader, Writer};
use core::convert::From;
extern crate alloc;
use alloc::boxed::Box;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SHA256_DIGEST_SIZE: usize = 32;
pub const SHA384_DIGEST_SIZE: usize = 48;
pub const SHA512_DIGEST_SIZE: usize = 64;

pub const RSASSA_2048_KEY_SIZE: usize = 256;
pub const RSASSA_3072_KEY_SIZE: usize = 384;
pub const RSASSA_4096_KEY_SIZE: usize = 512;
pub const RSAPSS_2048_KEY_SIZE: usize = 256;
pub const RSAPSS_3072_KEY_SIZE: usize = 384;
pub const RSAPSS_4096_KEY_SIZE: usize = 512;

pub const ECDSA_ECC_NIST_P256_KEY_SIZE: usize = 32 * 2;
pub const ECDSA_ECC_NIST_P384_KEY_SIZE: usize = 48 * 2;
pub const ECDSA_ECC_NIST_P521_KEY_SIZE: usize = 66 * 2;

pub const SECP_256_R1_KEY_SIZE: usize = 32 * 2;
pub const SECP_384_R1_KEY_SIZE: usize = 48 * 2;
pub const SECP_521_R1_KEY_SIZE: usize = 66 * 2;

pub const AEAD_AES_128_GCM_KEY_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_KEY_SIZE: usize = 32;
pub const AEAD_CHACHA20_POLY1305_KEY_SIZE: usize = 32;

pub const AEAD_AES_128_GCM_BLOCK_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_BLOCK_SIZE: usize = 16;
pub const AEAD_CHACHA20_POLY1305_BLOCK_SIZE: usize = 16;

pub const AEAD_AES_128_GCM_IV_SIZE: usize = 12;
pub const AEAD_AES_256_GCM_IV_SIZE: usize = 12;
pub const AEAD_CHACHA20_POLY1305_IV_SIZE: usize = 12;

pub const AEAD_AES_128_GCM_TAG_SIZE: usize = 16;
pub const AEAD_AES_256_GCM_TAG_SIZE: usize = 16;
pub const AEAD_CHACHA20_POLY1305_TAG_SIZE: usize = 16;

pub const SPDM_NONCE_SIZE: usize = 32;
pub const SPDM_RANDOM_SIZE: usize = 32;
pub const SPDM_MAX_HASH_SIZE: usize = 64;
pub const SPDM_MAX_ASYM_KEY_SIZE: usize = 512;
pub const SPDM_MAX_DHE_KEY_SIZE: usize = SECP_384_R1_KEY_SIZE;
pub const SPDM_MAX_AEAD_KEY_SIZE: usize = 32;
pub const SPDM_MAX_AEAD_IV_SIZE: usize = 12;

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpdmDigestStruct {
    pub data_size: u16,
    pub data: Box<[u8; SPDM_MAX_HASH_SIZE]>,
}
impl Default for SpdmDigestStruct {
    fn default() -> SpdmDigestStruct {
        SpdmDigestStruct {
            data_size: 0,
            data: Box::new([0u8; SPDM_MAX_HASH_SIZE]),
        }
    }
}

impl AsRef<[u8]> for SpdmDigestStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..self.data_size as usize]
    }
}

impl From<BytesMut> for SpdmDigestStruct {
    fn from(value: BytesMut) -> Self {
        SpdmDigestStruct::from(value.as_ref())
    }
}

impl From<&[u8]> for SpdmDigestStruct {
    fn from(value: &[u8]) -> Self {
        // TODO: verify
        // ensure value.len() in 32 48 64
        assert!(value.len() <= SPDM_MAX_HASH_SIZE);
        let data_size = value.len() as u16;
        let mut data = Box::new([0u8; SPDM_MAX_HASH_SIZE]);
        data[0..value.len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementSpecification: u8 {
        const DMTF = 0b0000_0001;
    }
}

impl Codec for SpdmMeasurementSpecification {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementSpecification> {
        let bits = u8::read(r)?;
        SpdmMeasurementSpecification::from_bits(bits)
    }
}
impl SpdmMeasurementSpecification {
    pub fn prioritize(&mut self, peer: SpdmMeasurementSpecification) {
        let prio_table = [SpdmMeasurementSpecification::DMTF];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmMeasurementSpecification::empty();
    }

    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementHashAlgo: u32 {
        const RAW_BIT_STREAM = 0b0000_0001;
        const TPM_ALG_SHA_256 = 0b0000_0010;
        const TPM_ALG_SHA_384 = 0b0000_0100;
        const TPM_ALG_SHA_512 = 0b0000_1000;
    }
}

impl SpdmMeasurementHashAlgo {
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_256 => SHA256_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384 => SHA384_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_512 => SHA512_DIGEST_SIZE as u16,
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM => 0u16,
            _ => {
                panic!("invalid MeasurementHashAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }
}
impl Codec for SpdmMeasurementHashAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmMeasurementHashAlgo> {
        let bits = u32::read(r)?;

        SpdmMeasurementHashAlgo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmBaseAsymAlgo: u32 {
        const TPM_ALG_RSASSA_2048 = 0b0000_0001;
        const TPM_ALG_RSAPSS_2048 = 0b0000_0010;
        const TPM_ALG_RSASSA_3072 = 0b0000_0100;
        const TPM_ALG_RSAPSS_3072 = 0b0000_1000;
        const TPM_ALG_ECDSA_ECC_NIST_P256 = 0b0001_0000;
        const TPM_ALG_RSASSA_4096 = 0b0010_0000;
        const TPM_ALG_RSAPSS_4096 = 0b0100_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P384 = 0b1000_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P521 = 0b0000_0001_0000_0000;
    }
}

impl SpdmBaseAsymAlgo {
    pub fn prioritize(&mut self, peer: SpdmBaseAsymAlgo) {
        let prio_table = [
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmBaseAsymAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048 => RSASSA_2048_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048 => RSAPSS_2048_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072 => RSASSA_3072_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072 => RSAPSS_3072_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 => RSASSA_4096_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096 => RSAPSS_4096_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => ECDSA_ECC_NIST_P256_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => ECDSA_ECC_NIST_P384_KEY_SIZE as u16,
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P521 => ECDSA_ECC_NIST_P521_KEY_SIZE as u16,
            _ => {
                panic!("invalid AsymAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }
}

impl Codec for SpdmBaseAsymAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmBaseAsymAlgo> {
        let bits = u32::read(r)?;

        SpdmBaseAsymAlgo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmBaseHashAlgo: u32 {
        const TPM_ALG_SHA_256 = 0b0000_0001;
        const TPM_ALG_SHA_384 = 0b0000_0010;
        const TPM_ALG_SHA_512 = 0b0000_0100;
    }
}

impl SpdmBaseHashAlgo {
    pub fn prioritize(&mut self, peer: SpdmBaseHashAlgo) {
        let prio_table = [
            SpdmBaseHashAlgo::TPM_ALG_SHA_512,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmBaseHashAlgo::TPM_ALG_SHA_256,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmBaseHashAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmBaseHashAlgo::TPM_ALG_SHA_256 => SHA256_DIGEST_SIZE as u16,
            SpdmBaseHashAlgo::TPM_ALG_SHA_384 => SHA384_DIGEST_SIZE as u16,
            SpdmBaseHashAlgo::TPM_ALG_SHA_512 => SHA512_DIGEST_SIZE as u16,
            _ => {
                panic!("invalid HashAlgo");
            }
        }
    }

    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }
}

impl Codec for SpdmBaseHashAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmBaseHashAlgo> {
        let bits = u32::read(r)?;

        SpdmBaseHashAlgo::from_bits(bits)
    }
}

enum_builder! {
    @U8
    EnumName: SpdmStandardId;
    EnumVal{
        SpdmStandardIdDMTF => 0x0,
        SpdmStandardIdTCG => 0x1,
        SpdmStandardIdUSB => 0x2,
        SpdmStandardIdPCISIG => 0x3,
        SpdmStandardIdIANA => 0x4,
        SpdmStandardIdHDBaseT => 0x5,
        SpdmStandardIdMIPI => 0x6,
        SpdmStandardIdCXL => 0x7,
        SpdmStandardIdJDEC => 0x8
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmExtAlgStruct {
    pub registry_id: SpdmStandardId,
    pub reserved: u8,
    pub algorithm_id: u16,
}

impl Codec for SpdmExtAlgStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.registry_id.encode(bytes)?;
        cnt += self.reserved.encode(bytes)?;
        cnt += self.algorithm_id.encode(bytes)?;
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmExtAlgStruct> {
        let registry_id = SpdmStandardId::read(r)?;
        let reserved = u8::read(r)?;
        let algorithm_id = u16::read(r)?;

        Some(SpdmExtAlgStruct {
            registry_id,
            reserved,
            algorithm_id,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmDheAlgo: u16 {
        const SECP_256_R1 = 0b0000_1000;
        const SECP_384_R1 = 0b0001_0000;
        const SECP_521_R1 = 0b0010_0000;
    }
}

impl SpdmDheAlgo {
    pub fn prioritize(&mut self, peer: SpdmDheAlgo) {
        let prio_table = [SpdmDheAlgo::SECP_384_R1, SpdmDheAlgo::SECP_256_R1];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmDheAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmDheAlgo::SECP_256_R1 => SECP_256_R1_KEY_SIZE as u16,
            SpdmDheAlgo::SECP_384_R1 => SECP_384_R1_KEY_SIZE as u16,
            SpdmDheAlgo::SECP_521_R1 => SECP_521_R1_KEY_SIZE as u16,
            _ => {
                panic!("invalid DheAlgo");
            }
        }
    }
}

impl Codec for SpdmDheAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmDheAlgo> {
        let bits = u16::read(r)?;

        SpdmDheAlgo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmAeadAlgo: u16 {
        const AES_128_GCM = 0b0000_0001;
        const AES_256_GCM = 0b0000_0010;
        const CHACHA20_POLY1305 = 0b0000_0100;
    }
}

impl SpdmAeadAlgo {
    pub fn prioritize(&mut self, peer: SpdmAeadAlgo) {
        let prio_table = [
            SpdmAeadAlgo::AES_256_GCM,
            SpdmAeadAlgo::AES_128_GCM,
            SpdmAeadAlgo::CHACHA20_POLY1305,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmAeadAlgo::empty();
    }
    pub fn get_key_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_KEY_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_KEY_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_KEY_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }
    pub fn get_iv_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_IV_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_IV_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_IV_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }
    pub fn get_tag_size(&self) -> u16 {
        match *self {
            SpdmAeadAlgo::AES_128_GCM => AEAD_AES_128_GCM_TAG_SIZE as u16,
            SpdmAeadAlgo::AES_256_GCM => AEAD_AES_256_GCM_TAG_SIZE as u16,
            SpdmAeadAlgo::CHACHA20_POLY1305 => AEAD_CHACHA20_POLY1305_TAG_SIZE as u16,
            _ => {
                panic!("invalid AeadAlgo");
            }
        }
    }
}

impl Codec for SpdmAeadAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmAeadAlgo> {
        let bits = u16::read(r)?;

        SpdmAeadAlgo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmReqAsymAlgo: u16 {
        const TPM_ALG_RSASSA_2048 = 0b0000_0001;
        const TPM_ALG_RSAPSS_2048 = 0b0000_0010;
        const TPM_ALG_RSASSA_3072 = 0b0000_0100;
        const TPM_ALG_RSAPSS_3072 = 0b0000_1000;
        const TPM_ALG_ECDSA_ECC_NIST_P256 = 0b0001_0000;
        const TPM_ALG_RSASSA_4096 = 0b0010_0000;
        const TPM_ALG_RSAPSS_4096 = 0b0100_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P384 = 0b1000_0000;
        const TPM_ALG_ECDSA_ECC_NIST_P521 = 0b0000_0001_0000_0000;
    }
}

impl SpdmReqAsymAlgo {
    pub fn prioritize(&mut self, peer: SpdmReqAsymAlgo) {
        let prio_table = [
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048,
        ];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmReqAsymAlgo::empty();
    }
    pub fn get_size(&self) -> u16 {
        match *self {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048 => RSASSA_2048_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048 => RSAPSS_2048_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072 => RSASSA_3072_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072 => RSAPSS_3072_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096 => RSASSA_4096_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096 => RSAPSS_4096_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256 => ECDSA_ECC_NIST_P256_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384 => ECDSA_ECC_NIST_P384_KEY_SIZE as u16,
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P521 => ECDSA_ECC_NIST_P521_KEY_SIZE as u16,
            _ => {
                panic!("invalid ReqAsymAlgo");
            }
        }
    }
}

impl Codec for SpdmReqAsymAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmReqAsymAlgo> {
        let bits = u16::read(r)?;

        SpdmReqAsymAlgo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmKeyScheduleAlgo: u16 {
        const SPDM_KEY_SCHEDULE = 0b0000_0001;
    }
}

impl SpdmKeyScheduleAlgo {
    pub fn prioritize(&mut self, peer: SpdmKeyScheduleAlgo) {
        let prio_table = [SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE];

        *self &= peer;
        for v in prio_table.iter() {
            if self.bits() & v.bits() != 0 {
                *self = *v;
                return;
            }
        }
        *self = SpdmKeyScheduleAlgo::empty();
    }
}

impl Codec for SpdmKeyScheduleAlgo {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmKeyScheduleAlgo> {
        let bits = u16::read(r)?;

        SpdmKeyScheduleAlgo::from_bits(bits)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpdmUnknownAlgo {}
impl Codec for SpdmUnknownAlgo {
    fn encode(&self, _bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        Ok(0)
    }

    fn read(_r: &mut Reader) -> Option<SpdmUnknownAlgo> {
        Some(SpdmUnknownAlgo {})
    }
}

enum_builder! {
    @U8
    EnumName: SpdmAlgType;
    EnumVal{
        SpdmAlgTypeDHE => 0x2,
        SpdmAlgTypeAEAD => 0x3,
        SpdmAlgTypeReqAsym => 0x4,
        SpdmAlgTypeKeySchedule => 0x5
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpdmAlg {
    SpdmAlgoDhe(SpdmDheAlgo),
    SpdmAlgoAead(SpdmAeadAlgo),
    SpdmAlgoReqAsym(SpdmReqAsymAlgo),
    SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo),
    // TBD: Need consider how to handle this SpdmAlgoUnknown
    SpdmAlgoUnknown(SpdmUnknownAlgo),
}
impl Default for SpdmAlg {
    fn default() -> SpdmAlg {
        SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmAlgStruct {
    pub alg_type: SpdmAlgType,
    pub alg_fixed_count: u8,
    pub alg_supported: SpdmAlg,
    pub alg_ext_count: u8, // for output only. Always treat as 0 on input.
}

impl Codec for SpdmAlgStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        // DSP0274 Table: Algorithm request structure
        assert_eq!((self.alg_fixed_count + 2) % 4, 0);
        assert_eq!(self.alg_ext_count, 0);
        cnt += self.alg_type.encode(bytes)?;
        let alg_count = ((self.alg_fixed_count as u32) << 4) as u8;
        cnt += alg_count.encode(bytes)?;

        if self.alg_fixed_count == 2 {
            match &self.alg_supported {
                SpdmAlg::SpdmAlgoDhe(alg_supported) => {
                    cnt += alg_supported.encode(bytes)?;
                }
                SpdmAlg::SpdmAlgoAead(alg_supported) => {
                    cnt += alg_supported.encode(bytes)?;
                }
                SpdmAlg::SpdmAlgoReqAsym(alg_supported) => {
                    cnt += alg_supported.encode(bytes)?;
                }
                SpdmAlg::SpdmAlgoKeySchedule(alg_supported) => {
                    cnt += alg_supported.encode(bytes)?;
                }
                SpdmAlg::SpdmAlgoUnknown(alg_supported) => {
                    cnt += alg_supported.encode(bytes)?;
                }
            }
        }
        Ok(cnt)
    }

    fn read(r: &mut Reader) -> Option<SpdmAlgStruct> {
        let alg_type = SpdmAlgType::read(r)?;
        let alg_count = u8::read(r)?;
        let alg_fixed_count = ((alg_count as u32 >> 4) & 0xF) as u8;
        let alg_ext_count = alg_count & 0xF;

        let alg_supported = match alg_type {
            SpdmAlgType::SpdmAlgTypeDHE => Some(SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::read(r)?)),
            SpdmAlgType::SpdmAlgTypeAEAD => Some(SpdmAlg::SpdmAlgoAead(SpdmAeadAlgo::read(r)?)),
            SpdmAlgType::SpdmAlgTypeReqAsym => {
                Some(SpdmAlg::SpdmAlgoReqAsym(SpdmReqAsymAlgo::read(r)?))
            }
            SpdmAlgType::SpdmAlgTypeKeySchedule => {
                Some(SpdmAlg::SpdmAlgoKeySchedule(SpdmKeyScheduleAlgo::read(r)?))
            }
            _ => Some(SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {})),
        };

        let alg_supported = alg_supported?;

        for _ in 0..(alg_ext_count as usize) {
            SpdmExtAlgStruct::read(r)?;
        }

        Some(SpdmAlgStruct {
            alg_type,
            alg_fixed_count,
            alg_supported,
            alg_ext_count,
        })
    }
}

pub const SPDM_MAX_SLOT_NUMBER: usize = 8;

enum_builder! {
    @U8
    EnumName: SpdmMeasurementSummaryHashType;
    EnumVal{
        SpdmMeasurementSummaryHashTypeNone => 0x0,
        SpdmMeasurementSummaryHashTypeTcb => 0x1,
        SpdmMeasurementSummaryHashTypeAll => 0xFF
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmNonceStruct {
    pub data: [u8; SPDM_NONCE_SIZE],
}

impl Codec for SpdmNonceStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        for d in self.data.iter() {
            d.encode(bytes)?;
        }
        Ok(SPDM_NONCE_SIZE)
    }
    fn read(r: &mut Reader) -> Option<SpdmNonceStruct> {
        let mut data = [0u8; SPDM_NONCE_SIZE];
        for d in data.iter_mut() {
            *d = u8::read(r)?;
        }
        Some(SpdmNonceStruct { data })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmRandomStruct {
    pub data: [u8; SPDM_RANDOM_SIZE],
}

impl Codec for SpdmRandomStruct {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        for d in self.data.iter() {
            d.encode(bytes)?;
        }
        Ok(SPDM_RANDOM_SIZE)
    }
    fn read(r: &mut Reader) -> Option<SpdmRandomStruct> {
        let mut data = [0u8; SPDM_RANDOM_SIZE];
        for d in data.iter_mut() {
            *d = u8::read(r)?;
        }
        Some(SpdmRandomStruct { data })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmSignatureStruct {
    pub data_size: u16,
    pub data: [u8; SPDM_MAX_ASYM_KEY_SIZE],
}
impl Default for SpdmSignatureStruct {
    fn default() -> SpdmSignatureStruct {
        SpdmSignatureStruct {
            data_size: 0,
            data: [0u8; SPDM_MAX_ASYM_KEY_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmSignatureStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmSignatureStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_ASYM_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmHKDFKeyStruct {
    pub data_size: u16,
    pub data: [u8; SPDM_MAX_ASYM_KEY_SIZE],
}
impl Default for SpdmHKDFKeyStruct {
    fn default() -> SpdmHKDFKeyStruct {
        SpdmHKDFKeyStruct {
            data_size: 0,
            data: [0u8; SPDM_MAX_ASYM_KEY_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmHKDFKeyStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmHKDFKeyStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_ASYM_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmCertChainData {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
}

impl Default for SpdmCertChainData {
    fn default() -> Self {
        SpdmCertChainData {
            data_size: 0u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }
    }
}
impl AsRef<[u8]> for SpdmCertChainData {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

#[derive(Default, Debug, Clone)]
pub struct SpdmCertChain {
    pub root_hash: SpdmDigestStruct,
    pub cert_chain: SpdmCertChainData,
}

enum_builder! {
    @U8
    EnumName: SpdmDmtfMeasurementType;
    EnumVal{
        SpdmDmtfMeasurementRom => 0x0,
        SpdmDmtfMeasurementFirmware => 0x1,
        SpdmDmtfMeasurementHardwareConfig => 0x2,
        SpdmDmtfMeasurementFirmwareConfig => 0x3,
        SpdmDmtfMeasurementManifest => 0x4,
        SpdmDmtfMeasurementStructuredRepresentationMode => 0x5,
        SpdmDmtfMeasurementMutableFirmwareVersionNumber => 0x6,
        SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber => 0x7
    }
}

enum_builder! {
    @U8
    EnumName: SpdmDmtfMeasurementRepresentation;
    EnumVal{
        SpdmDmtfMeasurementDigest => 0x0,
        SpdmDmtfMeasurementRawBit => 0x80
    }
}

#[derive(Debug, Clone)]
pub struct SpdmDmtfMeasurementStructure {
    pub r#type: SpdmDmtfMeasurementType,
    pub representation: SpdmDmtfMeasurementRepresentation,
    pub value_size: u16,
    pub value: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
}
impl Default for SpdmDmtfMeasurementStructure {
    fn default() -> SpdmDmtfMeasurementStructure {
        SpdmDmtfMeasurementStructure {
            r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            value_size: 0,
            value: [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
        }
    }
}
impl Codec for SpdmDmtfMeasurementStructure {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        let type_value = self.r#type.get_u8();
        let representation_value = self.representation.get_u8();
        let final_value = type_value + representation_value;
        cnt += final_value.encode(bytes)?;

        // TBD: Check measurement_hash

        cnt += self.value_size.encode(bytes)?;
        for v in self.value.iter().take(self.value_size as usize) {
            cnt += v.encode(bytes)?;
        }
        Ok(cnt)
    }
    fn read(r: &mut Reader) -> Option<SpdmDmtfMeasurementStructure> {
        let final_value = u8::read(r)?;
        let type_value = final_value & 0x7f;
        let representation_value = final_value & 0x80;
        let representation = match representation_value {
            0 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
            0x80 => SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
            val => SpdmDmtfMeasurementRepresentation::Unknown(val),
        };
        let r#type = match type_value {
            0 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom,
            1 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware,
            2 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig,
            3 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig,
            4 => SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest,
            5 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementStructuredRepresentationMode
                }
                _ => SpdmDmtfMeasurementType::Unknown(5),
            },
            6 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(6),
            },
            7 => match representation {
                SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit => {
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementMutableFirmwareSecurityVersionNumber
                }
                _ => SpdmDmtfMeasurementType::Unknown(7),
            },
            val => SpdmDmtfMeasurementType::Unknown(val),
        };

        // TBD: Check measurement_hash

        let value_size = u16::read(r)?;
        let mut value = [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];
        for v in value.iter_mut().take(value_size as usize) {
            *v = u8::read(r)?;
        }
        Some(SpdmDmtfMeasurementStructure {
            r#type,
            representation,
            value_size,
            value,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmMeasurementBlockStructure {
    pub index: u8,
    pub measurement_specification: SpdmMeasurementSpecification,
    pub measurement_size: u16,
    pub measurement: SpdmDmtfMeasurementStructure,
}
impl Codec for SpdmMeasurementBlockStructure {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        let mut cnt = 0usize;
        cnt += self.index.encode(bytes)?;
        cnt += self.measurement_specification.encode(bytes)?;
        cnt += self.measurement_size.encode(bytes)?;
        cnt += self.measurement.encode(bytes)?;
        Ok(cnt)
    }
    fn read(r: &mut Reader) -> Option<SpdmMeasurementBlockStructure> {
        let index = u8::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        let measurement_size = u16::read(r)?;
        let measurement = SpdmDmtfMeasurementStructure::read(r)?;
        Some(SpdmMeasurementBlockStructure {
            index,
            measurement_specification,
            measurement_size,
            measurement,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmMeasurementRecordStructure {
    pub number_of_blocks: u8,
    pub measurement_record_length: u24,
    pub measurement_record_data: [u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
}
impl Default for SpdmMeasurementRecordStructure {
    fn default() -> SpdmMeasurementRecordStructure {
        SpdmMeasurementRecordStructure {
            number_of_blocks: 0,
            measurement_record_length: u24::new(0),
            measurement_record_data: [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN],
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmDheExchangeStruct {
    pub data_size: u16,
    pub data: [u8; SPDM_MAX_DHE_KEY_SIZE],
}
impl Default for SpdmDheExchangeStruct {
    fn default() -> SpdmDheExchangeStruct {
        SpdmDheExchangeStruct {
            data_size: 0,
            data: [0u8; SPDM_MAX_DHE_KEY_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmDheExchangeStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmDheExchangeStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_DHE_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = [0u8; SPDM_MAX_DHE_KEY_SIZE];
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpdmDheFinalKeyStruct {
    pub data_size: u16,
    pub data: Box<[u8; SPDM_MAX_DHE_KEY_SIZE]>,
}
impl Default for SpdmDheFinalKeyStruct {
    fn default() -> SpdmDheFinalKeyStruct {
        SpdmDheFinalKeyStruct {
            data_size: 0,
            data: Box::new([0u8; SPDM_MAX_DHE_KEY_SIZE]),
        }
    }
}

impl AsRef<[u8]> for SpdmDheFinalKeyStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

impl From<BytesMut> for SpdmDheFinalKeyStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_DHE_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = Box::new([0u8; SPDM_MAX_DHE_KEY_SIZE]);
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone)]
pub struct SpdmPskContextStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_PSK_CONTEXT_SIZE],
}
impl Default for SpdmPskContextStruct {
    fn default() -> SpdmPskContextStruct {
        SpdmPskContextStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_PSK_CONTEXT_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmPskContextStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

#[derive(Debug, Clone)]
pub struct SpdmPskHintStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_PSK_HINT_SIZE],
}
impl Default for SpdmPskHintStruct {
    fn default() -> SpdmPskHintStruct {
        SpdmPskHintStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_PSK_HINT_SIZE],
        }
    }
}

impl AsRef<[u8]> for SpdmPskHintStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..(self.data_size as usize)]
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpdmAeadKeyStruct {
    pub data_size: u16,
    pub data: Box<[u8; SPDM_MAX_AEAD_KEY_SIZE]>,
}
impl Default for SpdmAeadKeyStruct {
    fn default() -> SpdmAeadKeyStruct {
        SpdmAeadKeyStruct {
            data_size: 0,
            data: Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]),
        }
    }
}

impl AsRef<[u8]> for SpdmAeadKeyStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..self.data_size as usize]
    }
}

impl From<BytesMut> for SpdmAeadKeyStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_AEAD_KEY_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = Box::new([0u8; SPDM_MAX_AEAD_KEY_SIZE]);
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpdmAeadIvStruct {
    pub data_size: u16,
    pub data: Box<[u8; SPDM_MAX_AEAD_IV_SIZE]>,
}
impl Default for SpdmAeadIvStruct {
    fn default() -> SpdmAeadIvStruct {
        SpdmAeadIvStruct {
            data_size: 0,
            data: Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]),
        }
    }
}

impl AsRef<[u8]> for SpdmAeadIvStruct {
    fn as_ref(&self) -> &[u8] {
        &self.data[0..self.data_size as usize]
    }
}

impl From<BytesMut> for SpdmAeadIvStruct {
    fn from(value: BytesMut) -> Self {
        assert!(value.as_ref().len() <= SPDM_MAX_AEAD_IV_SIZE);
        let data_size = value.as_ref().len() as u16;
        let mut data = Box::new([0u8; SPDM_MAX_AEAD_IV_SIZE]);
        data[0..value.as_ref().len()].copy_from_slice(value.as_ref());
        Self { data_size, data }
    }
}

#[cfg(all(test,))]
mod tests {
    use super::*;
    use codec::{Codec, Reader, Writer};

    #[test]
    fn test_case0_spdm_measurement_specification() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementSpecification::all();
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementSpecification::read(&mut reader).unwrap(),
            SpdmMeasurementSpecification::DMTF
        );
        assert_eq!(3, reader.left());
    }
    #[test]
    fn test_case0_spdm_measurement_hash_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmMeasurementHashAlgo::read(&mut reader).unwrap(),
            SpdmMeasurementHashAlgo::RAW_BIT_STREAM
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_base_asym_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmBaseAsymAlgo::read(&mut reader).unwrap(),
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_base_hash_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmBaseHashAlgo::TPM_ALG_SHA_256;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmBaseHashAlgo::read(&mut reader).unwrap(),
            SpdmBaseHashAlgo::TPM_ALG_SHA_256
        );
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_ext_alg_struct() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmExtAlgStruct {
            registry_id: SpdmStandardId::SpdmStandardIdDMTF,
            reserved: 100,
            algorithm_id: 200,
        };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        let spdm_ext_alg_struct = SpdmExtAlgStruct::read(&mut reader).unwrap();
        assert_eq!(
            spdm_ext_alg_struct.registry_id,
            SpdmStandardId::SpdmStandardIdDMTF
        );
        assert_eq!(spdm_ext_alg_struct.reserved, 100);
        assert_eq!(spdm_ext_alg_struct.algorithm_id, 200);
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case1_spdm_ext_alg_struct() {
        let u8_slice = &mut [0u8; 2];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmExtAlgStruct {
            registry_id: SpdmStandardId::SpdmStandardIdDMTF,
            reserved: 100,
            algorithm_id: 200,
        };
        assert!(value.encode(&mut writer).is_err());
        let mut reader = Reader::init(u8_slice);

        assert_eq!(SpdmExtAlgStruct::read(&mut reader).is_none(), true);
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_dhe_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmDheAlgo::SECP_256_R1;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmDheAlgo::read(&mut reader).unwrap(),
            SpdmDheAlgo::SECP_256_R1
        );
        assert_eq!(2, reader.left());
    }

    #[test]
    fn test_case0_spdm_aead_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAeadAlgo::AES_128_GCM;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmAeadAlgo::read(&mut reader).unwrap(),
            SpdmAeadAlgo::AES_128_GCM
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_req_asym_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmReqAsymAlgo::read(&mut reader).unwrap(),
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_key_schedule_algo() {
        let u8_slice = &mut [0u8; 4];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(
            SpdmKeyScheduleAlgo::read(&mut reader).unwrap(),
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE
        );
        assert_eq!(2, reader.left());
    }
    #[test]
    fn test_case0_spdm_nonce_struct() {
        let u8_slice = &mut [0u8; 32];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmNonceStruct { data: [100u8; 32] };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(32, reader.left());
        let spdm_nonce_struct = SpdmNonceStruct::read(&mut reader).unwrap();

        for i in 0..32 {
            assert_eq!(spdm_nonce_struct.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }

    #[test]
    fn test_case0_spdm_random_struct() {
        let u8_slice = &mut [0u8; 32];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmRandomStruct { data: [100u8; 32] };
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        assert_eq!(32, reader.left());
        let spdm_random_struct = SpdmRandomStruct::read(&mut reader).unwrap();

        for i in 0..32 {
            assert_eq!(spdm_random_struct.data[i], 100);
        }
        assert_eq!(0, reader.left());
    }
    #[test]
    fn test_case0_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
            alg_fixed_count: 2,
            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
            alg_ext_count: 0,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_alg_struct = SpdmAlgStruct::read(&mut reader).unwrap();
        assert_eq!(4, reader.left());
        assert_eq!(spdm_alg_struct.alg_type, SpdmAlgType::SpdmAlgTypeDHE);
        assert_eq!(spdm_alg_struct.alg_fixed_count, 2);
        assert_eq!(spdm_alg_struct.alg_ext_count, 0);
        assert_eq!(
            spdm_alg_struct.alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
    }
    #[test]
    #[should_panic]
    fn test_case1_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
            alg_fixed_count: 0,
            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
            alg_ext_count: 0,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_alg_struct = SpdmAlgStruct::read(&mut reader).unwrap();
        assert_eq!(spdm_alg_struct.alg_type, SpdmAlgType::SpdmAlgTypeDHE);
        assert_eq!(spdm_alg_struct.alg_fixed_count, 0);
        assert_eq!(spdm_alg_struct.alg_ext_count, 0);
        assert_eq!(
            spdm_alg_struct.alg_supported,
            SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1)
        );
    }
    #[test]
    #[should_panic]
    fn test_case2_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::SpdmAlgTypeDHE,
            alg_fixed_count: 0,
            alg_supported: SpdmAlg::SpdmAlgoDhe(SpdmDheAlgo::SECP_256_R1),
            alg_ext_count: 100,
        };
        assert!(value.encode(&mut writer).is_ok());
    }
    #[test]
    fn test_case3_spdm_alg_struct() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let spdmalg = SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {});
        let value = SpdmAlgStruct {
            alg_type: SpdmAlgType::Unknown(1),
            alg_fixed_count: 2,
            alg_supported: SpdmAlg::SpdmAlgoUnknown(SpdmUnknownAlgo {}),
            alg_ext_count: 0,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_alg_struct = SpdmAlgStruct::read(&mut reader).unwrap();

        assert_eq!(spdm_alg_struct.alg_type, SpdmAlgType::Unknown(1));
        assert_eq!(spdm_alg_struct.alg_fixed_count, 2);
        assert_eq!(spdm_alg_struct.alg_ext_count, 0);
        assert_eq!(spdm_alg_struct.alg_supported, spdmalg);
    }
    #[test]
    fn test_case0_spdm_digest_struct() {
        let bytes_mut = BytesMut::new();
        let u8_slice = &mut [0u8; 68];
        let mut _writer = Writer::init(u8_slice);
        let _value = SpdmDigestStruct {
            data_size: 64,
            data: Box::new([100u8; SPDM_MAX_HASH_SIZE]),
        };

        // TODO: assert should use should_panic
        let spdm_digest_struct = SpdmDigestStruct::from(bytes_mut);
        assert_eq!(spdm_digest_struct.data_size, 0);
    }
    #[test]
    fn test_case1_spdm_measurement_specification() {
        let value = SpdmMeasurementSpecification::DMTF;
        let mut spdm_measurement_specification = SpdmMeasurementSpecification::empty();
        spdm_measurement_specification.prioritize(value);
    }
    #[test]
    fn test_case1_spdm_signature_struct() {
        let bytes_mut = bytes::BytesMut::new();
        let spdm_signature_struct = SpdmSignatureStruct::from(bytes_mut);
        assert_eq!(spdm_signature_struct.data_size, 0);
        for i in 0..512 {
            assert_eq!(spdm_signature_struct.data[i], 0);
        }
    }

    #[test]
    #[should_panic(expected = "invalid MeasurementHashAlgo")]
    fn test_case1_spdm_measurement_hash_algo() {
        let mut value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_256;
        assert_eq!(value.get_size(), SHA256_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        assert_eq!(value.get_size(), SHA384_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::TPM_ALG_SHA_512;
        assert_eq!(value.get_size(), SHA512_DIGEST_SIZE as u16);

        value = SpdmMeasurementHashAlgo::RAW_BIT_STREAM;
        assert_eq!(value.get_size(), 0u16);

        value = SpdmMeasurementHashAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid AsymAlgo")]
    fn test_case1_spdm_base_asym_algo() {
        let mut value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048;
        assert_eq!(value.get_size(), RSASSA_2048_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048;
        assert_eq!(value.get_size(), RSAPSS_2048_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072;
        assert_eq!(value.get_size(), RSASSA_3072_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072;
        assert_eq!(value.get_size(), RSAPSS_3072_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096;
        assert_eq!(value.get_size(), RSASSA_4096_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096;
        assert_eq!(value.get_size(), RSAPSS_4096_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P256_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P384_KEY_SIZE as u16);

        value = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P521;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P521_KEY_SIZE as u16);
        value = SpdmBaseAsymAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid DheAlgo")]
    fn test_case1_spdm_dhe_algo() {
        let mut value = SpdmDheAlgo::SECP_256_R1;
        assert_eq!(value.get_size(), SECP_256_R1_KEY_SIZE as u16);

        value = SpdmDheAlgo::SECP_384_R1;
        assert_eq!(value.get_size(), SECP_384_R1_KEY_SIZE as u16);

        value = SpdmDheAlgo::SECP_521_R1;
        assert_eq!(value.get_size(), SECP_521_R1_KEY_SIZE as u16);

        value = SpdmDheAlgo::empty();
        value.get_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case1_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_128_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_256_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_key_size(), AEAD_CHACHA20_POLY1305_KEY_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_key_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case2_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_128_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_key_size(), AEAD_AES_256_GCM_KEY_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_key_size(), AEAD_CHACHA20_POLY1305_KEY_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_key_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case3_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_iv_size(), AEAD_AES_128_GCM_IV_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_iv_size(), AEAD_AES_256_GCM_IV_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_iv_size(), AEAD_CHACHA20_POLY1305_IV_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_iv_size();
    }
    #[test]
    #[should_panic(expected = "invalid AeadAlgo")]
    fn test_case4_spdm_aead_algo() {
        let mut value = SpdmAeadAlgo::AES_128_GCM;
        assert_eq!(value.get_tag_size(), AEAD_AES_128_GCM_TAG_SIZE as u16);

        value = SpdmAeadAlgo::AES_256_GCM;
        assert_eq!(value.get_tag_size(), AEAD_AES_256_GCM_TAG_SIZE as u16);

        value = SpdmAeadAlgo::CHACHA20_POLY1305;
        assert_eq!(value.get_tag_size(), AEAD_CHACHA20_POLY1305_TAG_SIZE as u16);

        value = SpdmAeadAlgo::empty();
        value.get_tag_size();
    }
    #[test]
    #[should_panic(expected = "invalid ReqAsymAlgo")]
    fn test_case1_spdm_req_asym_algo() {
        let mut value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_2048;
        assert_eq!(value.get_size(), RSASSA_2048_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        assert_eq!(value.get_size(), RSAPSS_2048_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072;
        assert_eq!(value.get_size(), RSASSA_3072_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_3072;
        assert_eq!(value.get_size(), RSAPSS_3072_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSASSA_4096;
        assert_eq!(value.get_size(), RSASSA_4096_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_4096;
        assert_eq!(value.get_size(), RSAPSS_4096_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P256_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P384_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P521;
        assert_eq!(value.get_size(), ECDSA_ECC_NIST_P521_KEY_SIZE as u16);

        value = SpdmReqAsymAlgo::empty();
        value.get_size();
    }
    #[test]
    fn test_case0_spdm_unknown_algo() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmUnknownAlgo {};
        assert!(value.encode(&mut writer).is_ok());
        let mut reader = Reader::init(u8_slice);
        SpdmUnknownAlgo::read(&mut reader);
    }
}
