// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::config;
use crate::msgs::SpdmCodec;
pub use crate::msgs::*;

use codec::{Codec, Reader, Writer};

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmNegotiateAlgorithmsRequestPayload {
    pub measurement_specification: SpdmMeasurementSpecification,
    pub base_asym_algo: SpdmBaseAsymAlgo,
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub alg_struct_count: u8,
    pub alg_struct: [SpdmAlgStruct; config::MAX_SPDM_ALG_STRUCT_COUNT],
}

impl SpdmCodec for SpdmNegotiateAlgorithmsRequestPayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.alg_struct_count.encode(bytes); // param1
        0u8.encode(bytes); // param1

        let mut length: u16 = 32;
        for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            length += 2 + algo.alg_fixed_count as u16;
        }
        length.encode(bytes);

        self.measurement_specification.encode(bytes);
        0u8.encode(bytes); // reserved

        self.base_asym_algo.encode(bytes);
        self.base_hash_algo.encode(bytes);
        for _i in 0..12 {
            0u8.encode(bytes); // reserved2
        }

        0u8.encode(bytes); // ext_asym_count

        0u8.encode(bytes); // ext_hash_count

        0u16.encode(bytes); // reserved3

        for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            algo.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmNegotiateAlgorithmsRequestPayload> {
        let alg_struct_count = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let length = u16::read(r)?;
        let measurement_specification = SpdmMeasurementSpecification::read(r)?;
        u8::read(r)?; // reserved

        let base_asym_algo = SpdmBaseAsymAlgo::read(r)?;
        let base_hash_algo = SpdmBaseHashAlgo::read(r)?;

        for _i in 0..12 {
            u8::read(r)?; // reserved2
        }

        let ext_asym_count = u8::read(r)?;
        for _ in 0..(ext_asym_count as usize) {
            SpdmExtAlgStruct::read(r)?;
        }

        let ext_hash_count = u8::read(r)?;
        for _ in 0..(ext_hash_count as usize) {
            SpdmExtAlgStruct::read(r)?;
        }

        u16::read(r)?; // reserved3

        let mut alg_struct = [SpdmAlgStruct::default(); config::MAX_SPDM_ALG_STRUCT_COUNT];
        for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
            *algo = SpdmAlgStruct::read(r)?;
        }

        //
        // check length
        //
        let mut calc_length: u16 = 32 + (4 * ext_asym_count as u16) + (4 * ext_hash_count as u16);
        for alg in alg_struct.iter().take(alg_struct_count as usize) {
            calc_length += 2 + alg.alg_fixed_count as u16 + (4 * alg.alg_ext_count as u16);
        }

        if length != calc_length {
            return None;
        }

        Some(SpdmNegotiateAlgorithmsRequestPayload {
            measurement_specification,
            base_asym_algo,
            base_hash_algo,
            alg_struct_count,
            alg_struct,
        })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmAlgorithmsResponsePayload {
    pub measurement_specification_sel: SpdmMeasurementSpecification,
    pub measurement_hash_algo: SpdmMeasurementHashAlgo,
    pub base_asym_sel: SpdmBaseAsymAlgo,
    pub base_hash_sel: SpdmBaseHashAlgo,
    pub alg_struct_count: u8,
    pub alg_struct: [SpdmAlgStruct; config::MAX_SPDM_ALG_STRUCT_COUNT],
}

impl SpdmCodec for SpdmAlgorithmsResponsePayload {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.alg_struct_count.encode(bytes); // param1
        0u8.encode(bytes); // param2

        let mut length: u16 = 36;
        for alg in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            length += 2 + alg.alg_fixed_count as u16;
        }
        length.encode(bytes);

        self.measurement_specification_sel.encode(bytes);
        0u8.encode(bytes); // reserved

        self.measurement_hash_algo.encode(bytes);
        self.base_asym_sel.encode(bytes);
        self.base_hash_sel.encode(bytes);
        for _i in 0..12 {
            0u8.encode(bytes); // reserved2
        }

        0u8.encode(bytes); // ext_asym_count

        0u8.encode(bytes); // ext_hash_count

        0u16.encode(bytes); // reserved3

        for algo in self.alg_struct.iter().take(self.alg_struct_count as usize) {
            algo.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmAlgorithmsResponsePayload> {
        let alg_struct_count = u8::read(r)?; // param1
        u8::read(r)?; // param2

        let length = u16::read(r)?;

        let measurement_specification_sel = SpdmMeasurementSpecification::read(r)?;
        u8::read(r)?; // reserved

        let measurement_hash_algo = SpdmMeasurementHashAlgo::read(r)?;
        let base_asym_sel = SpdmBaseAsymAlgo::read(r)?;
        let base_hash_sel = SpdmBaseHashAlgo::read(r)?;

        for _i in 0..12 {
            u8::read(r)?; // reserved2
        }

        let ext_asym_count = u8::read(r)?;
        for _ in 0..(ext_asym_count as usize) {
            SpdmExtAlgStruct::read(r)?;
        }

        let ext_hash_count = u8::read(r)?;
        for _ in 0..(ext_hash_count as usize) {
            SpdmExtAlgStruct::read(r)?;
        }

        u16::read(r)?; // reserved3

        let mut alg_struct = [SpdmAlgStruct::default(); config::MAX_SPDM_ALG_STRUCT_COUNT];
        for algo in alg_struct.iter_mut().take(alg_struct_count as usize) {
            *algo = SpdmAlgStruct::read(r)?;
        }

        let mut calc_length: u16 = 36 + (4 * ext_asym_count as u16) + (4 * ext_hash_count as u16);
        for algo in alg_struct.iter().take(alg_struct_count as usize) {
            calc_length += 2 + algo.alg_fixed_count as u16 + (4 * algo.alg_ext_count as u16);
        }

        if length != calc_length {
            return None;
        }

        Some(SpdmAlgorithmsResponsePayload {
            measurement_specification_sel,
            measurement_hash_algo,
            base_asym_sel,
            base_hash_sel,
            alg_struct_count,
            alg_struct,
        })
    }
}
