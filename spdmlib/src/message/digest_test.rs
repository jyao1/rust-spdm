// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::{
    common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo},
    testlib::SpdmBaseHashAlgo,
};
use byteorder::{ByteOrder, LittleEndian};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};

#[test]
fn test_digest_struct() {
    create_spdm_context!(context);

    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_256;

    // 1. [Negative] Param2 equal 0b11111111 total length less than 4 +(H * 8). Expectation: None
    let u8_slice = &mut [0u8; 4 + 32 * 7];

    u8_slice[3] = 0xff;
    let mut reader = Reader::init(&u8_slice[2..]);
    let ret = SpdmDigestsResponsePayload::spdm_read(&mut context, &mut reader);
    assert!(ret.is_none());
}

#[test]
fn test_digest_struct_case2() {
    create_spdm_context!(context);

    context.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    // 2. [Negative] Param2 equal 0b11001111 total read length equal 4 +(H * 6). Expectation: true
    let u8_slice = &mut [0u8; 4 + 48 * 9];

    u8_slice[3] = 0xcf;
    let mut reader = Reader::init(&u8_slice[2..]);
    let ret = SpdmDigestsResponsePayload::spdm_read(&mut context, &mut reader);
    assert_eq!(
        reader.used() + 2,
        4 + context.negotiate_info.base_hash_sel.get_size() as usize * 6
    );
    assert!(ret.is_some());
}
