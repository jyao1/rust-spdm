// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::*;
use crate::common::{SpdmCodec, SpdmConfigInfo, SpdmContext, SpdmProvisionInfo};
use testlib::{create_spdm_context, DeviceIO, TransportEncap};

#[test]
fn test_key_update_struct() {
    create_spdm_context!(context);
    let context = &mut context;

    // 1. Validate KeyUpdate request length is 4.
    let u8_slice = &mut [0u8; 4];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 2. Validate KEY_UPDATE_ACK response length is 4.
    let u8_slice = &mut [0u8; 4];
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
    assert_eq!(reader.left(), 0);

    // 3. Validate KEY_UPDATE operations equal to reserved value. Expactation, pass.
    let u8_slice = &mut [0u8; 4];
    u8_slice[2] = 4;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateRequestPayload::spdm_read(context, reader);
    assert!(ret.is_some());

    // 4. Validate KEY_UPDATE_ACK KEY_UPDATE operations equal to reserved value. Expectation, pass
    let u8_slice = &mut [0u8; 4];
    u8_slice[2] = 4;
    let reader = &mut Reader::init(&u8_slice[2..]);
    let ret = SpdmKeyUpdateResponsePayload::spdm_read(context, reader);
    assert!(ret.is_some());
}
