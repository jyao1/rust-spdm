// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

///Temporary hardcode response
pub const TEST_VENDOR_RESPONSE_DATA: &[u8; 19] = &[
    0x10u8, 0x7eu8, 0x00u8, 0x00u8, 0x03u8, 0x00u8, 0x02u8, 0x01u8, 0x00u8, 0x08u8, 0x00u8, 0x00u8,
    0x01u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x07u8,
];
impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_vendor_defined_request(&mut self, session_id: u32, _bytes: &[u8]) {
        let _ = self.send_secured_message(session_id, TEST_VENDOR_RESPONSE_DATA, false);
    }
}
