// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::{config, message::VendorIDStruct};

#[derive(Debug)]
pub enum InternalError<T = ()> {
    Succ,
    Unimpl,
    Violation,
    Unrecoverable,

    ErrStr(&'static str),

    CustomErr(T),
}

pub type TdispResult<T = ()> = Result<T, InternalError>;

pub const PCI_VENDOR_ID_STRUCT: VendorIDStruct = VendorIDStruct {
    len: 0,
    vendor_id: [0u8; config::MAX_VENDOR_ID_LEN_SIZE],
};
