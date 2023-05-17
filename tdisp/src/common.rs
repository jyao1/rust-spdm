// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::message::{VendorIDStruct, MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN};

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
    vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
};
