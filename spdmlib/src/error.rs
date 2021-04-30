// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt::{Debug, Formatter, Result};

/// POSIX errno
#[repr(u32)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SpdmErrorNum {
    EUNDEF = 0,
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    E2BIG = 7,
    ENOMEM = 12,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    EINVAL = 22,
    ERANGE = 34,
    ENOSYS = 38,
}

pub struct SpdmError {
    num: SpdmErrorNum,
    loc_file: &'static str,
    loc_line: u32,
    loc_col: u32,
    msg: &'static str,
}

pub type SpdmResult<T = ()> = core::result::Result<T, SpdmError>;

impl SpdmErrorNum {
    pub fn as_str(&self) -> &'static str {
        use SpdmErrorNum::*;
        match *self {
            EUNDEF => "Not defined",
            EPERM => "Operation not permitted",
            ENOENT => "No such file or directory",
            EIO => "I/O error",
            E2BIG => "Argument list too long",
            ENOMEM => "Out of memory",
            EFAULT => "Bad address",
            EBUSY => "Device or resource busy",
            EEXIST => "File exists",
            ENODEV => "No such device",
            EINVAL => "Invalid argument",
            ERANGE => "Math result not representable",
            ENOSYS => "Function not implemented",
        }
    }
}

impl SpdmError {
    pub fn new(
        num: SpdmErrorNum,
        loc_file: &'static str,
        loc_line: u32,
        loc_col: u32,
        msg: &'static str,
    ) -> Self {
        Self {
            num,
            loc_file,
            loc_line,
            loc_col,
            msg,
        }
    }

    pub fn code(&self) -> i32 {
        -(self.num as u32 as i32)
    }
}

impl Debug for SpdmError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "[{}:{}:{}] {}: {}",
            self.loc_file,
            self.loc_line,
            self.loc_col,
            self.num.as_str(),
            self.msg
        )?;
        Ok(())
    }
}

#[macro_export]
macro_rules! spdm_err {
    ($num: ident) => {{
        use $crate::error::{SpdmError, SpdmErrorNum::*};
        SpdmError::new($num, file!(), line!(), column!(), "")
    }};
    ($num: ident, $msg: expr) => {{
        use $crate::error::{SpdmError, SpdmErrorNum::*};
        SpdmError::new($num, file!(), line!(), column!(), $msg)
    }};
}

#[macro_export]
macro_rules! spdm_result_err {
    ($num: ident) => {
        Err(spdm_err!($num))
    };
    ($num: ident, $msg: expr) => {
        Err(spdm_err!($num, $msg))
    };
}
