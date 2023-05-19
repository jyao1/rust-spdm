// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ffi::{c_int, c_void};

use super::ffi::{mbedtls_md_get_size, mbedtls_md_info_from_type};

pub const MBEDTLS_MD_SHA256: i32 = 6;
pub const MBEDTLS_MD_SHA384: i32 = 7;
pub const MBEDTLS_MD_SHA512: i32 = 8;
#[repr(C)]
#[derive(Default)]
pub struct MbedtlsMdContextT {
    md_info: usize,
    md_ctx: usize,
    hmac_ctx: usize,
}

impl MbedtlsMdContextT {
    pub fn init() -> Self {
        let mut c = Self::default();
        unsafe {
            mbedtls_md_init(&mut c as *mut MbedtlsMdContextT);
        }
        c
    }
    pub fn setup(&mut self, md_info_type: i32) -> bool {
        let md_info = unsafe { mbedtls_md_info_from_type(md_info_type) };
        if md_info.is_null() {
            return false;
        }
        let mut ret;
        unsafe {
            ret = mbedtls_md_setup(self as *mut MbedtlsMdContextT, md_info, 0);
            if ret == 0 {
                ret = mbedtls_md_starts(self as *mut MbedtlsMdContextT)
            }
        };
        ret == 0
    }
    pub fn update(&mut self, data: &[u8]) -> bool {
        let ret =
            unsafe { mbedtls_md_update(self as *mut MbedtlsMdContextT, data.as_ptr(), data.len()) };
        ret == 0
    }
    pub fn finish(&mut self, data: &mut [u8]) -> Option<usize> {
        let data_len = data.len();
        let md_size = unsafe { mbedtls_md_get_size(self.md_info as *const c_void) } as usize;
        if md_size > data_len {
            return None;
        }
        let ret = unsafe { mbedtls_md_finish(self as *mut MbedtlsMdContextT, data.as_mut_ptr()) };
        if ret != 0 {
            None
        } else {
            Some(md_size)
        }
    }
    pub fn dup(&self) -> Option<Self> {
        let mut new_ctx = Self::init();
        let mut ret;
        unsafe {
            ret = mbedtls_md_setup(
                &mut new_ctx as *mut MbedtlsMdContextT,
                self.md_info as *const c_void,
                0,
            );
            if ret != 0 {
                return None;
            }
            ret = mbedtls_md_clone(
                &mut new_ctx as *mut MbedtlsMdContextT,
                self as *const MbedtlsMdContextT,
            );
            if ret == 0 {
                Some(new_ctx)
            } else {
                // new_ctx will be automatic free when drop
                None
            }
        }
    }
}

impl Drop for MbedtlsMdContextT {
    fn drop(&mut self) {
        unsafe {
            mbedtls_md_free(self as *mut MbedtlsMdContextT);
        }
    }
}

extern "C" {
    pub fn mbedtls_md_init(ctx: *mut MbedtlsMdContextT);
    pub fn mbedtls_md_setup(
        ctx: *mut MbedtlsMdContextT,
        md_info: *const c_void,
        hmac: c_int,
    ) -> c_int;
    pub fn mbedtls_md_starts(ctx: *mut MbedtlsMdContextT) -> c_int;
    pub fn mbedtls_md_update(
        ctx: *mut MbedtlsMdContextT,
        input: *const u8,
        input_size: usize,
    ) -> c_int;
    pub fn mbedtls_md_finish(ctx: *mut MbedtlsMdContextT, output: *mut u8) -> c_int;
    pub fn mbedtls_md_clone(dst: *mut MbedtlsMdContextT, src: *const MbedtlsMdContextT) -> c_int;
    pub fn mbedtls_md_free(ctx: *mut MbedtlsMdContextT);
}
