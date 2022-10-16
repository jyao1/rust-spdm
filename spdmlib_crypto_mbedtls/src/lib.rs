// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![cfg_attr(not(test), no_std)]
#![feature(core_ffi_c)]

extern crate alloc;

mod ffi;

pub mod aead_impl;
pub mod asym_verify_impl;
pub mod cert_operation_impl;
pub mod dhe_impl;
pub mod hash_impl;
pub mod hkdf_impl;
pub mod hmac_impl;
pub mod rand_impl;

#[cfg(target_os = "uefi")]
mod platform_support;

#[no_mangle]
pub unsafe extern "C" fn mbedtls_param_failed() {
    panic!("mbedtls_param_failed fail called")
}
