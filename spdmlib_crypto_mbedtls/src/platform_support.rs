// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::collections::BTreeMap;
use core::alloc::Layout;
use core::ffi::{c_char, c_int, c_void};
use lazy_static::lazy_static;
use spin::Mutex;

lazy_static! {
    static ref CALLOC_TABLE: Mutex<BTreeMap<usize, (usize, usize)>> = Mutex::new(BTreeMap::new());
}

#[no_mangle]
pub unsafe extern "C" fn strstr() {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn strchr() {
    unimplemented!();
}

#[no_mangle]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let addr = alloc::alloc::alloc_zeroed(Layout::from_size_align_unchecked(nmemb * size, 1))
        as *mut c_void;
    CALLOC_TABLE.lock().insert(addr as usize, (nmemb, size));
    addr
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if let Some((nmemb, size)) = CALLOC_TABLE.lock().remove(&(ptr as usize)) {
        alloc::alloc::dealloc(
            ptr as *mut u8,
            Layout::from_size_align_unchecked(size * nmemb, 1),
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    for i in 0.. {
        let s1_i = s1.offset(i);
        let s2_i = s2.offset(i);

        let val = *s1_i as c_int - *s2_i as c_int;
        if val != 0 || *s1_i == 0 {
            return val;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn rand() -> u32 {
    unimplemented!()
}
