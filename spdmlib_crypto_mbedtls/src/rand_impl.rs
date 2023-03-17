// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::arch::x86_64::_rdrand64_step;
use spdmlib::crypto::SpdmCryptoRandom;
use spdmlib::error::{SpdmResult, SPDM_STATUS_CRYPTO_ERROR};

pub static DEFAULT: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    if 0 == f_rng(data.as_mut_ptr(), data.len()) {
        Ok(data.len())
    } else {
        Err(SPDM_STATUS_CRYPTO_ERROR)
    }
}

fn f_rng(output: *mut u8, len: usize) -> i32 {
    let mut remain = len;
    while remain > 8 {
        remain -= 8;
        let mut count = 0;
        unsafe {
            while _rdrand64_step(&mut *(output.add(remain) as *mut u64)) != 1 || count > 5 {
                count += 1;
            }
            if count > 5 {
                return 1;
            }
        }
    }
    let mut buf = [0u8; 8];
    unsafe {
        let mut count = 0;
        while _rdrand64_step(&mut *(buf.as_mut_ptr() as *mut u64)) != 1 || count > 5 {
            count += 1;
        }
        if count > 5 {
            return 1;
        }
        core::slice::from_raw_parts_mut(output, remain).copy_from_slice(&buf[0..remain]);
    }
    0
}
