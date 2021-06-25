// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::config;
use core::cell::RefCell;

pub struct SharedBuffer {
    pub size: RefCell<usize>,
    buffer: RefCell<[u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE]>,
}

impl SharedBuffer {
    pub fn new() -> Self {
        SharedBuffer {
            size: RefCell::new(0usize),
            buffer: RefCell::new([0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE])
        }
    }
    pub fn set_buffer(&self, b: &[u8]) {
        let mut dest = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let len = b.len();
        *self.size.borrow_mut() = len;
        &dest[0..len].copy_from_slice(b);

        *self.buffer.borrow_mut() = dest;
    }

    pub fn get_buffer(&self, b: &mut [u8]) -> usize {
        let len = *self.size.borrow();
        let res = *self.buffer.borrow();
        b[0..len].copy_from_slice(&res[0..len]);
        len
    }
}
