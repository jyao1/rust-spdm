// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmContext;
use codec::{Reader, Writer};
use core::fmt::Debug;
extern crate alloc;

pub trait SpdmCodec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    /// Should we assert() here? or return to caller to let the caller handle it?
    fn spdm_encode(&self, _context: &mut SpdmContext, _bytes: &mut Writer);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn spdm_read(_context: &mut SpdmContext, _: &mut Reader) -> Option<Self>;

    // /// Convenience function to get the results of `encode()`.
    // /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    // /// Should we assert() here? or return to caller to let the caller handle it?
    // fn spdm_get_encoding(&self, bytes: &mut [u8]) -> Writer {
    //     let mut ret = Writer::init(bytes);
    //     self.encode(&mut ret);
    //     ret
    // }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn spdm_read_bytes(context: &mut SpdmContext, bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::spdm_read(context, &mut rd)
    }
}
