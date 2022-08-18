// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use crate::context;
pub use ::codec::*;
use core::fmt::Debug;

use self::context::TdispContext;

pub trait TdispCodec: Debug + Sized {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer);

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self>;

    fn tdisp_read_bytes(context: &mut TdispContext, bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::tdisp_read(context, &mut rd)
    }
}
