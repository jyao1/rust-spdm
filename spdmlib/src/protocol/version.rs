// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::enum_builder;
use codec::{Codec, Reader, Writer};

enum_builder! {
    @U8
    EnumName: SpdmVersion;
    EnumVal{
        SpdmVersion10 => 0x10,
        SpdmVersion11 => 0x11,
        SpdmVersion12 => 0x12
    }
}
