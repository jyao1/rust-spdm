// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::spdmlib::crypto::SpdmHkdf;
use spdmlib::protocol::{SpdmBaseHashAlgo, SpdmDigestStruct};

pub static FAKE_HKDF: SpdmHkdf = SpdmHkdf {
    hkdf_extract_cb: fake_hkdf_extract,
    hkdf_expand_cb: fake_hkdf_expand,
};

fn fake_hkdf_extract(
    _hash_algo: SpdmBaseHashAlgo,
    _salt: &[u8],
    _ikm: &[u8],
) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::default())
}

fn fake_hkdf_expand(
    _hash_algo: SpdmBaseHashAlgo,
    _pk: &[u8],
    _info: &[u8],
    _out_size: u16,
) -> Option<SpdmDigestStruct> {
    Some(SpdmDigestStruct::default())
}
