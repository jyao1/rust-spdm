// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmAsymVerify;
use spdmlib::error::SpdmResult;
use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

pub static FAKE_ASYM_VERIFY: SpdmAsymVerify = SpdmAsymVerify {
    verify_cb: fake_asym_verify,
};

fn fake_asym_verify(
    _base_hash_algo: SpdmBaseHashAlgo,
    _base_asym_algo: SpdmBaseAsymAlgo,
    _public_cert_der: &[u8],
    _data: &[u8],
    _signature: &SpdmSignatureStruct,
) -> SpdmResult {
    Ok(())
}
