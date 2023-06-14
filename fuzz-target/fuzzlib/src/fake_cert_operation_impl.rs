// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::crypto::SpdmCertOperation;
use spdmlib::error::SpdmResult;

pub static FAKE_CERT_OPERATION: SpdmCertOperation = SpdmCertOperation {
    get_cert_from_cert_chain_cb: fake_get_cert_from_cert_chain,
    verify_cert_chain_cb: fake_verify_cert_chain,
};

fn fake_get_cert_from_cert_chain(cert_chain: &[u8], _index: isize) -> SpdmResult<(usize, usize)> {
    return Ok((0, cert_chain.len()));
}

fn fake_verify_cert_chain(_cert_chain: &[u8]) -> SpdmResult {
    Ok(())
}
