// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../../fuzz-target/requester/key_exchange_req/src/main.rs");

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    fuzz_send_receive_spdm_key_exchange(data);
});
