// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[derive(Clone)]
pub struct SpdmTime {
    pub sleep_cb: fn(us: usize),
}
