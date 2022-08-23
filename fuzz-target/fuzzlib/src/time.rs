// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::time::SpdmTime;
pub static SPDM_TIME_IMPL: SpdmTime = SpdmTime {
    sleep_cb: |time: usize| {
        use std::{thread, time::Duration};
        thread::sleep(Duration::from_millis(time as u64));
    },
};
