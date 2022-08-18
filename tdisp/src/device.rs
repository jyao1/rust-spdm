// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::TdispResult;
use core::fmt::Debug;

pub trait TdispConfiguration: Debug {
    fn init_config(&mut self) -> TdispResult;

    fn lock_config(&mut self) -> TdispResult;

    fn unlock_config(&mut self) -> TdispResult;

    fn erase_confidential_config(&mut self) -> TdispResult;

    fn track_config_changes(&mut self) -> TdispResult;
}
