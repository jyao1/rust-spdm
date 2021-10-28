// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

mod context;

mod algorithm_rsp;
mod capability_rsp;
mod certificate_rsp;
mod challenge_rsp;
mod digest_rsp;
mod end_session_rsp;
mod finish_rsp;
mod heartbeat_rsp;
mod key_exchange_rsp;
mod key_update_rsp;
mod measurement_rsp;
mod psk_exchange_rsp;
mod psk_finish_rsp;
mod version_rsp;

mod error_rsp;
mod vendor_rsp;

pub use context::ResponderContext;

use crate::config;
use crate::msgs::*;
use codec::{Codec, Reader, Writer};
