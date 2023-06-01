// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

// TBD: need test different algorithm combinations
pub const USE_ECDSA: bool = true;

pub mod util;

pub mod device_io;
pub mod transport;

pub mod crypto_callback;
pub mod secret_callback;
