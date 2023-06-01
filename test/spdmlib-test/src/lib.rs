// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

pub mod common;

#[cfg(test)]
mod test_client_server;
#[cfg(test)]
mod test_library;

#[cfg(test)]
mod requester_tests;

#[cfg(test)]
mod responder_tests;
