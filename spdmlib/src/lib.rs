// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![feature(stmt_expr_attributes)]
#![feature(try_trait_v2)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate bitflags;

extern crate codec;

pub mod protocol;
#[macro_use]
pub mod error;
pub mod common;
pub mod crypto;
pub mod message;
pub mod requester;
pub mod responder;
pub mod secret;
pub mod time;

pub mod config;
