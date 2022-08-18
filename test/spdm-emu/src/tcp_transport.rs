// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// use codec::{Reader, Codec, Writer};
use std::io::{Read, Write};
use std::net::TcpStream;

use spdmlib::common::SpdmDeviceIo;
use spdmlib::error::SpdmResult;
use spdmlib::{spdm_err, spdm_result_err};

pub struct TcpTransport<'a> {
    pub data: &'a mut TcpStream,
}

impl SpdmDeviceIo for TcpTransport<'_> {
    fn receive(&mut self, buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let res = self.data.read(buffer).ok();
        if let Some(size) = res {
            Ok(size)
        } else {
            Err(0)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        let res = self.data.write(buffer);
        if res.is_ok() {
            Ok(())
        } else {
            spdm_result_err!(EIO)
        }
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}
