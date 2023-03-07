// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use spdmlib::spdm_result_err;

use spdmlib::spdm_err;

// use crate::spdmlib::error::SpdmResult;
use spdmlib::error::SpdmResult;
// use crate::spdmlib::responder::context::*;

use super::*;

pub struct FakeSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
}

impl<'a> FakeSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer) -> Self {
        FakeSpdmDeviceIoReceve { data: data }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(buffer);
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FuzzTmpSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
    fuzzdata: [[u8; 528]; 4],
    current: usize,
}

impl<'a> FuzzTmpSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer, fuzzdata: [[u8; 528]; 4], current: usize) -> Self {
        FuzzTmpSpdmDeviceIoReceve {
            data: data,
            fuzzdata,
            current,
        }
    }
}

impl SpdmDeviceIo for FuzzTmpSpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(&(self.fuzzdata[self.current]));
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        self.current += 1;
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FuzzSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
    fuzzdata: &'a [u8],
}

impl<'a> FuzzSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer, fuzzdata: &'a [u8]) -> Self {
        FuzzSpdmDeviceIoReceve {
            data: data,
            fuzzdata,
        }
    }
}

impl SpdmDeviceIo for FuzzSpdmDeviceIoReceve<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(self.fuzzdata);
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

pub struct FakeSpdmDeviceIo<'a> {
    pub data: &'a SharedBuffer,
    pub responder: &'a mut responder::ResponderContext,
    pub rsp_transport_encap: &'a mut dyn SpdmTransportEncap,
    pub rsp_device_io: &'a mut dyn SpdmDeviceIo,
}

impl<'a> FakeSpdmDeviceIo<'a> {
    pub fn new(
        data: &'a SharedBuffer,
        responder: &'a mut responder::ResponderContext,
        rsp_transport_encap: &'a mut dyn SpdmTransportEncap,
        rsp_device_io: &'a mut dyn SpdmDeviceIo,
    ) -> Self {
        FakeSpdmDeviceIo {
            data: data,
            responder,
            rsp_transport_encap,
            rsp_device_io,
        }
    }
}

impl SpdmDeviceIo for FakeSpdmDeviceIo<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], _timeout: usize) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("requester receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        self.data.set_buffer(buffer);
        log::info!("requester send    RAW - {:02x?}\n", buffer);
        let timeout = 60;
        if self
            .responder
            .process_message(timeout, &[0], self.rsp_transport_encap, self.rsp_device_io)
            .is_err()
        {
            return spdm_result_err!(ENOMEM);
        }
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

#[test]
fn test_single_run() {
    let buffer = SharedBuffer::new();
    let mut server = FakeSpdmDeviceIoReceve::new(&buffer);
    let mut client = FakeSpdmDeviceIoReceve::new(&buffer);
    client.send(&[1, 2]).unwrap();
    let mut rev = [0u8, 64];
    client.receive(&mut rev, 0).unwrap();
    println!("rev: {:?}", rev);
}
