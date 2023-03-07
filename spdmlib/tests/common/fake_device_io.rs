// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]
#![allow(unused)]

use super::shared_buffer::SharedBuffer;
use spdmlib::common::SpdmDeviceIo;
use spdmlib::common::SpdmTransportEncap;
use spdmlib::common::ST1;
use spdmlib::error::SpdmResult;
use spdmlib::responder;

pub struct FakeSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer,
}

impl<'a> FakeSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer) -> Self {
        FakeSpdmDeviceIoReceve { data }
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
            data,
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

        let _res =
            self.responder
                .process_message(ST1, &[0], self.rsp_transport_encap, self.rsp_device_io);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

#[test]
fn test_fake_device_io() {
    let buffer = SharedBuffer::new();
    let mut server = FakeSpdmDeviceIoReceve::new(&buffer);
    let mut client = FakeSpdmDeviceIoReceve::new(&buffer);
    const SEND_DATA: &[u8] = &[1, 2];
    client.send(SEND_DATA).unwrap();
    let mut rev = [0u8, 64];
    server.receive(&mut rev, ST1).unwrap();
    assert_eq!(&rev[..=1], SEND_DATA)
}
