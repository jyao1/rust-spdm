// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::spdm_emu::*;
use std::net::TcpStream;

use spdmlib::common::SpdmDeviceIo;
use spdmlib::config;
use spdmlib::error::SpdmResult;

pub struct SocketIoTransport<'a> {
    pub data: &'a mut TcpStream,
    transport_type: u32,
}
impl<'a> SocketIoTransport<'a> {
    pub fn new(stream: &'a mut TcpStream) -> Self {
        SocketIoTransport {
            data: stream,
            transport_type: if USE_PCIDOE {
                SOCKET_TRANSPORT_TYPE_PCI_DOE
            } else {
                SOCKET_TRANSPORT_TYPE_MCTP
            },
        }
    }
}

impl SpdmDeviceIo for SocketIoTransport<'_> {
    fn receive(&mut self, read_buffer: &mut [u8], timeout: usize) -> Result<usize, usize> {
        let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        if let Some((_, command, payload)) = receive_message(self.data, &mut buffer[..], timeout) {
            // TBD: do we need this?
            // self.transport_type = transport_type;
            let used = payload.len();
            let total = used + SOCKET_HEADER_LEN;
            if command == SOCKET_SPDM_COMMAND_NORMAL {
                read_buffer[..used].copy_from_slice(payload);
                Ok(used)
            } else {
                // this commmand need caller to deal.
                read_buffer[..total].copy_from_slice(&buffer[..total]);
                Err(total)
            }
        } else {
            // socket header can't be received.
            Err(0)
        }
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        send_message(
            self.data,
            self.transport_type,
            SOCKET_SPDM_COMMAND_NORMAL,
            buffer,
        );
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}
