// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::io::{Read, Write};
use std::net::TcpStream;

use codec::{Codec, Reader, Writer};
use spdmlib::config;

pub const SOCKET_HEADER_LEN: usize = 12;
pub const USE_PCIDOE: bool = false; // align with DMTF spdm_emu
pub const USE_ECDSA: bool = true;
pub const USE_ECDH: bool = true;

pub const SOCKET_TRANSPORT_TYPE_MCTP: u32 = 0x01;
pub const SOCKET_TRANSPORT_TYPE_PCI_DOE: u32 = 0x02;

pub const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x0001;
pub const SOCKET_SPDM_COMMAND_STOP: u32 = 0xFFFE;
pub const SOCKET_SPDM_COMMAND_UNKOWN: u32 = 0xFFFF;
pub const SOCKET_SPDM_COMMAND_TEST: u32 = 0xDEAD;

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmSocketHeader {
    pub command: u32,
    pub transport_type: u32,
    pub payload_size: u32,
}

impl Codec for SpdmSocketHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.command.encode(bytes);
        self.transport_type.encode(bytes);
        self.payload_size.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmSocketHeader> {
        let command = u32::read(r)?;
        let transport_type = u32::read(r)?;
        let payload_size = u32::read(r)?;

        Some(SpdmSocketHeader {
            command,
            transport_type,
            payload_size,
        })
    }
}

// u32 type, u32 command, usize, payload
pub fn receive_message<'a>(
    stream: &mut TcpStream,
    buffer: &'a mut [u8],
    _timeout: usize,
) -> Option<(u32, u32, &'a [u8])> {
    let mut buffer_size = 0;
    let mut expected_size = 0;
    loop {
        let s = stream
            .read(&mut buffer[buffer_size..])
            .expect("socket read error!");
        buffer_size += s;
        if (expected_size == 0) && (buffer_size >= SOCKET_HEADER_LEN) {
            let mut reader = Reader::init(&buffer[..core::mem::size_of::<SpdmSocketHeader>()]);
            let socket_header = SpdmSocketHeader::read(&mut reader).unwrap();

            expected_size = socket_header.payload_size.to_be() as usize + SOCKET_HEADER_LEN;
            // println!("expected_size: {:?}", expected_size);
        }
        if (expected_size != 0) && (buffer_size >= expected_size) {
            // println!("buffer_size: {:?}", buffer_size);
            break;
        }
    }
    println!(
        "read: {:02X?}{:02X?}",
        &buffer[..SOCKET_HEADER_LEN],
        &buffer[SOCKET_HEADER_LEN..buffer_size]
    );

    if buffer_size < SOCKET_HEADER_LEN {
        return None;
    }

    let mut reader = Reader::init(&buffer[..SOCKET_HEADER_LEN]);
    let socket_header = SpdmSocketHeader::read(&mut reader).unwrap();

    Some((
        socket_header.transport_type.to_be(),
        socket_header.command.to_be(),
        &mut buffer[SOCKET_HEADER_LEN..buffer_size],
    ))
}

pub fn send_message(
    stream: &mut TcpStream,
    transport_type: u32,
    command: u32,
    payload: &[u8],
) -> usize {
    let mut buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];

    let mut writer = Writer::init(&mut buffer);
    let payload_size = payload.len();
    let header = SpdmSocketHeader {
        command: command.to_be(),
        transport_type: transport_type.to_be(),
        payload_size: (payload_size as u32).to_be(),
    };
    header.encode(&mut writer);
    let used = writer.used();
    assert_eq!(used, SOCKET_HEADER_LEN);

    let buffer_size = SOCKET_HEADER_LEN + payload_size;
    stream
        .write_all(&buffer[..used])
        .expect("socket write error!");
    stream.write_all(payload).expect("socket write error!");
    stream.flush().expect("flush error");
    println!("write: {:02X?}{:02X?}", &buffer[..used], payload);

    buffer_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_spdm_socket_header() {
        let u8_slice = &mut [0u8; 16];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmSocketHeader {
            command: 0x100u32,
            transport_type: 0x200u32,
            payload_size: 0x300u32,
        };
        value.encode(&mut writer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(16, reader.left());
        let spdm_socket_header = SpdmSocketHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_socket_header.command, 0x100u32);
        assert_eq!(spdm_socket_header.transport_type, 0x200u32);
        assert_eq!(spdm_socket_header.payload_size, 0x300u32);
    }
}
