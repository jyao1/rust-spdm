// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use spdmlib::common::SpdmTransportEncap;
use spdmlib::error::SpdmResult;
use spdmlib::{spdm_err, spdm_result_err};

enum_builder! {
    @U8
    EnumName: MctpMessageType;
    EnumVal{
        MctpMessageTypeMctpControl => 0x00,
        MctpMessageTypePldm => 0x01,
        MctpMessageTypeNcsi => 0x02,
        MctpMessageTypeEthernet => 0x03,
        MctpMessageTypeNvme => 0x04,
        MctpMessageTypeSpdm => 0x05,
        MctpMessageTypeSecuredMctp => 0x06,
        MctpMessageTypeVendorDefinedPci => 0x7E,
        MctpMessageTypeVendorDefinedIana => 0x7F
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MctpMessageHeader {
    pub r#type: MctpMessageType,
}

impl Codec for MctpMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.r#type.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<MctpMessageHeader> {
        let r#type = MctpMessageType::read(r)?;
        Some(MctpMessageHeader { r#type })
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MctpTransportEncap {}

impl SpdmTransportEncap for MctpTransportEncap {
    fn encap(
        &mut self,
        spdm_buffer: &[u8],
        transport_buffer: &mut [u8],
        secured_message: bool,
    ) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut writer = Writer::init(&mut transport_buffer[..]);
        let mctp_header = MctpMessageHeader {
            r#type: if secured_message {
                MctpMessageType::MctpMessageTypeSecuredMctp
            } else {
                MctpMessageType::MctpMessageTypeSpdm
            },
        };
        mctp_header.encode(&mut writer);
        let header_size = writer.used();
        if transport_buffer.len() < header_size + payload_len {
            return spdm_result_err!(EINVAL);
        }
        transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + payload_len)
    }

    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)> {
        let mut reader = Reader::init(&transport_buffer[..]);
        let secured_message;
        match MctpMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                MctpMessageType::MctpMessageTypeSpdm => {
                    secured_message = false;
                }
                MctpMessageType::MctpMessageTypeSecuredMctp => {
                    secured_message = true;
                }
                _ => return spdm_result_err!(EINVAL),
            },
            None => return spdm_result_err!(EIO),
        }
        let header_size = reader.used();
        let payload_size = transport_buffer.len() - header_size;
        if spdm_buffer.len() < payload_size {
            return spdm_result_err!(EINVAL);
        }
        let payload = &transport_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok((payload_size, secured_message))
    }

    fn encap_app(&mut self, spdm_buffer: &[u8], app_buffer: &mut [u8]) -> SpdmResult<usize> {
        let payload_len = spdm_buffer.len();
        let mut writer = Writer::init(&mut app_buffer[..]);
        let mctp_header = MctpMessageHeader {
            r#type: MctpMessageType::MctpMessageTypeSpdm,
        };
        mctp_header.encode(&mut writer);
        let header_size = writer.used();
        if app_buffer.len() < header_size + payload_len {
            return spdm_result_err!(EINVAL);
        }
        app_buffer[header_size..(header_size + payload_len)].copy_from_slice(spdm_buffer);
        Ok(header_size + payload_len)
    }

    fn decap_app(&mut self, app_buffer: &[u8], spdm_buffer: &mut [u8]) -> SpdmResult<usize> {
        let mut reader = Reader::init(&app_buffer[..]);
        match MctpMessageHeader::read(&mut reader) {
            Some(mctp_header) => match mctp_header.r#type {
                MctpMessageType::MctpMessageTypeSpdm => {}
                _ => return spdm_result_err!(EINVAL),
            },
            None => return spdm_result_err!(EIO),
        }
        let header_size = reader.used();
        let payload_size = app_buffer.len() - header_size;
        if spdm_buffer.len() < payload_size {
            return spdm_result_err!(EINVAL);
        }
        let payload = &app_buffer[header_size..];
        spdm_buffer[..payload_size].copy_from_slice(payload);
        Ok(payload_size)
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        2
    }
    fn get_max_random_count(&mut self) -> u16 {
        32
    }
}
