// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::{SpdmCodec, SpdmContext, SpdmDeviceIo, SpdmTransportEncap};
use crate::config::MAX_SPDM_MSG_SIZE;
use crate::message::SpdmMessage;
use codec::{Reader, Writer};

#[allow(unused, unused_mut)]
macro_rules! create_spdm_context {
    ($context_name: ident) => {
        let transport_encap = &mut TransportEncap {};
        let device_io = &mut DeviceIO {};
        let config_info = SpdmConfigInfo::default();
        let provision_info = SpdmProvisionInfo::default();
        #[allow(unused, unused_mut)]
        let mut $context_name =
            SpdmContext::new(device_io, transport_encap, config_info, provision_info);
    };
}

#[allow(unused)]
pub fn new_spdm_message(value: SpdmMessage, mut context: SpdmContext) -> SpdmMessage {
    let u8_slice = &mut [0u8; MAX_SPDM_MSG_SIZE];
    let mut writer = Writer::init(u8_slice);
    value.spdm_encode(&mut context, &mut writer);
    let mut reader = Reader::init(u8_slice);
    let spdm_message: SpdmMessage = SpdmMessage::spdm_read(&mut context, &mut reader).unwrap();
    spdm_message
}

#[allow(unused)]
pub(crate) use create_spdm_context;

pub struct DeviceIO;
pub struct TransportEncap;
impl SpdmDeviceIo for DeviceIO {
    fn send(&mut self, _buffer: &[u8]) -> crate::error::SpdmResult {
        unimplemented!()
    }

    fn receive(&mut self, _buffer: &mut [u8], _timeoutt: usize) -> Result<usize, usize> {
        unimplemented!()
    }

    fn flush_all(&mut self) -> crate::error::SpdmResult {
        unimplemented!()
    }
}

impl SpdmTransportEncap for TransportEncap {
    fn encap(
        &mut self,
        _spdm_buffer: &[u8],
        _transport_buffer: &mut [u8],
        _secured_messagesage: bool,
    ) -> crate::error::SpdmResult<usize> {
        unimplemented!()
    }

    fn decap(
        &mut self,
        _transport_buffer: &[u8],
        _spdm_buffer: &mut [u8],
    ) -> crate::error::SpdmResult<(usize, bool)> {
        unimplemented!()
    }

    fn encap_app(
        &mut self,
        _spdm_buffer: &[u8],
        _app_buffer: &mut [u8],
        _is_app_messagesage: bool,
    ) -> crate::error::SpdmResult<usize> {
        unimplemented!()
    }

    fn decap_app(
        &mut self,
        _app_buffer: &[u8],
        _spdm_buffer: &mut [u8],
    ) -> crate::error::SpdmResult<(usize, bool)> {
        unimplemented!()
    }

    fn get_sequence_number_count(&mut self) -> u8 {
        unimplemented!()
    }

    fn get_max_random_count(&mut self) -> u16 {
        unimplemented!()
    }
}
