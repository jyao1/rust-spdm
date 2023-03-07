// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn handle_spdm_respond_if_ready(
        &mut self,
        bytes: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_respond_if_ready_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice(), transport_encap, device_io);
    }

    pub fn write_spdm_respond_if_ready_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let respond_if_ready =
            SpdmRespondIfReadyRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(respond_if_ready) = respond_if_ready {
            debug!("!!! respond_if_ready : {:02x?}\n", respond_if_ready);
        } else {
            error!("!!! respond_if_ready : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        //TODO: implement respond if ready
        self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
    }
}
