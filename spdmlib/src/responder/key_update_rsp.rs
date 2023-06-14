// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::message::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_key_update(&mut self, session_id: u32, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_key_update_response(session_id, bytes, &mut writer);
        self.send_secured_message(session_id, writer.used_slice(), false)
    }

    pub fn write_spdm_key_update_response(
        &mut self,
        session_id: u32,
        bytes: &[u8],
        writer: &mut Writer,
    ) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestKeyUpdate,
            Some(session_id),
        );

        let key_update_req = SpdmKeyUpdateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(key_update_req) = &key_update_req {
            debug!("!!! key_update req : {:02x?}\n", key_update_req);
        } else {
            error!("!!! key_update req : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let key_update_req = key_update_req.unwrap();

        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        let session = self.common.get_session_via_id(session_id).unwrap();
        match key_update_req.key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey => {
                let _ = session.create_data_secret_update(spdm_version_sel, true, false);
            }
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys => {
                let _ = session.create_data_secret_update(spdm_version_sel, true, true);
                let _ = session.activate_data_secret_update(spdm_version_sel, true, true, true);
            }
            SpdmKeyUpdateOperation::SpdmVerifyNewKey => {
                let _ = session.activate_data_secret_update(spdm_version_sel, true, false, true);
            }
            _ => {
                error!("!!! key_update req : fail !!!\n");
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return;
            }
        }

        info!("send spdm key_update rsp\n");

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: key_update_req.key_update_operation,
                tag: key_update_req.tag,
            }),
        };
        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
        }
    }
}
