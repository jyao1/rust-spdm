// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_key_update(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let key_update_req = SpdmKeyUpdateRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(key_update_req) = key_update_req {
            debug!("!!! key_update req : {:02x?}\n", key_update_req);
        } else {
            error!("!!! key_update req : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }
        let key_update_req = key_update_req.unwrap();

        let session = self.common.get_session_via_id(session_id).unwrap();
        match key_update_req.key_update_operation {
            SpdmKeyUpdateOperation::SpdmUpdateSingleKey => {
                let _ = session.create_data_secret_update(true, false);
            }
            SpdmKeyUpdateOperation::SpdmUpdateAllKeys => {
                let _ = session.create_data_secret_update(true, true);
                let _ = session.activate_data_secret_update(true, true, true);
            }
            SpdmKeyUpdateOperation::SpdmVerifyNewKey => {
                let _ = session.activate_data_secret_update(true, false, true);
            }
            _ => {
                error!("!!! key_update req : fail !!!\n");
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
        }

        info!("send spdm key_update rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseKeyUpdateAck,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateResponse(SpdmKeyUpdateResponsePayload {
                key_update_operation: key_update_req.key_update_operation,
                tag: key_update_req.tag,
            }),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[0..used]);
    }
}
