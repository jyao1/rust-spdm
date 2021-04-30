// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_key_update_op(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
        tag: u8,
    ) -> SpdmResult {
        info!("send spdm key_update\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestKeyUpdate,
            },
            payload: SpdmMessagePayload::SpdmKeyUpdateRequest(SpdmKeyUpdateRequestPayload {
                key_update_operation,
                tag,
            }),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_secured_message(session_id, &send_buffer[..used])?;

        // update key
        let session = self.common.get_session_via_id(session_id).unwrap();
        let update_requester = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateSingleKey
            || key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        let update_responder = key_update_operation == SpdmKeyUpdateOperation::SpdmUpdateAllKeys;
        session.create_data_secret_update(update_requester, update_responder)?;

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_secured_message(session_id, &mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseKeyUpdateAck => {
                    let key_update_rsp =
                        SpdmKeyUpdateResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let session = self.common.get_session_via_id(session_id).unwrap();
                    if let Some(key_update_rsp) = key_update_rsp {
                        debug!("!!! key_update rsp : {:02x?}\n", key_update_rsp);
                        session.activate_data_secret_update(
                            update_requester,
                            update_responder,
                            true,
                        )?;
                        Ok(())
                    } else {
                        error!("!!! key_update : fail !!!\n");
                        session.activate_data_secret_update(
                            update_requester,
                            update_responder,
                            false,
                        )?;
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }

    pub fn send_receive_spdm_key_update(
        &mut self,
        session_id: u32,
        key_update_operation: SpdmKeyUpdateOperation,
    ) -> SpdmResult {
        if key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateAllKeys
            && key_update_operation != SpdmKeyUpdateOperation::SpdmUpdateSingleKey
        {
            return spdm_result_err!(EINVAL);
        }
        self.send_receive_spdm_key_update_op(session_id, key_update_operation, 1)?;
        self.send_receive_spdm_key_update_op(
            session_id,
            SpdmKeyUpdateOperation::SpdmVerifyNewKey,
            2,
        )
    }
}
