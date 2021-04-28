// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_version(&mut self, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_version = SpdmGetVersionRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_version) = get_version {
            debug!("!!! get_version : {:02x?}\n", get_version);
        } else {
            error!("!!! get_version : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        // clear cache data
        self.common.reset_runtime_info();

        if self
            .common
            .runtime_info
            .message_a
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        info!("send spdm version\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseVersion,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 2,
                versions: [
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[0],
                    },
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[1],
                    },
                ],
            }),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_message(&send_buffer[0..used]);

        self.common
            .runtime_info
            .message_a
            .append_message(&send_buffer[..used]);
    }
}
