// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::error::SpdmResult;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_version(&mut self, bytes: &[u8]) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_version_response(bytes, &mut writer);
        self.send_message(writer.used_slice())
    }

    pub fn write_spdm_version_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != SpdmVersion::SpdmVersion10 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestGetVersion, None);

        let get_version = SpdmGetVersionRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_version) = get_version {
            debug!("!!! get_version : {:02x?}\n", get_version);
        } else {
            error!("!!! get_version : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        // clear cache data
        self.common.reset_context();

        if self
            .common
            .append_message_a(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        info!("send spdm version\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVersion,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 3,
                versions: [
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[0],
                    },
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[1],
                    },
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[2],
                    },
                ],
            }),
        };

        let res = response.spdm_encode(&mut self.common, writer);
        if res.is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }
        if self.common.append_message_a(writer.used_slice()).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
        }
    }
}
