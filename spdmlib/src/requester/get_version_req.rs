// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_NEGOTIATION_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_version(&mut self) -> SpdmResult {
        self.common
            .reset_buffer_via_request_code(SpdmRequestResponseCode::SpdmRequestGetVersion, None);

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.encode_spdm_version(&mut send_buffer)?;
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_version_response(0, &send_buffer[..send_used], &receive_buffer[..used])
    }

    pub fn encode_spdm_version(&mut self, buf: &mut [u8]) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
            },
            payload: SpdmMessagePayload::SpdmGetVersionRequest(SpdmGetVersionRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    pub fn handle_spdm_version_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseVersion => {
                    let version =
                        SpdmVersionResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(version) = version {
                        debug!("!!! version : {:02x?}\n", version);

                        let SpdmVersionResponsePayload {
                            version_number_entry_count,
                            mut versions,
                        } = version;

                        versions
                            .sort_unstable_by(|a, b| b.version.get_u8().cmp(&a.version.get_u8()));

                        self.common.negotiate_info.spdm_version_sel = SpdmVersion::Unknown(0);

                        for spdm_version_struct in
                            versions.iter().take(version_number_entry_count as usize)
                        {
                            if self
                                .common
                                .config_info
                                .spdm_version
                                .contains(&spdm_version_struct.version)
                            {
                                self.common.negotiate_info.spdm_version_sel =
                                    spdm_version_struct.version;
                                break;
                            }
                        }

                        match self.common.negotiate_info.spdm_version_sel {
                            SpdmVersion::Unknown(_) => {
                                debug!(
                                    "Version negotiation failed! with given version list: {:?}",
                                    versions
                                );
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
                            }
                            _ => {
                                debug!(
                                    "Version negotiated: {:?}",
                                    self.common.negotiate_info.spdm_version_sel
                                );
                            }
                        }

                        // clear cache data
                        self.common.reset_runtime_info();

                        self.common.append_message_a(send_buffer)?;
                        self.common.append_message_a(&receive_buffer[..used])?;

                        Ok(())
                    } else {
                        error!("!!! version : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => self.spdm_handle_error_response_main(
                    Some(session_id),
                    receive_buffer,
                    SpdmRequestResponseCode::SpdmRequestGetVersion,
                    SpdmRequestResponseCode::SpdmResponseVersion,
                ),
                _ => Err(SPDM_STATUS_ERROR_PEER),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
