// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_digest(&mut self) -> SpdmResult {
        info!("send spdm digest\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestGetDigests,
            },
            payload: SpdmMessagePayload::SpdmGetDigestsRequest(SpdmGetDigestsRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        // append message_b
        if self
            .common
            .runtime_info
            .message_b
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseDigests => {
                    let digests =
                        SpdmDigestsResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(digests) = digests {
                        debug!("!!! digests : {:02x?}\n", digests);

                        if self
                            .common
                            .runtime_info
                            .message_b
                            .append_message(&receive_buffer[..used])
                            .is_none()
                        {
                            return spdm_result_err!(ENOMEM);
                        }

                        Ok(())
                    } else {
                        error!("!!! digests : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}
