// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::{Codec, Reader};

use crate::common::session::SpdmSessionState;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUSY_PEER, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_INVALID_MSG_SIZE, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_NOT_READY_PEER,
    SPDM_STATUS_SESSION_MSG_ERROR,
};
use crate::message::*;
use crate::requester::RequesterContext;
use crate::time::sleep;

impl<'a> RequesterContext<'a> {
    fn spdm_handle_response_not_ready(
        &mut self,
        _session_id: Option<u32>,
        response: &[u8],
        original_request_code: SpdmRequestResponseCode,
        expected_response_code: SpdmRequestResponseCode,
    ) -> SpdmResult<ReceivedMessage> {
        if response.len()
            != core::mem::size_of::<SpdmMessageHeader>()
                + core::mem::size_of::<SpdmMessageGeneralPayload>()
                + core::mem::size_of::<SpdmErrorResponseNotReadyExtData>()
        {
            Err(SPDM_STATUS_INVALID_MSG_SIZE)
        } else {
            let extoff = core::mem::size_of::<SpdmMessageHeader>()
                + core::mem::size_of::<SpdmMessageGeneralPayload>();
            let mut extend_error_data_reader = Reader::init(&response[extoff..]);
            let extend_error_data = if let Some(eed) =
                SpdmErrorResponseNotReadyExtData::read(&mut extend_error_data_reader)
            {
                eed
            } else {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            };

            if extend_error_data.request_code != original_request_code.get_u8() {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            }

            sleep(2 << extend_error_data.rdt_exponent);

            self.spdm_requester_respond_if_ready(expected_response_code, extend_error_data)
        }
    }

    fn spdm_handle_simple_error_response(
        &mut self,
        session_id: Option<u32>,
        error_code: u8,
    ) -> SpdmResult<ReceivedMessage> {
        /* NOT_READY is treated as error here.
         * Use spdm_handle_error_response_main to handle NOT_READY message in long latency command.*/
        if error_code == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8() {
            Err(SPDM_STATUS_NOT_READY_PEER)
        } else if error_code == SpdmErrorCode::SpdmErrorBusy.get_u8() {
            Err(SPDM_STATUS_BUSY_PEER)
        } else if error_code == SpdmErrorCode::SpdmErrorRequestResynch.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                session.set_session_state(SpdmSessionState::SpdmSessionNotStarted);
            }
            Err(SPDM_STATUS_INVALID_PARAMETER)
        } else {
            Err(SPDM_STATUS_ERROR_PEER)
        }
    }

    pub fn spdm_handle_error_response_main(
        &mut self,
        session_id: Option<u32>,
        response: &[u8],
        original_request_code: SpdmRequestResponseCode,
        expected_response_code: SpdmRequestResponseCode,
    ) -> SpdmResult<ReceivedMessage> {
        let mut spdm_message_header_reader = Reader::init(response);
        let spdm_message_header =
            if let Some(smh) = SpdmMessageHeader::read(&mut spdm_message_header_reader) {
                smh
            } else {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            };
        let header_size = spdm_message_header_reader.used();

        if spdm_message_header.version != self.common.negotiate_info.spdm_version_sel {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        if spdm_message_header.request_response_code != SpdmRequestResponseCode::SpdmResponseError {
            return Err(SPDM_STATUS_INVALID_MSG_FIELD);
        }

        let mut spdm_message_payload_reader = Reader::init(&response[header_size..]);
        let spdm_message_general_payload =
            if let Some(smgp) = SpdmMessageGeneralPayload::read(&mut spdm_message_payload_reader) {
                smgp
            } else {
                return Err(SPDM_STATUS_INVALID_MSG_FIELD);
            };

        if spdm_message_general_payload.param1 == SpdmErrorCode::SpdmErrorDecryptError.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                let _ = session.teardown(sid);
            }
            Err(SPDM_STATUS_SESSION_MSG_ERROR)
        } else if spdm_message_general_payload.param1
            == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8()
        {
            self.spdm_handle_response_not_ready(
                session_id,
                response,
                original_request_code,
                expected_response_code,
            )
        } else {
            self.spdm_handle_simple_error_response(session_id, spdm_message_general_payload.param1)
        }
    }
}
