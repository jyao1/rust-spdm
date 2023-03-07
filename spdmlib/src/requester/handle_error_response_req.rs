// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use codec::{Codec, Reader};

use crate::common::session::SpdmSessionState;
use crate::common::{SpdmDeviceIo, SpdmTransportEncap};
use crate::error::{spdm_result_err, SpdmResult};
use crate::message::*;
use crate::requester::RequesterContext;
use crate::time::sleep;

impl RequesterContext {
    fn spdm_handle_response_not_ready(
        &mut self,
        _session_id: Option<u32>,
        response: &[u8],
        original_request_code: SpdmRequestResponseCode,
        expected_response_code: SpdmRequestResponseCode,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<ReceivedMessage> {
        if response.len()
            != core::mem::size_of::<SpdmMessageHeader>()
                + core::mem::size_of::<SpdmMessageGeneralPayload>()
                + core::mem::size_of::<SpdmErrorResponseNotReadyExtData>()
        {
            spdm_result_err!(EDEV)
        } else {
            let extoff = core::mem::size_of::<SpdmMessageHeader>()
                + core::mem::size_of::<SpdmMessageGeneralPayload>();
            let mut extend_error_data_reader = Reader::init(&response[extoff..]);
            let extend_error_data = if let Some(eed) =
                SpdmErrorResponseNotReadyExtData::read(&mut extend_error_data_reader)
            {
                eed
            } else {
                return spdm_result_err!(EINVAL);
            };

            if extend_error_data.request_code != original_request_code.get_u8() {
                return spdm_result_err!(EDEV);
            }

            sleep(2 << extend_error_data.rdt_exponent);

            self.spdm_requester_respond_if_ready(
                expected_response_code,
                extend_error_data,
                transport_encap,
                device_io,
            )
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
            spdm_result_err!(EDEV)
        } else if error_code == SpdmErrorCode::SpdmErrorBusy.get_u8() {
            spdm_result_err!(EBUSY)
        } else if error_code == SpdmErrorCode::SpdmErrorRequestResynch.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return spdm_result_err!(EFAULT);
                };
                session.set_session_state(SpdmSessionState::SpdmSessionNotStarted);
            }
            spdm_result_err!(EDEV)
        } else {
            spdm_result_err!(EDEV)
        }
    }

    pub fn spdm_handle_error_response_main(
        &mut self,
        session_id: Option<u32>,
        response: &[u8],
        original_request_code: SpdmRequestResponseCode,
        expected_response_code: SpdmRequestResponseCode,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<ReceivedMessage> {
        let mut spdm_message_header_reader = Reader::init(response);
        let spdm_message_header =
            if let Some(smh) = SpdmMessageHeader::read(&mut spdm_message_header_reader) {
                smh
            } else {
                return spdm_result_err!(EINVAL);
            };
        let header_size = spdm_message_header_reader.used();

        if spdm_message_header.version != self.common.negotiate_info.spdm_version_sel {
            return spdm_result_err!(EINVAL);
        }

        if spdm_message_header.request_response_code != SpdmRequestResponseCode::SpdmResponseError {
            return spdm_result_err!(EINVAL);
        }

        let mut spdm_message_payload_reader = Reader::init(&response[header_size..]);
        let spdm_message_general_payload =
            if let Some(smgp) = SpdmMessageGeneralPayload::read(&mut spdm_message_payload_reader) {
                smgp
            } else {
                return spdm_result_err!(EINVAL);
            };

        if spdm_message_general_payload.param1 == SpdmErrorCode::SpdmErrorDecryptError.get_u8() {
            if let Some(sid) = session_id {
                let session = if let Some(s) = self.common.get_session_via_id(sid) {
                    s
                } else {
                    return spdm_result_err!(EFAULT);
                };
                let _ = session.teardown(sid);
            }
            spdm_result_err!(ESEC)
        } else if spdm_message_general_payload.param1
            == SpdmErrorCode::SpdmErrorResponseNotReady.get_u8()
        {
            self.spdm_handle_response_not_ready(
                session_id,
                response,
                original_request_code,
                expected_response_code,
                transport_encap,
                device_io,
            )
        } else {
            self.spdm_handle_simple_error_response(session_id, spdm_message_general_payload.param1)
        }
    }
}
