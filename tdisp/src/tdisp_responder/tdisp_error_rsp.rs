// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::error::*;

use crate::{context::MessagePayloadResponseTdispError, tdisp_codec::TdispCodec};

use super::*;

impl<'a> TdispResponder<'a> {
    pub fn handle_tdisp_error(
        &mut self,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
        message_payload_response_tdisp_error: MessagePayloadResponseTdispError,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader =
            Reader::init(&vendor_defined_req_payload_struct.vendor_defined_req_payload);
        let _tmh = TdispMessageHeader::tdisp_read(&mut self.tdisp_requester_context, &mut reader);

        let mut vendor_defined_rsp_payload_struct: VendorDefinedRspPayloadStruct =
            VendorDefinedRspPayloadStruct {
                rsp_length: 0,
                vendor_defined_rsp_payload: [0u8;
                    spdmlib::config::MAX_SPDM_VENDOR_DEFINED_PAYLOAD_SIZE],
            };
        let mut writer =
            Writer::init(&mut vendor_defined_rsp_payload_struct.vendor_defined_rsp_payload);

        let tmhr = TdispMessageHeader {
            tdisp_version: self.tdisp_requester_context.version_sel,
            message_type: TdispRequestResponseCode::ResponseTdispError,
            interface_id: self.tdisp_requester_context.tdi,
        };

        tmhr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

        message_payload_response_tdisp_error
            .tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

        match self
            .tdisp_requester_context
            .configuration
            .erase_confidential_config()
        {
            Ok(_) => {
                self.tdisp_requester_context.state_machine.to_state_error();
                Ok(vendor_defined_rsp_payload_struct)
            }
            Err(_) => panic!("Confidential data leaking"),
        }
    }
}
