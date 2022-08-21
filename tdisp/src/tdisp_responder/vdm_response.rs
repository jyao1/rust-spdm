// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::error::*;

use crate::context::{MessagePayloadRequestVDM, MessagePayloadResponseVDM};

use super::*;

impl<'a> TdispResponder<'a> {
    pub fn handle_vdm_request(
        &mut self,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader =
            Reader::init(&vendor_defined_req_payload_struct.vendor_defined_req_payload);
        let tmh = TdispMessageHeader::tdisp_read(&mut self.tdisp_requester_context, &mut reader);
        let mpr =
            MessagePayloadRequestVDM::tdisp_read(&mut self.tdisp_requester_context, &mut reader);
        if tmh.is_none() || mpr.is_none() {
            self.handle_tdisp_error(
                vendor_defined_req_payload_struct,
                MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_REQUEST,
            )
        } else {
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
                message_type: TdispRequestResponseCode::ResponseVdmResponse,
                interface_id: self.tdisp_requester_context.tdi,
            };

            let mprr = MessagePayloadResponseVDM::default();
            // mprr.registry_id
            // mprr.vendor_id
            // mprr.vendor_id_len
            // vendor_data

            tmhr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);
            mprr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

            Ok(vendor_defined_rsp_payload_struct)
        }
    }
}
