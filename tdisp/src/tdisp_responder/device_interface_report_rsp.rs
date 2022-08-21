// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::error::*;

use crate::{
    context::{
        MessagePayloadRequestGetDeviceInterfaceReport, MessagePayloadResponseDeviceInterfaceReport,
    },
    state_machine::TDIState,
};

use super::*;

// security check
// Interface ID in the request is not hosted by the device
// DONE - TDI is not in CONFIG_LOCKED or RUN
// Invalid offset specified

impl<'a> TdispResponder<'a> {
    pub fn handle_device_interface_report(
        &mut self,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader =
            Reader::init(&vendor_defined_req_payload_struct.vendor_defined_req_payload);
        let tmh = TdispMessageHeader::tdisp_read(&mut self.tdisp_requester_context, &mut reader);
        let mpr = MessagePayloadRequestGetDeviceInterfaceReport::tdisp_read(
            &mut self.tdisp_requester_context,
            &mut reader,
        );
        if tmh.is_none() || mpr.is_none() {
            self.handle_tdisp_error(
                vendor_defined_req_payload_struct,
                MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_REQUEST,
            )
        } else if self.tdisp_requester_context.state_machine.current_state != TDIState::Run
            || self.tdisp_requester_context.state_machine.current_state != TDIState::ConfigLocked
        {
            self.handle_tdisp_error(
                vendor_defined_req_payload_struct,
                MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_INTERFACE_STATE,
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
                message_type: TdispRequestResponseCode::ResponseDeviceInterfaceReport,
                interface_id: self.tdisp_requester_context.tdi,
            };

            let mprr = MessagePayloadResponseDeviceInterfaceReport::default();
            // mprr.portion_length
            // mprr.reminder_length
            // mprr.report_bytes

            tmhr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);
            mprr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

            Ok(vendor_defined_rsp_payload_struct)
        }
    }
}
