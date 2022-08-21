// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::error::*;

use crate::{
    context::{MessagePayloadRequestBindP2pStream, MessagePayloadResponseBindP2pStream},
    state_machine::TDIState,
};

use super::*;

// security check
// Interface ID in the request is not hosted by the device
// TDI does not support binding peer-to-peer streams
// DONE - TDI is not in RUN
// Stream ID specified does not have IDE keys programmed for all sub streams
// All IDE keys of the stream identified by the Stream ID were not configured over the SPDM session on which the LOCK_INTERFACE_REQUEST was received
// Multiple IDE configuration registers have been programmed with the same stream ID
// IDE configuration register for this stream is configured as the default stream
// Address and/or RID association registers of this streams IDE configuration registers overlap with other IDE configuration registers
impl<'a> TdispResponder<'a> {
    pub fn handle_bind_p2p_stream_request(
        &mut self,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader =
            Reader::init(&vendor_defined_req_payload_struct.vendor_defined_req_payload);
        let tmh = TdispMessageHeader::tdisp_read(&mut self.tdisp_requester_context, &mut reader);
        let mpr = MessagePayloadRequestBindP2pStream::tdisp_read(
            &mut self.tdisp_requester_context,
            &mut reader,
        );
        if tmh.is_none() || mpr.is_none() {
            self.handle_tdisp_error(
                vendor_defined_req_payload_struct,
                MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_REQUEST,
            )
        } else if self.tdisp_requester_context.state_machine.current_state != TDIState::Run {
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
                message_type: TdispRequestResponseCode::ResponseBindP2pStreamResponse,
                interface_id: self.tdisp_requester_context.tdi,
            };

            let mprr = MessagePayloadResponseBindP2pStream::default();

            tmhr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);
            mprr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

            Ok(vendor_defined_rsp_payload_struct)
        }
    }
}
