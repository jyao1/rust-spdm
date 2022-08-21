// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use spdmlib::error::*;

use crate::{
    context::{MessagePayloadRequestLockInterface, MessagePayloadResponseLockInterface},
    state_machine::TDIState,
};

use super::*;

// security check
// Interface ID specified in the request is not hosted by the device.
// DONE - TDI is not in CONFIG_UNLOCKED.
// For TDIs where IDE is required:
// The default Stream does not match the Stream ID indicated
// The default stream does not have IDE keys programmed for all sub-streams
// All IDE keys of the default stream were not configured over the SPDM session on which the LOCK_INTERFACE_REQUEST was received
// Multiple IDE configuration registers in the device have been configured as the default stream
// The default Stream is associated with a TC other than TC0
// Phantom Functions Enabled
// Device PF BARs configured with overlapping addresses
// Expansion ROM base address, if supported, configured t// overlap with a BAR
// Resizable BAR control registers programmed with an unsupported BAR size
// VF BARs are configured with address overlapping another VF BAR, a PF BAR or Expansion ROM BAR
// Unsupported system page size is configured in the system page size register of SR-IOV capability
// Cache Line Size configured for LN requester capability (deprecated in PCIe Revision 6.0), if supported and enabled, does not match the system cache line size specified in the LOCK_INTERFACE_REQUEST or is configured t// a value not supported by the device.
// ST mode selected in TPH Requester Extended Capability, if supported and enabled, does not correspond t// a mode supported by the function hosting the TDI.
// Other device determined errors in the device or TDI configurations

// The LOCK_INTERFACE_REQUEST binds and configures the following parameters into the TDI
// MMIO_REPORTING_OFFSET
// NO_FW_UPDATE
// System cache line size
// MSI-X table and PBA
// BIND_P2P
// ALL_REQUEST_REDIRECT
impl<'a> TdispResponder<'a> {
    pub fn handle_lock_interface_request(
        &mut self,
        vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
    ) -> SpdmResult<VendorDefinedRspPayloadStruct> {
        let mut reader =
            Reader::init(&vendor_defined_req_payload_struct.vendor_defined_req_payload);
        let tmh = TdispMessageHeader::tdisp_read(&mut self.tdisp_requester_context, &mut reader);
        let mpr = MessagePayloadRequestLockInterface::tdisp_read(
            &mut self.tdisp_requester_context,
            &mut reader,
        );
        if tmh.is_none() || mpr.is_none() {
            self.handle_tdisp_error(
                vendor_defined_req_payload_struct,
                MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_REQUEST,
            )
        } else if self.tdisp_requester_context.state_machine.current_state
            != TDIState::ConfigUnlocked
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
                message_type: TdispRequestResponseCode::ResponseLockInterfaceResponse,
                interface_id: self.tdisp_requester_context.tdi,
            };

            let mprr = MessagePayloadResponseLockInterface::default();
            // mprr.start_interface_nonce

            tmhr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);
            mprr.tdisp_encode(&mut self.tdisp_requester_context, &mut writer);

            match self.tdisp_requester_context.configuration.init_config() {
                Ok(_) => match self.tdisp_requester_context.configuration.lock_config() {
                    Ok(_) => {
                        self.tdisp_requester_context
                            .state_machine
                            .to_state_config_locked();
                        Ok(vendor_defined_rsp_payload_struct)
                    }
                    Err(_) => self.handle_tdisp_error(
                        vendor_defined_req_payload_struct,
                        MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_DEVICE_CONFIGURATION,
                    ),
                },
                Err(_) => self.handle_tdisp_error(
                    vendor_defined_req_payload_struct,
                    MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_DEVICE_CONFIGURATION,
                ),
            }
        }
    }
}
