// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    context::{InterfaceId, TdispContext},
    device::TdispConfiguration,
};

pub struct TdispRequester<'a> {
    pub tdisp_requester_context: TdispContext<'a>,
}

impl<'a> TdispRequester<'a> {
    pub fn new(
        interface_id: InterfaceId,
        configuration: &'a mut dyn TdispConfiguration,
        spdm_session_id: u32,
    ) -> Self {
        TdispRequester {
            tdisp_requester_context: TdispContext::new(
                interface_id,
                configuration,
                spdm_session_id,
            ),
        }
    }
}

pub mod bind_p2p_stream_request_req;
pub mod get_device_interface_report_req;
pub mod get_device_interface_state_req;
pub mod get_tdisp_capabilities_req;
pub mod get_tdisp_version_req;
pub mod lock_interface_request_req;
pub mod set_mmio_attribute_request_req;
pub mod start_interface_request_req;
pub mod stop_interface_request_req;
pub mod unbind_p2p_stream_request_req;
pub mod vdm_request;
