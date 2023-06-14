// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::ST1;
use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::{SpdmResult, SPDM_STATUS_RECEIVE_FAIL, SPDM_STATUS_SEND_FAIL};
use crate::protocol::*;

pub struct RequesterContext<'a> {
    pub common: common::SpdmContext<'a>,
}

impl<'a> RequesterContext<'a> {
    pub fn new(
        device_io: &'a mut dyn SpdmDeviceIo,
        transport_encap: &'a mut dyn SpdmTransportEncap,
        config_info: common::SpdmConfigInfo,
        provision_info: common::SpdmProvisionInfo,
    ) -> Self {
        RequesterContext {
            common: common::SpdmContext::new(
                device_io,
                transport_encap,
                config_info,
                provision_info,
            ),
        }
    }

    pub fn init_connection(&mut self) -> SpdmResult {
        self.send_receive_spdm_version()?;
        self.send_receive_spdm_capability()?;
        self.send_receive_spdm_algorithm()
    }

    pub fn start_session(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<u32> {
        if !use_psk {
            let session_id =
                self.send_receive_spdm_key_exchange(slot_id, measurement_summary_hash_type)?;
            #[cfg(not(feature = "mut-auth"))]
            let req_slot_id: Option<u8> = None;
            #[cfg(feature = "mut-auth")]
            self.session_based_mutual_authenticate(session_id)?;
            #[cfg(feature = "mut-auth")]
            let req_slot_id = Some(self.common.runtime_info.get_local_used_cert_chain_slot_id());
            self.send_receive_spdm_finish(req_slot_id, session_id)?;
            Ok(session_id)
        } else {
            let session_id =
                self.send_receive_spdm_psk_exchange(measurement_summary_hash_type, None)?;
            self.send_receive_spdm_psk_finish(session_id)?;
            Ok(session_id)
        }
    }

    pub fn end_session(&mut self, session_id: u32) -> SpdmResult {
        self.send_receive_spdm_end_session(session_id)
    }

    pub fn send_message(&mut self, send_buffer: &[u8]) -> SpdmResult {
        if self.common.negotiate_info.rsp_data_transfer_size_sel != 0
            && send_buffer.len() > self.common.negotiate_info.rsp_data_transfer_size_sel as usize
        {
            return Err(SPDM_STATUS_SEND_FAIL);
        }
        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = self.common.encap(send_buffer, &mut transport_buffer)?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn send_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        is_app_message: bool,
    ) -> SpdmResult {
        if !is_app_message
            && self.common.negotiate_info.rsp_data_transfer_size_sel != 0
            && (send_buffer.len() > self.common.negotiate_info.rsp_data_transfer_size_sel as usize)
        {
            return Err(SPDM_STATUS_SEND_FAIL);
        }
        let mut transport_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = self.common.encode_secured_message(
            session_id,
            send_buffer,
            &mut transport_buffer,
            true,
            is_app_message,
        )?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn receive_message(
        &mut self,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        info!("receive_message!\n");

        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.rsp_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        let used = self
            .common
            .device_io
            .receive(&mut transport_buffer, timeout)
            .map_err(|_| SPDM_STATUS_RECEIVE_FAIL)?;

        self.common.decap(&transport_buffer[..used], receive_buffer)
    }

    pub fn receive_secured_message(
        &mut self,
        session_id: u32,
        receive_buffer: &mut [u8],
        crypto_request: bool,
    ) -> SpdmResult<usize> {
        info!("receive_secured_message!\n");

        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.rsp_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        let used = self
            .common
            .device_io
            .receive(&mut transport_buffer, timeout)
            .map_err(|_| SPDM_STATUS_RECEIVE_FAIL)?;

        self.common
            .decode_secured_message(session_id, &transport_buffer[..used], receive_buffer)
    }
}
