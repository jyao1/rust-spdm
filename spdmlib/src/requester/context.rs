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

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::common::*;
    use crate::message::*;
    use crate::responder;
    use crate::testlib::*;
    use codec::Writer;

    #[test]
    fn test_case0_start_session() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        crate::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        crate::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let status = requester.init_connection().is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_digest(None).is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_certificate(None, 0).is_ok();
        assert!(status);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert!(result.is_ok());

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert!(result.is_ok());

        let result = requester.start_session(
            true,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_case0_get_next_half_session() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        crate::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
        crate::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        let status = requester.init_connection().is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_digest(None).is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_certificate(None, 0).is_ok();
        assert!(status);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert_eq!(result.unwrap(), 0xfffdfffd);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert_eq!(result.unwrap(), 0xfffcfffc);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert_eq!(result.unwrap(), 0xfffbfffb);

        let result = requester.start_session(
            true,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert_eq!(result.unwrap(), 0xfffafffa);

        let result = requester.end_session(0xfffbfffb);
        assert!(result.is_ok());

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert_eq!(result.unwrap(), 0xfffbfffb);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_case0_receive_secured_message() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crate::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel =
            crate::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        responder.common.session = gen_array_clone(SpdmSession::new(), 4);
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            crate::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            crate::protocol::SpdmDheAlgo::SECP_384_R1,
            crate::protocol::SpdmAeadAlgo::AES_256_GCM,
            crate::protocol::SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel =
            crate::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        requester.common.session = gen_array_clone(SpdmSession::new(), 4);
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            crate::protocol::SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            crate::protocol::SpdmDheAlgo::SECP_384_R1,
            crate::protocol::SpdmAeadAlgo::AES_256_GCM,
            crate::protocol::SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::common::session::SpdmSessionState::SpdmSessionEstablished);
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmRequestResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
        };
        assert!(request
            .spdm_encode(&mut requester.common, &mut writer)
            .is_ok());
        let used = writer.used();

        let status = requester
            .send_secured_message(session_id, &send_buffer[..used], false)
            .is_ok();
        assert!(status);

        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];

        let status = requester
            .receive_secured_message(session_id, &mut receive_buffer, false)
            .is_ok();
        assert!(status);
    }
}
