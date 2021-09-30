// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::SpdmResult;
use crate::msgs::*;

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
        let result = self.send_receive_spdm_version();
        if result.is_err() {
            return result;
        }
        let result = self.send_receive_spdm_capability();
        if result.is_err() {
            return result;
        }
        self.send_receive_spdm_algorithm()
    }

    pub fn start_session(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> SpdmResult<u32> {
        if !use_psk {
            let result =
                self.send_receive_spdm_key_exchange(slot_id, measurement_summary_hash_type);
            if let Ok(session_id) = result {
                let result = self.send_receive_spdm_finish(session_id);
                if result.is_ok() {
                    Ok(session_id)
                } else {
                    spdm_result_err!(EIO)
                }
            } else {
                spdm_result_err!(EIO)
            }
        } else {
            let result = self.send_receive_spdm_psk_exchange(measurement_summary_hash_type);
            if let Ok(session_id) = result {
                let result = self.send_receive_spdm_psk_finish(session_id);
                if result.is_ok() {
                    Ok(session_id)
                } else {
                    spdm_result_err!(EIO)
                }
            } else {
                spdm_result_err!(EIO)
            }
        }
    }

    pub fn end_session(&mut self, session_id: u32) -> SpdmResult {
        let _result = self.send_receive_spdm_end_session(session_id);
        Ok(())
    }

    pub fn send_message(&mut self, send_buffer: &[u8]) -> SpdmResult {
        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.common.encap(send_buffer, &mut transport_buffer)?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn send_secured_message(&mut self, session_id: u32, send_buffer: &[u8]) -> SpdmResult {
        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.common.encode_secured_message(
            session_id,
            send_buffer,
            &mut transport_buffer,
            true,
        )?;
        self.common.device_io.send(&transport_buffer[..used])
    }

    pub fn receive_message(&mut self, receive_buffer: &mut [u8]) -> SpdmResult<usize> {
        info!("receive_message!\n");

        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self
            .common
            .device_io
            .receive(&mut transport_buffer)
            .map_err(|_| spdm_err!(EIO))?;

        self.common.decap(&transport_buffer[..used], receive_buffer)
    }

    pub fn receive_secured_message(
        &mut self,
        session_id: u32,
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        info!("receive_secured_message!\n");

        let mut transport_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];

        let used = self
            .common
            .device_io
            .receive(&mut transport_buffer)
            .map_err(|_| spdm_err!(EIO))?;

        self.common
            .decode_secured_message(session_id, &transport_buffer[..used], receive_buffer)
    }
}

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::session::SpdmSession;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::Writer;

    #[test]
    fn test_case0_start_session() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

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

        let status = requester.send_receive_spdm_digest().is_ok();
        assert!(status);

        let status = requester.send_receive_spdm_certificate(0).is_ok();
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
    fn test_case0_receive_secured_message() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL);

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        responder.common.session = [SpdmSession::new(); 4];
        responder.common.session[0].setup(session_id).unwrap();
        responder.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        responder.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        let rsp_session_id = 0xffu16;
        let session_id = (0xffu32 << 16) + rsp_session_id as u32;
        requester.common.session = [SpdmSession::new(); 4];
        requester.common.session[0].setup(session_id).unwrap();
        requester.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        requester.common.session[0]
            .set_session_state(crate::session::SpdmSessionState::SpdmSessionEstablished);
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestEndSession,
            },
            payload: SpdmMessagePayload::SpdmEndSessionRequest(SpdmEndSessionRequestPayload {
                end_session_request_attributes: SpdmEndSessionRequestAttributes::empty(),
            }),
        };
        request.spdm_encode(&mut requester.common, &mut writer);
        let used = writer.used();

        let status = requester
            .send_secured_message(session_id, &send_buffer[..used])
            .is_ok();
        assert!(status);

        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];

        let status = requester
            .receive_secured_message(session_id, &mut receive_buffer)
            .is_ok();
        assert!(status);
    }
}
