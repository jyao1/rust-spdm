// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::ST1;
use crate::common::{self, SpdmDeviceIo, SpdmTransportEncap};
use crate::config;
use crate::error::{spdm_err, spdm_result_err, SpdmResult};
use crate::protocol::*;

pub struct RequesterContext {
    pub common: common::SpdmContext,
}

impl RequesterContext {
    pub fn new(
        config_info: common::SpdmConfigInfo,
        provision_info: common::SpdmProvisionInfo,
    ) -> Self {
        RequesterContext {
            common: common::SpdmContext::new(config_info, provision_info),
        }
    }

    pub fn init_connection(
        &mut self,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        self.send_receive_spdm_version(transport_encap, device_io)?;
        self.send_receive_spdm_capability(transport_encap, device_io)?;
        self.send_receive_spdm_algorithm(transport_encap, device_io)
    }

    pub fn start_session(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<u32> {
        if !use_psk {
            let result = self.send_receive_spdm_key_exchange(
                slot_id,
                measurement_summary_hash_type,
                transport_encap,
                device_io,
            );
            if let Ok(session_id) = result {
                let result =
                    self.send_receive_spdm_finish(slot_id, session_id, transport_encap, device_io);
                if result.is_ok() {
                    Ok(session_id)
                } else {
                    spdm_result_err!(EIO)
                }
            } else {
                spdm_result_err!(EIO)
            }
        } else {
            let result = self.send_receive_spdm_psk_exchange(
                measurement_summary_hash_type,
                transport_encap,
                device_io,
            );
            if let Ok(session_id) = result {
                let result =
                    self.send_receive_spdm_psk_finish(session_id, transport_encap, device_io);
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

    pub fn end_session(
        &mut self,
        session_id: u32,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        self.send_receive_spdm_end_session(session_id, transport_encap, device_io)
    }

    pub fn send_message(
        &mut self,
        send_buffer: &[u8],
        // transport_buffer: &mut [u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let used = self
            .common
            .encap(send_buffer, &mut transport_buffer, transport_encap)?;
        device_io.send(&transport_buffer[..used])
    }

    pub fn send_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        is_app_message: bool,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let used = self.common.encode_secured_message(
            session_id,
            send_buffer,
            &mut transport_buffer,
            true,
            is_app_message,
            transport_encap,
        )?;
        device_io.send(&transport_buffer[..used])
    }

    pub fn receive_message(
        &mut self,
        receive_buffer: &mut [u8],
        crypto_request: bool,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<usize> {
        info!("receive_message!\n");

        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.rsp_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];
        let used = device_io
            .receive(&mut transport_buffer, timeout)
            .map_err(|_| spdm_err!(EIO))?;

        self.common
            .decap(&transport_buffer[..used], receive_buffer, transport_encap)
    }

    pub fn receive_secured_message(
        &mut self,
        session_id: u32,
        receive_buffer: &mut [u8],
        crypto_request: bool,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult<usize> {
        info!("receive_secured_message!\n");

        let timeout: usize = if crypto_request {
            2 << self.common.negotiate_info.rsp_ct_exponent_sel
        } else {
            ST1
        };

        let mut transport_buffer = [0u8; config::DATA_TRANSFER_SIZE];

        let used = device_io
            .receive(&mut transport_buffer, timeout)
            .map_err(|_| spdm_err!(EIO))?;

        self.common.decode_secured_message(
            session_id,
            &transport_buffer[..used],
            receive_buffer,
            transport_encap,
        )
    }
}

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::common::session::SpdmSession;
    use crate::common::*;
    use crate::message::*;
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

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

        let status = requester
            .init_connection(pcidoe_transport_encap2, &mut device_io_requester)
            .is_ok();
        assert!(status);

        let status = requester
            .send_receive_spdm_digest(None, pcidoe_transport_encap2, &mut device_io_requester)
            .is_ok();
        assert!(status);

        let status = requester
            .send_receive_spdm_certificate(
                None,
                0,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            pcidoe_transport_encap2,
            &mut device_io_requester,
        );
        assert!(result.is_ok());

        let result = requester.start_session(
            false,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            pcidoe_transport_encap2,
            &mut device_io_requester,
        );
        assert!(result.is_ok());

        let result = requester.start_session(
            true,
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll,
            pcidoe_transport_encap2,
            &mut device_io_requester,
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

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(rsp_config_info, rsp_provision_info);

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
        let mut device_io_requester = FakeSpdmDeviceIo::new(
            &shared_buffer,
            &mut responder,
            pcidoe_transport_encap,
            &mut device_io_responder,
        );

        let mut requester = RequesterContext::new(req_config_info, req_provision_info);

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
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
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
        request.spdm_encode(&mut requester.common, &mut writer);
        let used = writer.used();

        let status = requester
            .send_secured_message(
                session_id,
                &send_buffer[..used],
                false,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];

        let status = requester
            .receive_secured_message(
                session_id,
                &mut receive_buffer,
                false,
                pcidoe_transport_encap2,
                &mut device_io_requester,
            )
            .is_ok();
        assert!(status);
    }
}
