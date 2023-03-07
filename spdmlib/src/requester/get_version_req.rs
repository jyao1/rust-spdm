// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{spdm_result_err, SpdmResult};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl RequesterContext {
    pub fn send_receive_spdm_version(
        &mut self,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_version(&mut send_buffer);
        self.send_message(&send_buffer[..send_used], transport_encap, device_io)?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false, transport_encap, device_io)?;
        self.handle_spdm_version_response(
            0,
            &send_buffer[..send_used],
            &receive_buffer[..used],
            transport_encap,
            device_io,
        )
    }

    pub fn encode_spdm_version(&mut self, buf: &mut [u8]) -> usize {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetVersion,
            },
            payload: SpdmMessagePayload::SpdmGetVersionRequest(SpdmGetVersionRequestPayload {}),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        writer.used()
    }

    pub fn handle_spdm_version_response(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        receive_buffer: &[u8],
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) -> SpdmResult {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseVersion => {
                    let version =
                        SpdmVersionResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(version) = version {
                        debug!("!!! version : {:02x?}\n", version);

                        let SpdmVersionResponsePayload {
                            version_number_entry_count,
                            mut versions,
                        } = version;

                        versions
                            .sort_unstable_by(|a, b| b.version.get_u8().cmp(&a.version.get_u8()));

                        self.common.negotiate_info.spdm_version_sel = SpdmVersion::Unknown(0);

                        for spdm_version_struct in
                            versions.iter().take(version_number_entry_count as usize)
                        {
                            if spdm_version_struct.version
                                == self.common.provision_info.default_version
                                || self
                                    .common
                                    .config_info
                                    .spdm_version
                                    .contains(&spdm_version_struct.version)
                            {
                                self.common.negotiate_info.spdm_version_sel =
                                    spdm_version_struct.version;
                                break;
                            }
                        }

                        match self.common.negotiate_info.spdm_version_sel {
                            SpdmVersion::Unknown(_) => {
                                debug!(
                                    "Version negotiation failed! with given version list: {:?}",
                                    versions
                                );
                                return spdm_result_err!(EFAULT);
                            }
                            _ => {
                                debug!(
                                    "Version negotiated: {:?}",
                                    self.common.negotiate_info.spdm_version_sel
                                );
                            }
                        }

                        // clear cache data
                        self.common.reset_runtime_info();

                        let message_a = &mut self.common.runtime_info.message_a;
                        message_a
                            .append_message(send_buffer)
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        message_a
                            .append_message(&receive_buffer[..used])
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))
                    } else {
                        error!("!!! version : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let erm = self.spdm_handle_error_response_main(
                        Some(session_id),
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestGetVersion,
                        SpdmRequestResponseCode::SpdmResponseVersion,
                        transport_encap,
                        device_io,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_version_response(
                                session_id,
                                send_buffer,
                                &receive_buffer[..used],
                                transport_encap,
                                device_io,
                            )
                        }
                        _ => spdm_result_err!(EINVAL),
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }
}

#[cfg(all(test,))]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_version() {
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
            .send_receive_spdm_version(pcidoe_transport_encap2, &mut device_io_requester)
            .is_ok();
        assert!(status);
    }
}
