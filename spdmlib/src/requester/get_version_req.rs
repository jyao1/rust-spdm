// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_ERROR_PEER, SPDM_STATUS_INVALID_MSG_FIELD,
    SPDM_STATUS_NEGOTIATION_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_version(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_GET_VERSION_REQUEST_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_version(&mut send_buffer);
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_VERSION_RESPONSE_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_version_response(&send_buffer[..send_used], &receive_buffer[..used])
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
        send_buffer: &[u8],
        receive_buffer: &[u8],
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
                                return Err(SPDM_STATUS_NEGOTIATION_FAIL);
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
                            .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
                        message_a
                            .append_message(&receive_buffer[..used])
                            .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))
                    } else {
                        error!("!!! version : fail !!!\n");
                        Err(SPDM_STATUS_INVALID_MSG_FIELD)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let rm = self.spdm_handle_error_response_main(
                        None,
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestGetVersion,
                        SpdmRequestResponseCode::SpdmResponseVersion,
                    )?;
                    let receive_buffer = rm.receive_buffer;
                    let used = rm.used;
                    self.handle_spdm_version_response(send_buffer, &receive_buffer[..used])
                }
                _ => Err(SPDM_STATUS_ERROR_PEER),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
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
        let rsp_provision_info = create_info();
        let req_provision_info = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_provision_info,
        );

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_provision_info,
        );

        let status = requester.send_receive_spdm_version().is_ok();
        assert!(status);
    }
}
