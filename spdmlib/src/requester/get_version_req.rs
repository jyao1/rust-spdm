// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::error::{spdm_result_err, SpdmResult};
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    pub fn send_receive_spdm_version(&mut self) -> SpdmResult {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used = self.encode_spdm_version(&mut send_buffer);
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_version_response(0, &send_buffer[..send_used], &receive_buffer[..used])
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

                        versions[0..version_number_entry_count as usize].sort_by(|s1, s2| {
                            if s2.version > s1.version {
                                core::cmp::Ordering::Greater
                            } else {
                                core::cmp::Ordering::Less
                            }
                        });
                        log::info!("versions: {:02X?}", versions);

                        self.common.negotiate_info.spdm_version_sel = if versions
                            [0..version_number_entry_count as usize]
                            .iter()
                            .map(|s| s.version)
                            .any(|v| v == self.common.provision_info.default_version)
                        {
                            self.common.provision_info.default_version
                        } else {
                            let mut found_spdm_version = SpdmVersion::Unknown(0);
                            for s in self.common.config_info.spdm_version {
                                if versions[0..version_number_entry_count as usize]
                                    .iter()
                                    .map(|s| s.version)
                                    .any(|v| v == s)
                                {
                                    found_spdm_version = s;
                                    break;
                                }
                            }
                            if let SpdmVersion::Unknown(0) = found_spdm_version {
                                log::error!("can't find common versions to start communication\n");
                                return spdm_result_err!(ERANGE);
                            } else {
                                found_spdm_version
                            }
                        };

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
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_version_response(
                                session_id,
                                send_buffer,
                                &receive_buffer[..used],
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

        let status = requester.send_receive_spdm_version().is_ok();
        assert!(status);
    }
}
