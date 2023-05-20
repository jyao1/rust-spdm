// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_version(&mut self, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_version_response(bytes, &mut writer);
        let _ = self.send_message(writer.used_slice());
    }

    pub fn write_spdm_version_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != SpdmVersion::SpdmVersion10 {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let get_version = SpdmGetVersionRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_version) = get_version {
            debug!("!!! get_version : {:02x?}\n", get_version);
        } else {
            error!("!!! get_version : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        // clear cache data
        self.common.reset_context();

        if self
            .common
            .append_message_a(&bytes[..reader.used()])
            .is_err()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
            return;
        }

        info!("send spdm version\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion10,
                request_response_code: SpdmRequestResponseCode::SpdmResponseVersion,
            },
            payload: SpdmMessagePayload::SpdmVersionResponse(SpdmVersionResponsePayload {
                version_number_entry_count: 3,
                versions: [
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[0],
                    },
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[1],
                    },
                    SpdmVersionStruct {
                        update: 0,
                        version: self.common.config_info.spdm_version[2],
                    },
                ],
            }),
        };

        let _ = response.spdm_encode(&mut self.common, writer);
        if self.common.append_message_a(writer.used_slice()).is_err() {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorUnspecified, 0, writer);
        }
    }
}

#[cfg(all(test,))]
mod tests_responder {
    use super::*;
    use crate::message::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_version() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let bytes = &mut [0u8; 1024];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        context.handle_spdm_version(bytes);

        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 1024];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let u8_slice = &u8_slice[4..];
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseVersion
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x03);
            assert_eq!(payload.versions[0].update, 0);
            assert_eq!(payload.versions[0].version, SpdmVersion::SpdmVersion10);
            assert_eq!(payload.versions[1].update, 0);
            assert_eq!(payload.versions[1].version, SpdmVersion::SpdmVersion11);
            assert_eq!(payload.versions[2].update, 0);
            assert_eq!(payload.versions[2].version, SpdmVersion::SpdmVersion12);
        }
    }
}
