// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_digest(&mut self, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_digests = SpdmGetDigestsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_digests) = get_digests {
            debug!("!!! get_digests : {:02x?}\n", get_digests);
        } else {
            error!("!!! get_digests : fail !!!\n");
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        if self
            .common
            .runtime_info
            .message_b
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
            return;
        }

        let digest_size = self.common.negotiate_info.base_hash_sel.get_size();

        info!("send spdm digest\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask: 0x1,
                slot_count: 1u8,
                digests: [SpdmDigestStruct {
                    data_size: digest_size as u16,
                    data: [0xffu8; SPDM_MAX_HASH_SIZE],
                }; SPDM_MAX_SLOT_NUMBER],
            }),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        let my_cert_chain = self.common.provision_info.my_cert_chain.unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        // patch the message before send
        send_buffer[(used - cert_chain_hash.data_size as usize)..used]
            .copy_from_slice(cert_chain_hash.as_ref());

        let _ = self.send_message(&send_buffer[0..used]);

        self.common
            .runtime_info
            .message_b
            .append_message(&send_buffer[..used]);
    }
}
