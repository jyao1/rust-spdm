// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
use crate::crypto;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
extern crate alloc;
use crate::protocol::gen_array_clone;
use alloc::boxed::Box;

impl ResponderContext {
    pub fn handle_spdm_digest(
        &mut self,
        bytes: &[u8],
        session_id: Option<u32>,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_digest_response(bytes, &mut writer);

        if let Some(session_id) = session_id {
            let _ = self.send_secured_message(
                session_id,
                writer.used_slice(),
                false,
                transport_encap,
                device_io,
            );
        } else {
            let _ = self.send_message(writer.used_slice(), transport_encap, device_io);
        }
    }

    fn write_spdm_digest_response(&mut self, bytes: &[u8], writer: &mut Writer) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let get_digests = SpdmGetDigestsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_digests) = get_digests {
            debug!("!!! get_digests : {:02x?}\n", get_digests);
        } else {
            error!("!!! get_digests : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        #[cfg(not(feature = "hashed-transcript-data"))]
        if self
            .common
            .runtime_info
            .message_b
            .append_message(&bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            &bytes[..reader.used()],
        );

        let digest_size = self.common.negotiate_info.base_hash_sel.get_size();

        info!("send spdm digest\n");
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseDigests,
            },
            payload: SpdmMessagePayload::SpdmDigestsResponse(SpdmDigestsResponsePayload {
                slot_mask: 0x1,
                slot_count: 1u8,
                digests: gen_array_clone(
                    SpdmDigestStruct {
                        data_size: digest_size,
                        data: Box::new([0xffu8; SPDM_MAX_HASH_SIZE]),
                    },
                    SPDM_MAX_SLOT_NUMBER,
                ),
            }),
        };
        response.spdm_encode(&mut self.common, writer);

        let my_cert_chain = self.common.provision_info.my_cert_chain.as_ref().unwrap();
        let cert_chain_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            my_cert_chain.as_ref(),
        )
        .unwrap();

        // patch the message before send
        let used = writer.used();
        writer.mut_used_slice()[(used - cert_chain_hash.data_size as usize)..used]
            .copy_from_slice(cert_chain_hash.as_ref());

        #[cfg(not(feature = "hashed-transcript-data"))]
        self.common
            .runtime_info
            .message_b
            .append_message(writer.used_slice());

        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(
            self.common
                .runtime_info
                .digest_context_m1m2
                .as_mut()
                .unwrap(),
            writer.used_slice(),
        );
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
    fn test_case0_handle_spdm_digest() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut context = responder::ResponderContext::new(config_info, provision_info);
        context.common.provision_info.my_cert_chain = Some(SpdmCertChainData {
            data_size: 512u16,
            data: [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        });
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.runtime_info.digest_context_m1m2 =
            Some(crypto::hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_384).unwrap());

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let bytes = &mut [0u8; 1024];
        context.handle_spdm_digest(
            bytes,
            None,
            pcidoe_transport_encap,
            &mut socket_io_transport,
        );
    }
}
