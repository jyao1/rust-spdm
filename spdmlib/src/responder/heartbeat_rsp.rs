// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_heartbeat(&mut self, session_id: u32, bytes: &[u8]) {
        let mut reader = Reader::init(bytes);
        SpdmMessageHeader::read(&mut reader);

        let heartbeat_req = SpdmHeartbeatRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(heartbeat_req) = heartbeat_req {
            debug!("!!! heartbeat req : {:02x?}\n", heartbeat_req);
        } else {
            error!("!!! heartbeat req : fail !!!\n");
            return;
        }

        info!("send spdm heartbeat rsp\n");

        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseHeartbeatAck,
            },
            payload: SpdmMessagePayload::SpdmHeartbeatResponse(SpdmHeartbeatResponsePayload {}),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_secured_message(session_id, &send_buffer[0..used]);
    }
}
#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::msgs::SpdmMessageHeader;
    use crate::testlib::*;
    use crate::{crypto, responder};
    use codec::{Codec, Writer};

    #[test]
    fn test_case0_handle_spdm_heartbeat() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        crypto::asym_sign::register(ASYM_SIGN_IMPL);
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
            request_response_code: SpdmResponseResponseCode::SpdmRequestChallenge,
        };
        value.encode(&mut writer);

        let session_id = 4294901758u32;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        context.handle_spdm_heartbeat(session_id, bytes);
    }
}
