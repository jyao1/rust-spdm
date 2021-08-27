// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::responder::*;

impl<'a> ResponderContext<'a> {
    pub fn send_spdm_error(&mut self, error_code: SpdmErrorCode, error_data: u8) {
        info!("send spdm version\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code,
                error_data,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                    SpdmErrorResponseNoneExtData {},
                ),
            }),
        };
        response.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();
        let _ = self.send_message(&send_buffer[0..used]);
    }
}

#[cfg(test)]
mod tests_responder {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};
    #[test]
    fn test_case0_send_spdm_error() {
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

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        context.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
    }
}
