// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::SpdmCodec;
use crate::common::SpdmDeviceIo;
use crate::common::SpdmTransportEncap;
use crate::message::*;
use crate::responder::*;

impl ResponderContext {
    pub fn write_spdm_error(
        &mut self,
        error_code: SpdmErrorCode,
        error_data: u8,
        writer: &mut Writer,
    ) {
        let error = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseError,
            },
            payload: SpdmMessagePayload::SpdmErrorResponse(SpdmErrorResponsePayload {
                error_code,
                error_data,
                extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                    SpdmErrorResponseNoneExtData {},
                ),
            }),
        };
        error.spdm_encode(&mut self.common, writer);
    }

    pub fn send_spdm_error(
        &mut self,
        error_code: SpdmErrorCode,
        error_data: u8,
        transport_encap: &mut dyn SpdmTransportEncap,
        device_io: &mut dyn SpdmDeviceIo,
    ) {
        info!("send spdm version\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_error(error_code, error_data, &mut writer);
        let _ = self.send_message(writer.used_slice(), transport_encap, device_io);
    }
}

#[cfg(all(test,))]
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
        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

        context.send_spdm_error(
            SpdmErrorCode::SpdmErrorInvalidRequest,
            0,
            pcidoe_transport_encap,
            &mut socket_io_transport,
        );
    }
}
