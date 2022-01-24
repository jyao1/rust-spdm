// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common;
use crate::common::spdm_codec::SpdmCodec;
use codec::enum_builder;
use codec::{Codec, Reader, Writer};

enum_builder! {
    @U8
    EnumName: SpdmErrorCode;
    EnumVal{
        SpdmErrorInvalidRequest => 0x1,
        SpdmErrorInvalidSession => 0x2,
        SpdmErrorBusy => 0x3,
        SpdmErrorUnexpectedRequest => 0x4,
        SpdmErrorUnspecified => 0x5,
        SpdmErrorDecryptError => 0x6,
        SpdmErrorUnsupportedRequest => 0x7,
        SpdmErrorRequestInFlight => 0x8,
        SpdmErrorInvalidResponseCode => 0x9,
        SpdmErrorSessionLimitExceeded => 0xA,
        SpdmErrorMajorVersionMismatch => 0x41,
        SpdmErrorResponseNotReady => 0x42,
        SpdmErrorRequestResynch => 0x43,
        SpdmErrorVendorDefined => 0xFF
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpdmErrorResponseNoneExtData {}

impl SpdmCodec for SpdmErrorResponseNoneExtData {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, _bytes: &mut Writer) {}

    fn spdm_read(
        _context: &mut common::SpdmContext,
        _r: &mut Reader,
    ) -> Option<SpdmErrorResponseNoneExtData> {
        Some(SpdmErrorResponseNoneExtData {})
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpdmErrorResponseNotReadyExtData {
    pub rdt_exponent: u8,
    pub request_code: u8,
    pub token: u8,
    pub tdtm: u8,
}

impl SpdmCodec for SpdmErrorResponseNotReadyExtData {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.rdt_exponent.encode(bytes);
        self.request_code.encode(bytes);
        self.token.encode(bytes);
        self.tdtm.encode(bytes);
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponseNotReadyExtData> {
        let rdt_exponent = u8::read(r)?;
        let request_code = u8::read(r)?;
        let token = u8::read(r)?;
        let tdtm = u8::read(r)?;

        Some(SpdmErrorResponseNotReadyExtData {
            rdt_exponent,
            request_code,
            token,
            tdtm,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpdmErrorResponseVendorExtData {
    pub data_size: u8,
    pub data: [u8; 32],
}

impl SpdmCodec for SpdmErrorResponseVendorExtData {
    fn spdm_encode(&self, _context: &mut common::SpdmContext, bytes: &mut Writer) {
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }

    fn spdm_read(
        _context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponseVendorExtData> {
        let mut data_size = 0;
        let mut data = [0u8; 32];

        for d in &mut data {
            let result = u8::read(r);
            match result {
                Some(v) => {
                    *d = v;
                    data_size += 1;
                }
                None => {
                    break;
                }
            }
        }

        Some(SpdmErrorResponseVendorExtData { data_size, data })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpdmErrorResponseExtData {
    SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData),
    SpdmErrorExtDataNotReady(SpdmErrorResponseNotReadyExtData),
    SpdmErrorExtDataVendorDefined(SpdmErrorResponseVendorExtData),
}
impl Default for SpdmErrorResponseExtData {
    fn default() -> SpdmErrorResponseExtData {
        SpdmErrorResponseExtData::SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData {})
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmErrorResponsePayload {
    pub error_code: SpdmErrorCode,
    pub error_data: u8,
    pub extended_data: SpdmErrorResponseExtData,
}

impl SpdmCodec for SpdmErrorResponsePayload {
    fn spdm_encode(&self, context: &mut common::SpdmContext, bytes: &mut Writer) {
        self.error_code.encode(bytes); // param1
        self.error_data.encode(bytes); // param2

        match &self.extended_data {
            SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) => {
                extended_data.spdm_encode(context, bytes);
            }
            SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(extended_data) => {
                extended_data.spdm_encode(context, bytes);
            }
            SpdmErrorResponseExtData::SpdmErrorExtDataNone(extended_data) => {
                extended_data.spdm_encode(context, bytes);
            }
        }
    }

    fn spdm_read(
        context: &mut common::SpdmContext,
        r: &mut Reader,
    ) -> Option<SpdmErrorResponsePayload> {
        let error_code = SpdmErrorCode::read(r)?; // param1
        let error_data = u8::read(r)?; // param2

        let extended_data = match error_code {
            SpdmErrorCode::SpdmErrorResponseNotReady => {
                Some(SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                    SpdmErrorResponseNotReadyExtData::spdm_read(context, r)?,
                ))
            }
            SpdmErrorCode::SpdmErrorVendorDefined => {
                Some(SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(
                    SpdmErrorResponseVendorExtData::spdm_read(context, r)?,
                ))
            }
            _ => Some(SpdmErrorResponseExtData::SpdmErrorExtDataNone(
                SpdmErrorResponseNoneExtData::spdm_read(context, r)?,
            )),
        };

        let extended_data = extended_data?;

        Some(SpdmErrorResponsePayload {
            error_code,
            error_data,
            extended_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlib::*;

    #[test]
    fn test_case0_spdm_error_response_not_ready_ext_data() {
        let u8_slice = &mut [0u8; 8];
        let mut writer = Writer::init(u8_slice);

        let value = SpdmErrorResponseNotReadyExtData {
            rdt_exponent: 0xaa,
            request_code: 0xaa,
            token: 0x55,
            tdtm: 0x55,
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        let spdm_error_response_not_ready_ext_data =
            SpdmErrorResponseNotReadyExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(spdm_error_response_not_ready_ext_data.rdt_exponent, 0xaa);
        assert_eq!(spdm_error_response_not_ready_ext_data.request_code, 0xaa);
        assert_eq!(spdm_error_response_not_ready_ext_data.token, 0x55);
        assert_eq!(spdm_error_response_not_ready_ext_data.tdtm, 0x55);
        assert_eq!(4, reader.left());
    }
    #[test]
    fn test_case0_spdm_error_response_vendor_ext_data() {
        let u8_slice = &mut [0u8; 32];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmErrorResponseVendorExtData {
            data_size: 32,
            data: [100u8; 32],
        };
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(32, reader.left());
        let response_vendor_ext_data =
            SpdmErrorResponseVendorExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(response_vendor_ext_data.data_size, 32);
        for i in 0..32 {
            assert_eq!(response_vendor_ext_data.data[i], 100u8);
        }
    }
    #[test]
    fn test_case1_spdm_error_response_vendor_ext_data() {
        let u8_slice = &mut [0u8; 32];
        let mut writer = Writer::init(u8_slice);
        let value = SpdmErrorResponseVendorExtData::default();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        value.spdm_encode(&mut context, &mut writer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(32, reader.left());
        let response_vendor_ext_data =
            SpdmErrorResponseVendorExtData::spdm_read(&mut context, &mut reader).unwrap();
        assert_eq!(response_vendor_ext_data.data_size, 32);
        for i in 0..32 {
            assert_eq!(response_vendor_ext_data.data[i], 0);
        }
    }
    #[test]
    fn test_case0_spdm_error_response_payload() {
        let value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorResponseNotReady,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(
                SpdmErrorResponseNotReadyExtData {
                    rdt_exponent: 0x11,
                    request_code: 0x22,
                    token: 0x33,
                    tdtm: 0x44,
                },
            ),
        };

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let my_spdm_device_io = &mut MySpdmDeviceIo;
        let mut context = new_context(my_spdm_device_io, pcidoe_transport_encap);

        let mut spdm_error_response_payload = new_spdm_response(value, &mut context);

        assert_eq!(
            spdm_error_response_payload.error_code,
            SpdmErrorCode::SpdmErrorResponseNotReady
        );
        assert_eq!(spdm_error_response_payload.error_data, 100);
        if let SpdmErrorResponseExtData::SpdmErrorExtDataNotReady(extended_data) =
            &spdm_error_response_payload.extended_data
        {
            assert_eq!(extended_data.rdt_exponent, 0x11);
            assert_eq!(extended_data.request_code, 0x22);
            assert_eq!(extended_data.token, 0x33);
            assert_eq!(extended_data.tdtm, 0x44);
        }

        let mut value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorVendorDefined,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::default(),
        };
        value.extended_data = SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(
            SpdmErrorResponseVendorExtData {
                data_size: 32,
                data: [100u8; 32],
            },
        );
        spdm_error_response_payload = new_spdm_response(value, &mut context);

        if let SpdmErrorResponseExtData::SpdmErrorExtDataVendorDefined(extended_data) =
            &spdm_error_response_payload.extended_data
        {
            assert_eq!(extended_data.data_size, 32);
            for i in 0..32 {
                assert_eq!(extended_data.data[i], 100u8);
            }
        }

        let mut value = SpdmErrorResponsePayload {
            error_code: SpdmErrorCode::SpdmErrorInvalidRequest,
            error_data: 100,
            extended_data: SpdmErrorResponseExtData::default(),
        };
        value.extended_data =
            SpdmErrorResponseExtData::SpdmErrorExtDataNone(SpdmErrorResponseNoneExtData {});
        new_spdm_response(value, &mut context);
    }

    fn new_spdm_response(
        value: SpdmErrorResponsePayload,
        context: &mut common::SpdmContext,
    ) -> SpdmErrorResponsePayload {
        let u8_slice = &mut [0u8; 100];
        let mut writer = Writer::init(u8_slice);
        value.spdm_encode(context, &mut writer);
        let mut reader = Reader::init(u8_slice);

        SpdmErrorResponsePayload::spdm_read(context, &mut reader).unwrap()
    }
}
