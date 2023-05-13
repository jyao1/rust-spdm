// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::opaque::{SpdmOpaqueStruct, MAX_SPDM_OPAQUE_SIZE};
use crate::common::ManagedBuffer;
use crate::common::SpdmCodec;
use crate::common::SpdmMeasurementContentChanged;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_BUFFER_FULL;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::SPDM_STATUS_INVALID_PARAMETER;
use crate::message::*;
use crate::protocol::*;
use crate::responder::*;
use crate::secret::*;

impl<'a> ResponderContext<'a> {
    pub fn handle_spdm_measurement(&mut self, session_id: Option<u32>, bytes: &[u8]) {
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        self.write_spdm_measurement_response(session_id, bytes, &mut writer);
        match session_id {
            None => {
                let _ = self.send_message(writer.used_slice());
            }
            Some(session_id) => {
                let _ = self.send_secured_message(session_id, writer.used_slice(), false);
            }
        }
    }

    pub fn write_spdm_measurement_response(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
        writer: &mut Writer,
    ) {
        let mut reader = Reader::init(bytes);
        let message_header = SpdmMessageHeader::read(&mut reader);
        if let Some(message_header) = message_header {
            if message_header.version != self.common.negotiate_info.spdm_version_sel {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorVersionMismatch, 0, writer);
                return;
            }
        } else {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        let get_measurements =
            SpdmGetMeasurementsRequestPayload::spdm_read(&mut self.common, &mut reader);
        if let Some(get_measurements) = &get_measurements {
            debug!("!!! get_measurements : {:02x?}\n", get_measurements);
        } else {
            error!("!!! get_measurements : fail !!!\n");
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }
        let get_measurements = get_measurements.unwrap();

        let signature_size = self.common.negotiate_info.base_asym_sel.get_size();

        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
        {
            self.common.runtime_info.need_measurement_signature = true;
        } else {
            self.common.runtime_info.need_measurement_signature = false;
        }

        let base_hash_sel = self.common.negotiate_info.base_hash_sel;
        let spdm_version_sel = self.common.negotiate_info.spdm_version_sel;
        #[cfg(feature = "hashed-transcript-data")]
        let message_a = self.common.runtime_info.message_a.clone();
        let measurement_specification_sel =
            self.common.negotiate_info.measurement_specification_sel;
        let runtime_content_change_support = self.common.config_info.runtime_content_change_support;
        let content_changed = self.common.runtime_info.content_changed;
        let base_asym_sel = self.common.negotiate_info.base_asym_sel;

        #[cfg(not(feature = "hashed-transcript-data"))]
        if self
            .append_message_m_response(session_id, &bytes[..reader.used()])
            .is_none()
        {
            self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
            return;
        }

        info!("send spdm measurement\n");

        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        let _ = crypto::rand::get_random(&mut nonce);

        let real_measurement_block_count = spdm_measurement_collection(
            spdm_version_sel,
            measurement_specification_sel,
            base_hash_sel,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize,
        )
        .unwrap()
        .number_of_blocks;

        let number_of_measurement: u8 = if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll
            || get_measurements.measurement_operation
                == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber
        {
            real_measurement_block_count
        } else {
            1
        };
        let measurement_record = if get_measurements.measurement_operation
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll
        {
            spdm_measurement_collection(
                spdm_version_sel,
                measurement_specification_sel,
                base_hash_sel,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize,
            )
            .unwrap()
        } else if let SpdmMeasurementOperation::Unknown(index) =
            get_measurements.measurement_operation
        {
            if index > real_measurement_block_count {
                self.write_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0, writer);
                return;
            }
            spdm_measurement_collection(
                spdm_version_sel,
                measurement_specification_sel,
                base_hash_sel,
                index as usize,
            )
            .unwrap()
        } else {
            SpdmMeasurementRecordStructure::default()
        };

        let content_changed =
            if runtime_content_change_support && spdm_version_sel == SpdmVersion::SpdmVersion12 {
                content_changed
            } else {
                SpdmMeasurementContentChanged::NOT_SUPPORTED
            };

        let response = SpdmMessage {
            header: SpdmMessageHeader {
                version: spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmResponseMeasurements,
            },
            payload: SpdmMessagePayload::SpdmMeasurementsResponse(
                SpdmMeasurementsResponsePayload {
                    number_of_measurement,
                    slot_id: get_measurements.slot_id,
                    content_changed,
                    measurement_record,
                    nonce: SpdmNonceStruct { data: nonce },
                    opaque: SpdmOpaqueStruct {
                        data_size: 0,
                        data: [0u8; MAX_SPDM_OPAQUE_SIZE],
                    },
                    signature: SpdmSignatureStruct {
                        data_size: signature_size,
                        data: [0x60u8; SPDM_MAX_ASYM_KEY_SIZE],
                    },
                },
            ),
        };

        let used = if let Ok(sz) = response.spdm_encode(&mut self.common, writer) {
            sz
        } else {
            panic!("Failed to encode!");
        };

        #[cfg(feature = "hashed-transcript-data")]
        let message_m = match session_id {
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                    s
                } else {
                    panic!("invalid session id");
                };

                if session.runtime_info.digest_context_l1l2.is_none() {
                    session.runtime_info.digest_context_l1l2 =
                        crypto::hash::hash_ctx_init(base_hash_sel);
                    if spdm_version_sel == SpdmVersion::SpdmVersion12 {
                        crypto::hash::hash_ctx_update(
                            session.runtime_info.digest_context_l1l2.as_mut().unwrap(),
                            message_a.as_ref(),
                        )
                        .unwrap();
                    }
                }

                &mut session.runtime_info.digest_context_l1l2
            }
            None => {
                if self.common.runtime_info.digest_context_l1l2.is_none() {
                    self.common.runtime_info.digest_context_l1l2 =
                        crypto::hash::hash_ctx_init(base_hash_sel);
                    if spdm_version_sel == SpdmVersion::SpdmVersion12 {
                        crypto::hash::hash_ctx_update(
                            self.common
                                .runtime_info
                                .digest_context_l1l2
                                .as_mut()
                                .unwrap(),
                            message_a.as_ref(),
                        )
                        .unwrap();
                    }
                }

                &mut self.common.runtime_info.digest_context_l1l2
            }
        };
        #[cfg(feature = "hashed-transcript-data")]
        crypto::hash::hash_ctx_update(message_m.as_mut().unwrap(), &bytes[..reader.used()])
            .unwrap();

        // generat signature
        if get_measurements
            .measurement_attributes
            .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
        {
            let base_asym_size = base_asym_sel.get_size() as usize;
            let temp_used = used - base_asym_size;
            #[cfg(not(feature = "hashed-transcript-data"))]
            self.append_message_m_response(session_id, &writer.used_slice()[..temp_used]);

            #[cfg(feature = "hashed-transcript-data")]
            crypto::hash::hash_ctx_update(
                message_m.as_mut().unwrap(),
                &writer.used_slice()[..temp_used],
            )
            .unwrap();

            let signature = self.generate_measurement_signature(session_id);
            if signature.is_err() {
                self.send_spdm_error(SpdmErrorCode::SpdmErrorInvalidRequest, 0);
                return;
            }
            let signature = signature.unwrap();
            // patch the message before send
            writer.mut_used_slice()[(used - base_asym_size)..used]
                .copy_from_slice(signature.as_ref());
            #[cfg(not(feature = "hashed-transcript-data"))]
            match session_id {
                Some(session_id) => {
                    self.common
                        .get_session_via_id(session_id)
                        .unwrap()
                        .runtime_info
                        .message_m
                        .reset_message();
                }
                None => {
                    self.common.runtime_info.message_m.reset_message();
                }
            }
            #[cfg(feature = "hashed-transcript-data")]
            match session_id {
                Some(session_id) => {
                    self.common
                        .get_session_via_id(session_id)
                        .unwrap()
                        .runtime_info
                        .digest_context_l1l2 = None;
                }
                None => {
                    self.common.runtime_info.digest_context_l1l2 = None;
                }
            }
        } else {
            #[cfg(not(feature = "hashed-transcript-data"))]
            self.append_message_m_response(session_id, writer.used_slice());
            #[cfg(feature = "hashed-transcript-data")]
            match session_id {
                Some(_) => {
                    crypto::hash::hash_ctx_update(message_m.as_mut().unwrap(), writer.used_slice())
                        .unwrap();
                }
                None => {
                    crypto::hash::hash_ctx_update(
                        self.common
                            .runtime_info
                            .digest_context_l1l2
                            .as_mut()
                            .unwrap(),
                        writer.used_slice(),
                    )
                    .unwrap();
                }
            }
        }
    }
    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn append_message_m_response(
        &mut self,
        session_id: Option<u32>,
        bytes: &[u8],
    ) -> Option<usize> {
        match session_id {
            None => self.common.runtime_info.message_m.append_message(bytes),
            Some(session_id) => {
                let session = self.common.get_session_via_id(session_id).unwrap();
                session.runtime_info.message_m.append_message(bytes)
            }
        }
    }

    pub fn generate_measurement_signature(
        &mut self,
        session_id: Option<u32>,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let mut message = ManagedBuffer::default();

        #[cfg(not(feature = "hashed-transcript-data"))]
        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            let message_a = self.common.runtime_info.message_a.clone();
            message
                .append_message(message_a.as_ref())
                .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
        }

        #[cfg(not(feature = "hashed-transcript-data"))]
        match session_id {
            None => {
                message
                    .append_message(self.common.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_session_via_id(session_id) {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                message
                    .append_message(session.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
        }
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        #[cfg(not(feature = "hashed-transcript-data"))]
        let message_hash =
            crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

        #[cfg(feature = "hashed-transcript-data")]
        let message_hash = match session_id {
            Some(session_id) => crypto::hash::hash_ctx_finalize(
                self.common
                    .get_session_via_id(session_id)
                    .unwrap()
                    .runtime_info
                    .digest_context_l1l2
                    .as_mut()
                    .cloned()
                    .unwrap(),
            )
            .unwrap(),
            None => crypto::hash::hash_ctx_finalize(
                self.common
                    .runtime_info
                    .digest_context_l1l2
                    .as_mut()
                    .cloned()
                    .unwrap(),
            )
            .unwrap(),
        };
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        if self.common.negotiate_info.spdm_version_sel == SpdmVersion::SpdmVersion12 {
            message.reset_message();
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message
                .append_message(message_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crypto::asym_sign::sign(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
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
    #[should_panic(expected = "not implemented")]
    fn test_case0_handle_spdm_measurement() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::Unknown(5),
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            //not useful,
            //actually if MeasurementeAttributes is zero(not signature),
            //slot_id will be set to zero when calling SpdmGetMeasurementsRequestPayload.spdm_encode().
            //such like value.spdm_encode().
            slot_id: 0xaau8,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        context.handle_spdm_measurement(None, bytes);

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let data = context.common.runtime_info.message_m.as_ref();
            let u8_slice = &mut [0u8; 2048];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestChallenge
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let get_measurements =
                SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader)
                    .unwrap();
            assert_eq!(
                get_measurements.measurement_attributes,
                SpdmMeasurementAttributes::empty()
            );
            assert_eq!(
                get_measurements.measurement_operation,
                SpdmMeasurementOperation::Unknown(5)
            );

            let spdm_message_slice = &u8_slice[4..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseMeasurements
            );
            if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
                assert_eq!(payload.number_of_measurement, 1);
                assert_eq!(payload.slot_id, 0);
                assert_eq!(payload.measurement_record.number_of_blocks, 1);
                //index in measurement_record should equal to measurement_operation
                assert_eq!(payload.measurement_record.record[0].index, 5);
                assert_eq!(
                    payload.measurement_record.record[0].measurement_specification,
                    SpdmMeasurementSpecification::DMTF
                );
                let measurement_size = context
                    .common
                    .negotiate_info
                    .measurement_hash_sel
                    .get_size()
                    + 3;
                assert_eq!(
                    payload.measurement_record.record[0].measurement_size,
                    measurement_size
                );
                assert_eq!(
                    payload.measurement_record.record[0].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
                );
                assert_eq!(
                    payload.measurement_record.record[0]
                        .measurement
                        .representation,
                    SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
                );
                let value_size = context
                    .common
                    .negotiate_info
                    .measurement_hash_sel
                    .get_size();
                assert_eq!(
                    payload.measurement_record.record[0].measurement.value_size,
                    value_size
                );
                for i in 0..value_size as usize {
                    assert_eq!(
                        payload.measurement_record.record[0].measurement.value[i],
                        95
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "not implemented")]
    fn test_case1_handle_spdm_measurement() {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion10;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;

        let spdm_message_header = &mut [0u8; 1024];
        let mut writer = Writer::init(spdm_message_header);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let measurements_struct = &mut [0u8; 1024];
        let mut writer = Writer::init(measurements_struct);
        let value = SpdmGetMeasurementsRequestPayload {
            measurement_attributes: SpdmMeasurementAttributes::empty(),
            measurement_operation: SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            nonce: SpdmNonceStruct {
                data: [100u8; SPDM_NONCE_SIZE],
            },
            //not useful,
            //actually if MeasurementeAttributes is zero(not signature),
            //slot_id will be set to zero when calling SpdmGetMeasurementsRequestPayload.spdm_encode().
            //such like value.spdm_encode().
            slot_id: 0xaau8,
        };
        assert!(value.spdm_encode(&mut context.common, &mut writer).is_ok());

        let bytes = &mut [0u8; 1024];
        bytes.copy_from_slice(&spdm_message_header[0..]);
        bytes[2..].copy_from_slice(&measurements_struct[0..1022]);
        context.handle_spdm_measurement(None, bytes);

        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            let data = context.common.runtime_info.message_m.as_ref();
            let u8_slice = &mut [0u8; 2048];
            for (i, data) in data.iter().enumerate() {
                u8_slice[i] = *data;
            }

            let mut message_header_slice = Reader::init(u8_slice);
            let spdm_message_header = SpdmMessageHeader::read(&mut message_header_slice).unwrap();
            assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
            assert_eq!(
                spdm_message_header.request_response_code,
                SpdmRequestResponseCode::SpdmRequestChallenge
            );

            let spdm_struct_slice = &u8_slice[2..];
            let mut reader = Reader::init(spdm_struct_slice);
            let get_measurements =
                SpdmGetMeasurementsRequestPayload::spdm_read(&mut context.common, &mut reader)
                    .unwrap();
            assert_eq!(
                get_measurements.measurement_attributes,
                SpdmMeasurementAttributes::empty()
            );
            assert_eq!(
                get_measurements.measurement_operation,
                SpdmMeasurementOperation::SpdmMeasurementRequestAll
            );

            let spdm_message_slice = &u8_slice[4..];
            let mut reader = Reader::init(spdm_message_slice);
            let spdm_message: SpdmMessage =
                SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();
            assert_eq!(
                spdm_message.header.request_response_code,
                SpdmRequestResponseCode::SpdmResponseMeasurements
            );

            if let SpdmMessagePayload::SpdmMeasurementsResponse(payload) = &spdm_message.payload {
                assert_eq!(payload.number_of_measurement, 1);
                //if measurement_attributes == 0, it means responder donot need append signature,
                //and slot_id should be 0.
                assert_eq!(payload.slot_id, 0);
                assert_eq!(payload.measurement_record.number_of_blocks, 5);

                for i in 0..5 {
                    assert_eq!(payload.measurement_record.record[i].index, (i as u8) + 1);
                    assert_eq!(
                        payload.measurement_record.record[i].measurement_specification,
                        SpdmMeasurementSpecification::DMTF
                    );
                }

                let measurement_size = context
                    .common
                    .negotiate_info
                    .measurement_hash_sel
                    .get_size()
                    + 3;
                for i in 0..4 {
                    assert_eq!(
                        payload.measurement_record.record[i].measurement_size,
                        measurement_size
                    );
                    assert_eq!(
                        payload.measurement_record.record[i]
                            .measurement
                            .representation,
                        SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest
                    );
                }
                assert_eq!(
                    payload.measurement_record.record[4].measurement_size,
                    3 + config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
                );
                assert_eq!(
                    payload.measurement_record.record[4]
                        .measurement
                        .representation,
                    SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit
                );

                assert_eq!(
                    payload.measurement_record.record[0].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementRom
                );
                assert_eq!(
                    payload.measurement_record.record[1].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmware
                );
                assert_eq!(
                    payload.measurement_record.record[2].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementHardwareConfig
                );
                assert_eq!(
                    payload.measurement_record.record[3].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementFirmwareConfig
                );
                assert_eq!(
                    payload.measurement_record.record[4].measurement.r#type,
                    SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest
                );

                let value_size = context
                    .common
                    .negotiate_info
                    .measurement_hash_sel
                    .get_size();
                assert_eq!(
                    payload.measurement_record.record[0].measurement.value_size,
                    value_size
                );
                assert_eq!(
                    payload.measurement_record.record[1].measurement.value_size,
                    SHA384_DIGEST_SIZE as u16
                );
                assert_eq!(
                    payload.measurement_record.record[2].measurement.value_size,
                    value_size
                );
                assert_eq!(
                    payload.measurement_record.record[3].measurement.value_size,
                    value_size
                );
                assert_eq!(
                    payload.measurement_record.record[4].measurement.value_size,
                    config::MAX_SPDM_MEASUREMENT_VALUE_LEN as u16,
                );

                for j in 0..value_size as usize {
                    assert_eq!(
                        payload.measurement_record.record[0].measurement.value[j],
                        0x5au8
                    );
                    assert_eq!(
                        payload.measurement_record.record[1].measurement.value[j],
                        0x5bu8
                    );
                    assert_eq!(
                        payload.measurement_record.record[2].measurement.value[j],
                        0x5cu8
                    );
                    assert_eq!(
                        payload.measurement_record.record[3].measurement.value[j],
                        0x5du8
                    );
                    assert_eq!(
                        payload.measurement_record.record[4].measurement.value[j],
                        0x5eu8
                    );
                }
            }
        }
    }
}
