// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
#[cfg(feature = "hashed-transcript-data")]
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;
use crate::error::{
    SpdmResult, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_ERROR_PEER,
    SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_PARAMETER, SPDM_STATUS_VERIF_FAIL,
};
use crate::message::*;
use crate::protocol::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_measurement_record(
        &mut self,
        session_id: Option<u32>,
        measurement_attributes: SpdmMeasurementAttributes,
        measurement_operation: SpdmMeasurementOperation,
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure,
        slot_id: u8,
    ) -> SpdmResult<u8> {
        info!("send spdm measurement\n");

        if slot_id >= SPDM_MAX_SLOT_NUMBER as u8 {
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        self.common.reset_buffer_via_request_code(
            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            session_id,
        );

        let mut send_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let send_used = self.encode_spdm_measurement_record(
            measurement_attributes,
            measurement_operation,
            slot_id,
            &mut send_buffer,
        )?;
        match session_id {
            Some(session_id) => {
                self.send_secured_message(session_id, &send_buffer[..send_used], false)?;
            }
            None => {
                self.send_message(&send_buffer[..send_used])?;
            }
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_MSG_SIZE];
        let used = match session_id {
            Some(session_id) => {
                self.receive_secured_message(session_id, &mut receive_buffer, true)?
            }
            None => self.receive_message(&mut receive_buffer, true)?,
        };

        self.handle_spdm_measurement_record_response(
            session_id,
            slot_id,
            measurement_attributes,
            measurement_operation,
            spdm_measurement_record_structure,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_measurement_record(
        &mut self,
        measurement_attributes: SpdmMeasurementAttributes,
        measurement_operation: SpdmMeasurementOperation,
        slot_id: u8,
        buf: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut writer = Writer::init(buf);
        let mut nonce = [0u8; SPDM_NONCE_SIZE];
        crypto::rand::get_random(&mut nonce)?;

        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetMeasurements,
            },
            payload: SpdmMessagePayload::SpdmGetMeasurementsRequest(
                SpdmGetMeasurementsRequestPayload {
                    measurement_attributes,
                    measurement_operation,
                    nonce: SpdmNonceStruct { data: nonce },
                    slot_id,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn handle_spdm_measurement_record_response(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        measurement_attributes: SpdmMeasurementAttributes,
        measurement_operation: SpdmMeasurementOperation,
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<u8> {
        if measurement_attributes.contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED) {
            self.common.runtime_info.need_measurement_signature = true;
        } else {
            self.common.runtime_info.need_measurement_signature = false;
        }

        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => {
                if message_header.version != self.common.negotiate_info.spdm_version_sel {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                }
                match message_header.request_response_code {
                    SpdmRequestResponseCode::SpdmResponseMeasurements => {
                        let measurements = SpdmMeasurementsResponsePayload::spdm_read(
                            &mut self.common,
                            &mut reader,
                        );
                        let used = reader.used();
                        if let Some(measurements) = measurements {
                            debug!("!!! measurements : {:02x?}\n", measurements);

                            if self.common.negotiate_info.spdm_version_sel.get_u8()
                                >= SpdmVersion::SpdmVersion12.get_u8()
                            {
                                self.common.runtime_info.content_changed =
                                    measurements.content_changed;
                            }

                            let base_asym_size =
                                self.common.negotiate_info.base_asym_sel.get_size() as usize;
                            let temp_used = used
                                - if self.common.runtime_info.need_measurement_signature {
                                    base_asym_size
                                } else {
                                    0
                                };

                            self.common.append_message_m(session_id, send_buffer)?;
                            self.common
                                .append_message_m(session_id, &receive_buffer[..temp_used])?;

                            // verify signature
                            if measurement_attributes
                                .contains(SpdmMeasurementAttributes::SIGNATURE_REQUESTED)
                            {
                                if self
                                    .verify_measurement_signature(
                                        slot_id,
                                        session_id,
                                        &measurements.signature,
                                    )
                                    .is_err()
                                {
                                    error!("verify_measurement_signature fail");
                                    self.common.reset_message_m(session_id);
                                    return Err(SPDM_STATUS_VERIF_FAIL);
                                } else {
                                    self.common.reset_message_m(session_id);
                                    info!("verify_measurement_signature pass");
                                }
                            }

                            *spdm_measurement_record_structure = SpdmMeasurementRecordStructure {
                                ..measurements.measurement_record
                            };

                            match measurement_operation {
                                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber => {
                                    Ok(measurements.number_of_measurement)
                                }
                                SpdmMeasurementOperation::SpdmMeasurementRequestAll => {
                                    Ok(measurements.measurement_record.number_of_blocks)
                                }
                                _ => Ok(measurements.measurement_record.number_of_blocks),
                            }
                        } else {
                            error!("!!! measurements : fail !!!\n");
                            Err(SPDM_STATUS_INVALID_MSG_FIELD)
                        }
                    }
                    SpdmRequestResponseCode::SpdmResponseError => {
                        let status = self.spdm_handle_error_response_main(
                            session_id,
                            receive_buffer,
                            SpdmRequestResponseCode::SpdmRequestGetMeasurements,
                            SpdmRequestResponseCode::SpdmResponseMeasurements,
                        );
                        match status {
                            Err(status) => Err(status),
                            Ok(()) => Err(SPDM_STATUS_ERROR_PEER),
                        }
                    }
                    _ => Err(SPDM_STATUS_ERROR_PEER),
                }
            }
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }

    pub fn send_receive_spdm_measurement(
        &mut self,
        session_id: Option<u32>,
        slot_id: u8,
        spdm_measuremente_attributes: SpdmMeasurementAttributes,
        measurement_operation: SpdmMeasurementOperation,
        out_total_number: &mut u8, // out, total number when measurement_operation = SpdmMeasurementQueryTotalNumber
        //      number of blocks got measured.
        spdm_measurement_record_structure: &mut SpdmMeasurementRecordStructure, // out
    ) -> SpdmResult {
        *out_total_number = self.send_receive_spdm_measurement_record(
            session_id,
            spdm_measuremente_attributes,
            measurement_operation,
            spdm_measurement_record_structure,
            slot_id,
        )?;
        Ok(())
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn verify_measurement_signature(
        &self,
        slot_id: u8,
        session_id: Option<u32>,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let message_l1l2_hash = match session_id {
            None => {
                let ctx = self
                    .common
                    .runtime_info
                    .digest_context_l1l2
                    .as_ref()
                    .cloned()
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
                crypto::hash::hash_ctx_finalize(ctx).ok_or(SPDM_STATUS_CRYPTO_ERROR)?
            }
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_immutable_session_via_id(session_id)
                {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_MSG_FIELD);
                };
                let ctx = session
                    .runtime_info
                    .digest_context_l1l2
                    .as_ref()
                    .cloned()
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
                crypto::hash::hash_ctx_finalize(ctx).ok_or(SPDM_STATUS_CRYPTO_ERROR)?
            }
        };

        debug!("message_l1l2_hash - {:02x?}", message_l1l2_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        let mut message_sign = ManagedBuffer12Sign::default();
        if self.common.negotiate_info.spdm_version_sel.get_u8()
            >= SpdmVersion::SpdmVersion12.get_u8()
        {
            message_sign.reset_message();
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_sign
                .append_message(message_l1l2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        } else {
            error!("hashed-transcript-data is unsupported in SPDM 1.0/1.1 signing verification!\n");
            return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
        }

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message_sign.as_ref(),
            signature,
        )
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn verify_measurement_signature(
        &self,
        slot_id: u8,
        session_id: Option<u32>,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let mut message_l1l2 = ManagedBufferL1L2::default();

        if self.common.negotiate_info.spdm_version_sel.get_u8()
            >= SpdmVersion::SpdmVersion12.get_u8()
        {
            let message_a = self.common.runtime_info.message_a.clone();
            message_l1l2
                .append_message(message_a.as_ref())
                .map_or_else(|| Err(SPDM_STATUS_BUFFER_FULL), |_| Ok(()))?;
        }

        match session_id {
            None => {
                message_l1l2
                    .append_message(self.common.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
            Some(session_id) => {
                let session = if let Some(s) = self.common.get_immutable_session_via_id(session_id)
                {
                    s
                } else {
                    return Err(SPDM_STATUS_INVALID_PARAMETER);
                };
                message_l1l2
                    .append_message(session.runtime_info.message_m.as_ref())
                    .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            }
        }

        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        debug!("message_l1l2 - {:02x?}", message_l1l2.as_ref());
        let message_l1l2_hash = crypto::hash::hash_all(
            self.common.negotiate_info.base_hash_sel,
            message_l1l2.as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        debug!("message_l1l2_hash - {:02x?}", message_l1l2_hash.as_ref());

        if self.common.peer_info.peer_cert_chain[slot_id as usize].is_none() {
            error!("peer_cert_chain is not populated!\n");
            return Err(SPDM_STATUS_INVALID_PARAMETER);
        }

        let cert_chain_data = &self.common.peer_info.peer_cert_chain[slot_id as usize]
            .as_ref()
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
            .data[(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.common.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];

        if self.common.negotiate_info.spdm_version_sel.get_u8()
            >= SpdmVersion::SpdmVersion12.get_u8()
        {
            message_l1l2.reset_message();
            message_l1l2
                .append_message(&SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(&SPDM_VERSION_1_2_SIGNING_CONTEXT_ZEROPAD_6)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(&SPDM_MEASUREMENTS_SIGN_CONTEXT)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            message_l1l2
                .append_message(message_l1l2_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        crypto::asym_verify::verify(
            self.common.negotiate_info.base_hash_sel,
            self.common.negotiate_info.base_asym_sel,
            cert_chain_data,
            message_l1l2.as_ref(),
            signature,
        )
    }
}
