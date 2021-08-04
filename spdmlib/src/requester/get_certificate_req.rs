// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto;
use crate::error::SpdmResult;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_certificate_partial(
        &mut self,
        slot_id: u8,
        offset: u16,
        length: u16,
    ) -> SpdmResult<(u16, u16)> {
        info!("send spdm certificate\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let mut writer = Writer::init(&mut send_buffer);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: SpdmVersion::SpdmVersion11,
                request_response_code: SpdmResponseResponseCode::SpdmRequestGetCertificate,
            },
            payload: SpdmMessagePayload::SpdmGetCertificateRequest(
                SpdmGetCertificateRequestPayload {
                    slot_id,
                    offset,
                    length,
                },
            ),
        };
        request.spdm_encode(&mut self.common, &mut writer);
        let used = writer.used();

        self.send_message(&send_buffer[..used])?;

        // append message_b
        if self
            .common
            .runtime_info
            .message_b
            .append_message(&send_buffer[..used])
            .is_none()
        {
            return spdm_result_err!(ENOMEM);
        }

        // Receive
        let mut receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let used = self.receive_message(&mut receive_buffer)?;

        let mut reader = Reader::init(&receive_buffer[..used]);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmResponseResponseCode::SpdmResponseCertificate => {
                    let certificate =
                        SpdmCertificateResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(certificate) = certificate {
                        debug!("!!! certificate : {:02x?}\n", certificate);
                        if (offset + certificate.portion_length) as usize > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE {
                            return spdm_result_err!(ENOMEM);
                        }
                        self.common.peer_info.peer_cert_chain.cert_chain.data[(offset as usize)
                            ..(offset as usize + certificate.portion_length as usize)]
                            .copy_from_slice(
                                &certificate.cert_chain[0..(certificate.portion_length as usize)],
                            );

                        self.common.peer_info.peer_cert_chain.cert_chain.data_size =
                            offset + certificate.portion_length;

                        if self
                            .common
                            .runtime_info
                            .message_b
                            .append_message(&receive_buffer[..used])
                            .is_none()
                        {
                            return spdm_result_err!(ENOMEM);
                        }

                        Ok((certificate.portion_length, certificate.remainder_length))
                    } else {
                        error!("!!! certificate : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                _ => spdm_result_err!(EINVAL),
            },
            None => spdm_result_err!(EIO),
        }
    }

    pub fn send_receive_spdm_certificate(&mut self, slot_id: u8) -> SpdmResult {
        let mut offset = 0u16;
        let mut length = config::MAX_SPDM_CERT_PORTION_LEN as u16;
        while length != 0 {
            let result = self.send_receive_spdm_certificate_partial(slot_id, offset, length);
            match result {
                Ok((portion_length, remainder_length)) => {
                    offset += portion_length;
                    length = remainder_length;
                    if length > config::MAX_SPDM_CERT_PORTION_LEN as u16 {
                        length = config::MAX_SPDM_CERT_PORTION_LEN as u16;
                    }
                }
                Err(_) => return spdm_result_err!(EIO),
            }
        }

        // verify
        if let Some(peer_cert_chain_data) = self.common.provision_info.peer_cert_chain_data {
            //
            // TBD: Verify cert chain
            //
            if self.common.peer_info.peer_cert_chain.cert_chain.data_size <= (4 + self.common.negotiate_info.base_hash_sel.get_size()) {
                return spdm_result_err!(EIO);
            }

            let data_size = self.common.peer_info.peer_cert_chain.cert_chain.data_size
                - 4
                - self.common.negotiate_info.base_hash_sel.get_size();
            let mut data = [0u8; config::MAX_SPDM_CERT_CHAIN_DATA_SIZE];
            data[0..(data_size as usize)].copy_from_slice(
                &self.common.peer_info.peer_cert_chain.cert_chain.data[(4usize
                    + self.common.negotiate_info.base_hash_sel.get_size() as usize)
                    ..(self.common.peer_info.peer_cert_chain.cert_chain.data_size as usize)],
            );
            let runtime_peer_cert_chain_data = SpdmCertChainData { data_size, data };

            let (root_cert_begin, root_cert_end) =
                crypto::cert_operation::get_cert_from_cert_chain(
                    &runtime_peer_cert_chain_data.data
                        [..(runtime_peer_cert_chain_data.data_size as usize)],
                    0,
                )?;
            let root_cert = &runtime_peer_cert_chain_data.data[root_cert_begin..root_cert_end];
            let root_hash =
                crypto::hash::hash_all(self.common.negotiate_info.base_hash_sel, root_cert)
                    .unwrap();
            if root_hash.data[..(root_hash.data_size as usize)]
                != self.common.peer_info.peer_cert_chain.cert_chain.data[4usize
                    ..(4usize + self.common.negotiate_info.base_hash_sel.get_size() as usize)]
            {
                error!("root_hash - fail!\n");
                return spdm_result_err!(EINVAL);
            }

            if runtime_peer_cert_chain_data.data_size != peer_cert_chain_data.data_size {
                error!("cert_chain size - fail!\n");
                debug!(
                    "provision cert_chain data size - {:?}\n",
                    peer_cert_chain_data.data_size
                );
                debug!(
                    "runtime cert_chain data size - {:?}\n",
                    runtime_peer_cert_chain_data.data_size
                );
                return spdm_result_err!(EINVAL);
            }
            if runtime_peer_cert_chain_data.data != peer_cert_chain_data.data {
                error!("cert_chain data - fail!\n");
                return spdm_result_err!(EINVAL);
            }

            if crypto::cert_operation::verify_cert_chain(
                &runtime_peer_cert_chain_data.data
                    [..(runtime_peer_cert_chain_data.data_size as usize)],
            )
            .is_err()
            {
                error!("cert_chain verification - fail! - TBD later\n");
                return spdm_result_err!(EFAULT);
            }
            info!("cert_chain verification - pass!\n");
        }

        Ok(())
    }
}
