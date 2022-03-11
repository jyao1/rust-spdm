// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::common::error::SpdmResult;
use crate::crypto;
use crate::message::*;
use crate::requester::*;

impl<'a> RequesterContext<'a> {
    fn send_receive_spdm_certificate_partial(
        &mut self,
        slot_id: u8,
        offset: u16,
        length: u16,
    ) -> SpdmResult<(u16, u16)> {
        info!("send spdm certificate\n");
        let mut send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let send_used =
            self.encode_spdm_certificate_partial(slot_id, offset, length, &mut send_buffer);
        self.send_message(&send_buffer[..send_used])?;

        let mut receive_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self.receive_message(&mut receive_buffer, false)?;
        self.handle_spdm_certificate_partial_response(
            0,
            offset,
            &send_buffer[..send_used],
            &receive_buffer[..used],
        )
    }

    pub fn encode_spdm_certificate_partial(
        &mut self,
        slot_id: u8,
        offset: u16,
        length: u16,
        buf: &mut [u8],
    ) -> usize {
        let mut writer = Writer::init(buf);
        let request = SpdmMessage {
            header: SpdmMessageHeader {
                version: self.common.negotiate_info.spdm_version_sel,
                request_response_code: SpdmRequestResponseCode::SpdmRequestGetCertificate,
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
        writer.used()
    }

    pub fn handle_spdm_certificate_partial_response(
        &mut self,
        session_id: u32,
        offset: u16,
        send_buffer: &[u8],
        receive_buffer: &[u8],
    ) -> SpdmResult<(u16, u16)> {
        let mut reader = Reader::init(receive_buffer);
        match SpdmMessageHeader::read(&mut reader) {
            Some(message_header) => match message_header.request_response_code {
                SpdmRequestResponseCode::SpdmResponseCertificate => {
                    let certificate =
                        SpdmCertificateResponsePayload::spdm_read(&mut self.common, &mut reader);
                    let used = reader.used();
                    if let Some(certificate) = certificate {
                        debug!("!!! certificate : {:02x?}\n", certificate);
                        if certificate.portion_length as usize > config::MAX_SPDM_CERT_PORTION_LEN
                            || (offset + certificate.portion_length) as usize
                                > config::MAX_SPDM_CERT_CHAIN_DATA_SIZE
                        {
                            return spdm_result_err!(ENOMEM);
                        }
                        self.common.peer_info.peer_cert_chain.cert_chain.data[(offset as usize)
                            ..(offset as usize + certificate.portion_length as usize)]
                            .copy_from_slice(
                                &certificate.cert_chain[0..(certificate.portion_length as usize)],
                            );

                        self.common.peer_info.peer_cert_chain.cert_chain.data_size =
                            offset + certificate.portion_length;

                        let message_b = &mut self.common.runtime_info.message_b;
                        message_b
                            .append_message(send_buffer)
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;
                        message_b
                            .append_message(&receive_buffer[..used])
                            .map_or_else(|| spdm_result_err!(ENOMEM), |_| Ok(()))?;

                        Ok((certificate.portion_length, certificate.remainder_length))
                    } else {
                        error!("!!! certificate : fail !!!\n");
                        spdm_result_err!(EFAULT)
                    }
                }
                SpdmRequestResponseCode::SpdmResponseError => {
                    let erm = self.spdm_handle_error_response_main(
                        session_id,
                        receive_buffer,
                        SpdmRequestResponseCode::SpdmRequestGetCertificate,
                        SpdmRequestResponseCode::SpdmResponseCertificate,
                    );
                    match erm {
                        Ok(rm) => {
                            let receive_buffer = rm.receive_buffer;
                            let used = rm.used;
                            self.handle_spdm_certificate_partial_response(
                                session_id,
                                offset,
                                send_buffer,
                                &receive_buffer[..used],
                            )
                        }
                        _ => spdm_result_err!(EINVAL),
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
        self.verify_spdm_certificate_chain()
    }

    pub fn verify_spdm_certificate_chain(&mut self) -> SpdmResult {
        // verify
        if let Some(peer_cert_chain_data) = &self.common.provision_info.peer_cert_chain_data {
            //
            // TBD: Verify cert chain
            //
            if self.common.peer_info.peer_cert_chain.cert_chain.data_size
                <= (4 + self.common.negotiate_info.base_hash_sel.get_size())
            {
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

#[cfg(test)]
mod tests_requester {
    use super::*;
    use crate::testlib::*;
    use crate::{crypto, responder};

    #[test]
    fn test_case0_send_receive_spdm_certificate() {
        let (rsp_config_info, rsp_provision_info) = create_info();
        let (req_config_info, req_provision_info) = create_info();

        let shared_buffer = SharedBuffer::new();
        let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

        crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

        let mut responder = responder::ResponderContext::new(
            &mut device_io_responder,
            pcidoe_transport_encap,
            rsp_config_info,
            rsp_provision_info,
        );

        responder.common.reset_runtime_info();
        responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        responder.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
        let mut device_io_requester = FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

        let mut requester = RequesterContext::new(
            &mut device_io_requester,
            pcidoe_transport_encap2,
            req_config_info,
            req_provision_info,
        );

        requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        requester.common.negotiate_info.base_asym_sel =
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

        let status = requester.send_receive_spdm_certificate(0).is_ok();
        assert!(status);
    }
}
