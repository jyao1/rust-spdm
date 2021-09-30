// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::config;
use crate::crypto;
use crate::error::SpdmResult;
use crate::msgs::*;
use crate::session::*;
use codec::Writer;

pub const OPAQUE_DATA_SUPPORT_VERSION: [u8; 20] = [
    0x46, 0x54, 0x4d, 0x44, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x01, 0x01, 0x00,
    0x11, 0x00, 0x00, 0x00,
];
pub const OPAQUE_DATA_VERSION_SELECTION: [u8; 16] = [
    0x46, 0x54, 0x4d, 0x44, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x11,
];

pub trait SpdmDeviceIo {
    fn send(&mut self, buffer: &[u8]) -> SpdmResult;

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, usize>;

    fn flush_all(&mut self) -> SpdmResult;
}

use core::fmt::Debug;
impl Debug for dyn SpdmDeviceIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dyn SpdmDeviceIo")
    }
}

pub trait SpdmTransportEncap {
    fn encap(
        &mut self,
        spdm_buffer: &[u8],
        transport_buffer: &mut [u8],
        secured_message: bool,
    ) -> SpdmResult<usize>;

    fn decap(
        &mut self,
        transport_buffer: &[u8],
        spdm_buffer: &mut [u8],
    ) -> SpdmResult<(usize, bool)>;

    fn encap_app(&mut self, spdm_buffer: &[u8], app_buffer: &mut [u8]) -> SpdmResult<usize>;

    fn decap_app(&mut self, app_buffer: &[u8], spdm_buffer: &mut [u8]) -> SpdmResult<usize>;

    // for session
    fn get_sequence_number_count(&mut self) -> u8;
    fn get_max_random_count(&mut self) -> u16;
}

impl Debug for dyn SpdmTransportEncap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dyn SpdmTransportEncap")
    }
}

pub struct SpdmContext<'a> {
    pub device_io: &'a mut dyn SpdmDeviceIo,
    pub transport_encap: &'a mut dyn SpdmTransportEncap,

    pub config_info: SpdmConfigInfo,
    pub negotiate_info: SpdmNegotiateInfo,
    pub runtime_info: SpdmRuntimeInfo,

    pub provision_info: SpdmProvisionInfo,
    pub peer_info: SpdmPeerInfo,

    pub session: [SpdmSession; config::MAX_SPDM_SESSION_COUNT],
}

impl<'a> SpdmContext<'a> {
    pub fn new(
        device_io: &'a mut dyn SpdmDeviceIo,
        transport_encap: &'a mut dyn SpdmTransportEncap,
        config_info: SpdmConfigInfo,
        provision_info: SpdmProvisionInfo,
    ) -> Self {
        SpdmContext {
            device_io,
            transport_encap,
            config_info,
            negotiate_info: SpdmNegotiateInfo::default(),
            runtime_info: SpdmRuntimeInfo::default(),
            provision_info,
            peer_info: SpdmPeerInfo::default(),
            session: [SpdmSession::new(); config::MAX_SPDM_SESSION_COUNT],
        }
    }

    pub fn get_hash_size(&self) -> u16 {
        self.negotiate_info.base_hash_sel.get_size()
    }
    pub fn get_asym_key_size(&self) -> u16 {
        self.negotiate_info.base_asym_sel.get_size()
    }
    pub fn get_dhe_key_size(&self) -> u16 {
        self.negotiate_info.dhe_sel.get_size()
    }

    pub fn reset_runtime_info(&mut self) {
        self.runtime_info = SpdmRuntimeInfo::default();
    }

    pub fn get_immutable_session_via_id(&self, session_id: u32) -> Option<&SpdmSession> {
        for session in self.session.iter() {
            if session.get_session_id() == session_id {
                return Some(session);
            }
        }
        None
    }

    pub fn get_session_via_id(&mut self, session_id: u32) -> Option<&mut SpdmSession> {
        for session in self.session.iter_mut() {
            if session.get_session_id() == session_id {
                return Some(session);
            }
        }
        None
    }

    pub fn get_next_avaiable_session(&mut self) -> Option<&mut SpdmSession> {
        self.get_session_via_id(0)
    }

    pub fn calc_req_transcript_data(
        &self,
        use_psk: bool,
        message_k: &ManagedBuffer,
        message_f: Option<&ManagedBuffer>,
    ) -> SpdmResult<ManagedBuffer> {
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or(spdm_err!(ENOMEM))?;
        debug!("message_a - {:02x?}", self.runtime_info.message_a.as_ref());
        if !use_psk {
            let cert_chain_data = &self.peer_info.peer_cert_chain.cert_chain.data[(4usize
                + self.negotiate_info.base_hash_sel.get_size() as usize)
                ..(self.peer_info.peer_cert_chain.cert_chain.data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or_else(|| spdm_err!(EFAULT))?;
            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        debug!("message_k - {:02x?}", message_k.as_ref());
        if message_f.is_some() {
            message
                .append_message(message_f.unwrap().as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            debug!("message_f - {:02x?}", message_f.unwrap().as_ref());
        }

        Ok(message)
    }

    pub fn calc_rsp_transcript_data(
        &mut self,
        use_psk: bool,
        message_k: &ManagedBuffer,
        message_f: Option<&ManagedBuffer>,
    ) -> SpdmResult<ManagedBuffer> {
        if !use_psk && self.provision_info.my_cert_chain_data.is_none() {
            return spdm_result_err!(EINVAL);
        }
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or(spdm_err!(ENOMEM))?;
        debug!("message_a - {:02x?}", self.runtime_info.message_a.as_ref());
        if !use_psk {
            let my_cert_chain_data = self.provision_info.my_cert_chain_data.unwrap();
            let cert_chain_data = my_cert_chain_data.as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or_else(|| spdm_err!(EFAULT))?;

            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        debug!("message_k - {:02x?}", message_k.as_ref());
        if message_f.is_some() {
            message
                .append_message(message_f.unwrap().as_ref())
                .ok_or_else(|| spdm_err!(ENOMEM))?;
            debug!("message_f - {:02x?}", message_f.unwrap().as_ref());
        }

        Ok(message)
    }

    pub fn calc_req_transcript_hash(
        &self,
        use_psk: bool,
        message_k: &ManagedBuffer,
        message_f: Option<&ManagedBuffer>,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message = self.calc_req_transcript_data(use_psk, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        Ok(transcript_hash)
    }

    pub fn calc_rsp_transcript_hash(
        &mut self,
        use_psk: bool,
        message_k: &ManagedBuffer,
        message_f: Option<&ManagedBuffer>,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message = self.calc_rsp_transcript_data(use_psk, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        Ok(transcript_hash)
    }

    pub fn verify_challenge_auth_signature(
        &mut self,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        message
            .append_message(self.runtime_info.message_b.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        message
            .append_message(self.runtime_info.message_c.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        let cert_chain_data = &self.peer_info.peer_cert_chain.cert_chain.data[(4usize
            + self.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.peer_info.peer_cert_chain.cert_chain.data_size as usize)];

        crypto::asym_verify::verify(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            cert_chain_data,
            message.as_ref(),
            signature,
        )
    }

    pub fn generate_challenge_auth_signature(&mut self) -> SpdmResult<SpdmSignatureStruct> {
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        message
            .append_message(self.runtime_info.message_b.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        message
            .append_message(self.runtime_info.message_c.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        crypto::asym_sign::sign(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or_else(|| spdm_err!(EFAULT))
    }

    pub fn verify_measurement_signature(&mut self, signature: &SpdmSignatureStruct) -> SpdmResult {
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_m.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        let cert_chain_data = &self.peer_info.peer_cert_chain.cert_chain.data[(4usize
            + self.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.peer_info.peer_cert_chain.cert_chain.data_size as usize)];

        crypto::asym_verify::verify(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            cert_chain_data,
            message.as_ref(),
            signature,
        )
    }

    pub fn generate_measurement_signature(&mut self) -> SpdmResult<SpdmSignatureStruct> {
        let mut message = ManagedBuffer::default();
        message
            .append_message(self.runtime_info.message_m.as_ref())
            .ok_or_else(|| spdm_err!(ENOMEM))?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        crypto::asym_sign::sign(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or_else(|| spdm_err!(EFAULT))
    }

    pub fn verify_key_exchange_rsp_signature(
        &mut self,
        message_k: &ManagedBuffer,
        signature: &SpdmSignatureStruct,
    ) -> SpdmResult {
        let message = self.calc_req_transcript_data(false, message_k, None)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        let cert_chain_data = &self.peer_info.peer_cert_chain.cert_chain.data[(4usize
            + self.negotiate_info.base_hash_sel.get_size() as usize)
            ..(self.peer_info.peer_cert_chain.cert_chain.data_size as usize)];

        crypto::asym_verify::verify(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            cert_chain_data,
            message.as_ref(),
            signature,
        )
    }

    pub fn generate_key_exchange_rsp_signature(
        &mut self,
        message_k: &ManagedBuffer,
    ) -> SpdmResult<SpdmSignatureStruct> {
        let message = self.calc_rsp_transcript_data(false, message_k, None)?;
        // we dont need create message hash for verify
        // we just print message hash for debug purpose
        let message_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or_else(|| spdm_err!(EFAULT))?;
        debug!("message_hash - {:02x?}", message_hash.as_ref());

        crypto::asym_sign::sign(
            self.negotiate_info.base_hash_sel,
            self.negotiate_info.base_asym_sel,
            message.as_ref(),
        )
        .ok_or_else(|| spdm_err!(EFAULT))
    }

    pub fn encap(&mut self, send_buffer: &[u8], transport_buffer: &mut [u8]) -> SpdmResult<usize> {
        self.transport_encap
            .encap(send_buffer, transport_buffer, false)
    }

    pub fn encode_secured_message(
        &mut self,
        session_id: u32,
        send_buffer: &[u8],
        transport_buffer: &mut [u8],
        is_requester: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let used = self
            .transport_encap
            .encap_app(send_buffer, &mut app_buffer)?;

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

        let mut encoded_send_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let encode_size = spdm_session.encode_spdm_secured_message(
            &app_buffer[0..used],
            &mut encoded_send_buffer,
            is_requester,
        )?;

        self.transport_encap
            .encap(&encoded_send_buffer[..encode_size], transport_buffer, true)
    }

    pub fn decap(
        &mut self,
        transport_buffer: &[u8],
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let (used, secured_message) = self
            .transport_encap
            .decap(transport_buffer, receive_buffer)?;

        if secured_message {
            return spdm_result_err!(EFAULT);
        }

        Ok(used)
    }

    pub fn decode_secured_message(
        &mut self,
        session_id: u32,
        transport_buffer: &[u8],
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut encoded_receive_buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
        let (used, secured_message) = self
            .transport_encap
            .decap(transport_buffer, &mut encoded_receive_buffer)?;

        if !secured_message {
            return spdm_result_err!(EFAULT);
        }

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(spdm_err!(EINVAL))?;

        let mut app_buffer = [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE];
        let decode_size = spdm_session.decode_spdm_secured_message(
            &encoded_receive_buffer[..used],
            &mut app_buffer,
            false,
        )?;

        let used = self
            .transport_encap
            .decap_app(&app_buffer[0..decode_size], receive_buffer)?;

        Ok(used)
    }
}

#[derive(Debug, Default)]
pub struct SpdmConfigInfo {
    pub spdm_version: [SpdmVersion; config::MAX_SPDM_VERSION_COUNT],
    pub req_capabilities: SpdmRequestCapabilityFlags,
    pub rsp_capabilities: SpdmResponseCapabilityFlags,
    pub req_ct_exponent: u8,
    pub rsp_ct_exponent: u8,
    pub measurement_specification: SpdmMeasurementSpecification,
    pub measurement_hash_algo: SpdmMeasurementHashAlgo,
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub base_asym_algo: SpdmBaseAsymAlgo,
    pub dhe_algo: SpdmDheAlgo,
    pub aead_algo: SpdmAeadAlgo,
    pub req_asym_algo: SpdmReqAsymAlgo,
    pub key_schedule_algo: SpdmKeyScheduleAlgo,
}

#[derive(Debug, Default)]
pub struct SpdmNegotiateInfo {
    pub spdm_version_sel: SpdmVersion,
    pub req_capabilities_sel: SpdmRequestCapabilityFlags,
    pub rsp_capabilities_sel: SpdmResponseCapabilityFlags,
    pub req_ct_exponent_sel: u8,
    pub rsp_ct_exponent_sel: u8,
    pub measurement_specification_sel: SpdmMeasurementSpecification,
    pub measurement_hash_sel: SpdmMeasurementHashAlgo,
    pub base_hash_sel: SpdmBaseHashAlgo,
    pub base_asym_sel: SpdmBaseAsymAlgo,
    pub dhe_sel: SpdmDheAlgo,
    pub aead_sel: SpdmAeadAlgo,
    pub req_asym_sel: SpdmReqAsymAlgo,
    pub key_schedule_sel: SpdmKeyScheduleAlgo,
}

// TBD ManagedSmallBuffer
#[derive(Debug, Copy, Clone)]
pub struct ManagedBuffer(usize, [u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE]);

impl ManagedBuffer {
    pub fn append_message(&mut self, bytes: &[u8]) -> Option<usize> {
        let used = self.0;
        let mut writer = Writer::init(&mut self.1[used..]);
        let write_len = writer.extend_from_slice(bytes)?;
        self.0 = used + write_len;
        Some(writer.used())
    }
    pub fn reset_message(&mut self) {
        self.0 = 0;
    }
}

impl AsRef<[u8]> for ManagedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..(self.0 as usize)]
    }
}

impl Default for ManagedBuffer {
    fn default() -> Self {
        ManagedBuffer(0usize, [0u8; config::MAX_SPDM_MESSAGE_BUFFER_SIZE])
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SpdmRuntimeInfo {
    pub need_measurement_summary_hash: bool,
    pub need_measurement_signature: bool,
    pub message_a: ManagedBuffer,
    pub message_b: ManagedBuffer,
    pub message_c: ManagedBuffer,
    pub message_m: ManagedBuffer,
}

#[derive(Default)]
pub struct SpdmProvisionInfo {
    pub my_cert_chain_data: Option<SpdmCertChainData>,
    pub my_cert_chain: Option<SpdmCertChainData>, // use SpdmCertChainData instead of SpdmCertChain for easy command sending.
    // TBD: union peer. But it is still option.
    pub peer_cert_chain_data: Option<SpdmCertChainData>,
    pub peer_cert_chain_root_hash: Option<SpdmDigestStruct>,
}

#[derive(Default)]
pub struct SpdmPeerInfo {
    pub peer_cert_chain: SpdmCertChain,
}
