// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub mod key_schedule;
pub mod opaque;
pub mod session;
pub mod spdm_codec;

use crate::{crypto, protocol::*};

pub use opaque::*;
pub use spdm_codec::SpdmCodec;

use crate::config::{self, MAX_SPDM_SESSION_COUNT};
use crate::error::{
    SpdmResult, SPDM_STATUS_DECAP_FAIL, SPDM_STATUS_INVALID_PARAMETER,
    SPDM_STATUS_SESSION_NUMBER_EXCEED,
};
#[cfg(not(feature = "hashed-transcript-data"))]
use crate::error::{
    SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_CRYPTO_ERROR, SPDM_STATUS_INVALID_STATE_LOCAL,
};

use codec::enum_builder;
use codec::{Codec, Reader, Writer};
use session::*;

enum_builder! {
    @U8
    EnumName: SpdmConnectionState;
    EnumVal{
        // Before GET_VERSION/VERSION
        SpdmConnectionNotStarted => 0x0,
        // After GET_VERSION/VERSION
        SpdmConnectionAfterVersion => 0x1,
        // After GET_CAPABILITIES/CAPABILITIES
        SpdmConnectionAfterCapabilities => 0x2,
        // After NEGOTIATE_ALGORITHMS/ALGORITHMS
        SpdmConnectionNegotiated => 0x3,
        // After GET_DIGESTS/DIGESTS
        SpdmConnectionAfterDigest => 0x4,
        // After GET_CERTIFICATE/CERTIFICATE
        SpdmConnectionAfterCertificate => 0x5,
        // After CHALLENGE/CHALLENGE_AUTH,
        // and ENCAP CHALLENGE/CHALLENGE_AUTH if MUT_AUTH is enabled.
        SpdmConnectionAuthenticated => 0x5
    }
}

#[cfg(feature = "hashed-transcript-data")]
pub use crate::crypto::HashCtx;

#[cfg(feature = "downcast")]
use core::any::Any;

/// The maximum amount of time the Responder has to provide a
/// response to requests that do not require cryptographic processing, such
/// as the GET_CAPABILITIES , GET_VERSION , or NEGOTIATE_ALGORITHMS
/// request messages. See SPDM spec. 1.1.0  Page 29 for more information:
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf
pub const ST1: usize = 1_000_000;

/// used as parameter to be slot_id when use_psk is true
pub const INVALID_SLOT: u8 = 0xFF;

/// used to as the first next_half_session_id
pub const INITIAL_SESSION_ID: u16 = 0xFFFD;
pub const INVALID_HALF_SESSION_ID: u16 = 0x0;
pub const INVALID_SESSION_ID: u32 = 0x0;

pub trait SpdmDeviceIo {
    fn send(&mut self, buffer: &[u8]) -> SpdmResult;

    fn receive(&mut self, buffer: &mut [u8], timeout: usize) -> Result<usize, usize>;

    fn flush_all(&mut self) -> SpdmResult;

    #[cfg(feature = "downcast")]
    fn as_any(&mut self) -> &mut dyn Any;
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

    fn encap_app(
        &mut self,
        spdm_buffer: &[u8],
        app_buffer: &mut [u8],
        is_app_message: bool,
    ) -> SpdmResult<usize>;

    fn decap_app(&mut self, app_buffer: &[u8], spdm_buffer: &mut [u8])
        -> SpdmResult<(usize, bool)>;

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
            session: gen_array(config::MAX_SPDM_SESSION_COUNT),
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

    pub fn reset_negotiate_info(&mut self) {
        self.negotiate_info = SpdmNegotiateInfo::default();
    }

    pub fn reset_peer_info(&mut self) {
        self.peer_info = SpdmPeerInfo::default();
    }

    pub fn reset_context(&mut self) {
        self.reset_runtime_info();
        self.reset_negotiate_info();
        self.reset_peer_info();

        for s in &mut self.session {
            s.set_default();
        }
    }

    pub fn get_immutable_session_via_id(&self, session_id: u32) -> Option<&SpdmSession> {
        self.session
            .iter()
            .find(|&session| session.get_session_id() == session_id)
    }

    pub fn get_session_via_id(&mut self, session_id: u32) -> Option<&mut SpdmSession> {
        self.session
            .iter_mut()
            .find(|session| session.get_session_id() == session_id)
    }

    pub fn get_next_avaiable_session(&mut self) -> Option<&mut SpdmSession> {
        self.get_session_via_id(0)
    }

    pub fn get_session_status(&self) -> [(u32, SpdmSessionState); config::MAX_SPDM_SESSION_COUNT] {
        let mut status =
            [(0u32, SpdmSessionState::SpdmSessionNotStarted); config::MAX_SPDM_SESSION_COUNT];
        for (i, it) in status
            .iter_mut()
            .enumerate()
            .take(config::MAX_SPDM_SESSION_COUNT)
        {
            it.0 = self.session[i].get_session_id();
            it.1 = self.session[i].get_session_state();
        }
        status
    }

    pub fn get_next_half_session_id(&self, is_requester: bool) -> SpdmResult<u16> {
        let shift = if is_requester { 0 } else { 16 };

        for (index, s) in self.session.iter().enumerate().take(MAX_SPDM_SESSION_COUNT) {
            if ((s.get_session_id() & (0xFFFF << shift)) >> shift) as u16 == INVALID_HALF_SESSION_ID
            {
                return Ok(INITIAL_SESSION_ID - index as u16);
            }
        }

        Err(SPDM_STATUS_SESSION_NUMBER_EXCEED)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_req_transcript_data(
        &self,
        slot_id: u8,
        use_psk: bool,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<ManagedBufferTH> {
        let mut message = ManagedBufferTH::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_a - {:02x?}", self.runtime_info.message_a.as_ref());

        if !use_psk {
            if self.peer_info.peer_cert_chain[slot_id as usize].is_none() {
                error!("peer_cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_PARAMETER);
            }

            let cert_chain_data = &self.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data[..(self.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_PARAMETER)?
                .data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_k - {:02x?}", message_k.as_ref());
        if let Some(message_f) = message_f {
            message
                .append_message(message_f.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("message_f - {:02x?}", message_f.as_ref());
        }

        Ok(message)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_rsp_transcript_data(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<ManagedBufferTH> {
        let mut message = ManagedBufferTH::default();
        message
            .append_message(self.runtime_info.message_a.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_a - {:02x?}", self.runtime_info.message_a.as_ref());
        if !use_psk {
            if self.provision_info.my_cert_chain[slot_id as usize].is_none() {
                error!("my_cert_chain is not populated!\n");
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }

            let my_cert_chain_data = self.provision_info.my_cert_chain[slot_id as usize]
                .as_ref()
                .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;
            let cert_chain_data = my_cert_chain_data.as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;

            message
                .append_message(cert_chain_hash.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("cert_chain_data - {:02x?}", cert_chain_data);
        }
        message
            .append_message(message_k.as_ref())
            .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        debug!("message_k - {:02x?}", message_k.as_ref());
        if let Some(message_f) = message_f {
            message
                .append_message(message_f.as_ref())
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
            debug!("message_f - {:02x?}", message_f.as_ref());
        }

        Ok(message)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_req_transcript_hash(
        &self,
        slot_id: u8,
        use_psk: bool,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message = self.calc_req_transcript_data(slot_id, use_psk, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn calc_rsp_transcript_hash(
        &mut self,
        use_psk: bool,
        slot_id: u8,
        message_k: &ManagedBufferK,
        message_f: Option<&ManagedBufferF>,
    ) -> SpdmResult<SpdmDigestStruct> {
        let message = self.calc_rsp_transcript_data(use_psk, slot_id, message_k, message_f)?;

        let transcript_hash =
            crypto::hash::hash_all(self.negotiate_info.base_hash_sel, message.as_ref())
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?;
        Ok(transcript_hash)
    }

    pub fn get_certchain_hash_rsp(
        &self,
        use_psk: bool,
        slot_id: usize,
    ) -> Option<SpdmDigestStruct> {
        if !use_psk {
            if self.provision_info.my_cert_chain[slot_id].is_none() {
                error!("my_cert_chain is not populated!\n");
                return None;
            }

            let my_cert_chain_data = self.provision_info.my_cert_chain[slot_id].as_ref()?;
            let cert_chain_data = my_cert_chain_data.as_ref();
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(None::<SpdmDigestStruct>);
            if let Ok(hash) = cert_chain_hash {
                Some(SpdmDigestStruct::from(hash.as_ref()))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn get_certchain_hash_req(&self, slot_id: u8, use_psk: bool) -> Option<SpdmDigestStruct> {
        if !use_psk {
            if self.peer_info.peer_cert_chain[slot_id as usize].is_none() {
                error!("peer_cert_chain is not populated!\n");
                return None;
            }

            let cert_chain_data = &self.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()?
                .data[..(self.peer_info.peer_cert_chain[slot_id as usize]
                .as_ref()?
                .data_size as usize)];
            let cert_chain_hash =
                crypto::hash::hash_all(self.negotiate_info.base_hash_sel, cert_chain_data)
                    .ok_or(None::<SpdmDigestStruct>);

            if let Ok(hash) = cert_chain_hash {
                Some(SpdmDigestStruct::from(hash.as_ref()))
            } else {
                None
            }
        } else {
            None
        }
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
        is_app_message: bool,
    ) -> SpdmResult<usize> {
        let mut app_buffer = [0u8; config::SENDER_BUFFER_SIZE];
        let used = self
            .transport_encap
            .encap_app(send_buffer, &mut app_buffer, is_app_message)?;

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        let mut encoded_send_buffer = [0u8; config::SENDER_BUFFER_SIZE];
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
            return Err(SPDM_STATUS_DECAP_FAIL); //need check
        }

        Ok(used)
    }

    pub fn decode_secured_message(
        &mut self,
        session_id: u32,
        transport_buffer: &[u8],
        receive_buffer: &mut [u8],
    ) -> SpdmResult<usize> {
        let mut encoded_receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        let (used, secured_message) = self
            .transport_encap
            .decap(transport_buffer, &mut encoded_receive_buffer)?;

        if !secured_message {
            return Err(SPDM_STATUS_DECAP_FAIL);
        }

        let spdm_session = self
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_PARAMETER)?;

        let mut app_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
        let decode_size = spdm_session.decode_spdm_secured_message(
            &encoded_receive_buffer[..used],
            &mut app_buffer,
            false,
        )?;

        let used = self
            .transport_encap
            .decap_app(&app_buffer[0..decode_size], receive_buffer)?;

        Ok(used.0)
    }
}

#[derive(Debug, Default)]
pub struct SpdmConfigInfo {
    pub spdm_version: [SpdmVersion; MAX_SPDM_VERSION_COUNT],
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
    pub opaque_support: SpdmOpaqueSupport,
    pub session_policy: u8,
    pub runtime_content_change_support: bool,
    pub data_transfer_size: u32,
    pub max_spdm_msg_size: u32,
    pub heartbeat_period: u8, // used by responder only
    pub secure_spdm_version: [u8; MAX_SECURE_SPDM_VERSION_COUNT], // used by responder only
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
    pub opaque_data_support: SpdmOpaqueSupport,
    pub termination_policy_set: bool, // used by responder to take action when code or configuration changed.
    pub req_data_transfer_size_sel: u32, // spdm 1.2
    pub req_max_spdm_msg_size_sel: u32, // spdm 1.2
    pub rsp_data_transfer_size_sel: u32, // spdm 1.2
    pub rsp_max_spdm_msg_size_sel: u32, // spdm 1.2
}

const MAX_MANAGED_BUFFER_A_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_B_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_C_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_M_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_K_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_F_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_M1M2_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_L1L2_SIZE: usize = config::MAX_SPDM_MSG_SIZE;
const MAX_MANAGED_BUFFER_TH_SIZE: usize = config::MAX_SPDM_MSG_SIZE;

#[derive(Debug, Clone)]
pub struct ManagedBufferA(usize, [u8; MAX_MANAGED_BUFFER_A_SIZE]);

impl ManagedBufferA {
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

impl AsRef<[u8]> for ManagedBufferA {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferA {
    fn default() -> Self {
        ManagedBufferA(0usize, [0u8; MAX_MANAGED_BUFFER_A_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferB(usize, [u8; MAX_MANAGED_BUFFER_B_SIZE]);

impl ManagedBufferB {
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

impl AsRef<[u8]> for ManagedBufferB {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferB {
    fn default() -> Self {
        ManagedBufferB(0usize, [0u8; MAX_MANAGED_BUFFER_B_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferC(usize, [u8; MAX_MANAGED_BUFFER_C_SIZE]);

impl ManagedBufferC {
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

impl AsRef<[u8]> for ManagedBufferC {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferC {
    fn default() -> Self {
        ManagedBufferC(0usize, [0u8; MAX_MANAGED_BUFFER_C_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferM(usize, [u8; MAX_MANAGED_BUFFER_M_SIZE]);

impl ManagedBufferM {
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

impl AsRef<[u8]> for ManagedBufferM {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferM {
    fn default() -> Self {
        ManagedBufferM(0usize, [0u8; MAX_MANAGED_BUFFER_M_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferK(usize, [u8; MAX_MANAGED_BUFFER_K_SIZE]);

impl ManagedBufferK {
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

impl AsRef<[u8]> for ManagedBufferK {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferK {
    fn default() -> Self {
        ManagedBufferK(0usize, [0u8; MAX_MANAGED_BUFFER_K_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferF(usize, [u8; MAX_MANAGED_BUFFER_F_SIZE]);

impl ManagedBufferF {
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

impl AsRef<[u8]> for ManagedBufferF {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferF {
    fn default() -> Self {
        ManagedBufferF(0usize, [0u8; MAX_MANAGED_BUFFER_F_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferM1M2(usize, [u8; MAX_MANAGED_BUFFER_M1M2_SIZE]);

impl ManagedBufferM1M2 {
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

impl AsRef<[u8]> for ManagedBufferM1M2 {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferM1M2 {
    fn default() -> Self {
        ManagedBufferM1M2(0usize, [0u8; MAX_MANAGED_BUFFER_M1M2_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferL1L2(usize, [u8; MAX_MANAGED_BUFFER_L1L2_SIZE]);

impl ManagedBufferL1L2 {
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

impl AsRef<[u8]> for ManagedBufferL1L2 {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferL1L2 {
    fn default() -> Self {
        ManagedBufferL1L2(0usize, [0u8; MAX_MANAGED_BUFFER_L1L2_SIZE])
    }
}

#[derive(Debug, Clone)]
pub struct ManagedBufferTH(usize, [u8; MAX_MANAGED_BUFFER_TH_SIZE]);

impl ManagedBufferTH {
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

impl AsRef<[u8]> for ManagedBufferTH {
    fn as_ref(&self) -> &[u8] {
        &self.1[0..self.0]
    }
}

impl Default for ManagedBufferTH {
    fn default() -> Self {
        ManagedBufferTH(0usize, [0u8; MAX_MANAGED_BUFFER_TH_SIZE])
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmMeasurementContentChanged: u8 {
        const NOT_SUPPORTED = 0b0000_0000;
        const DETECTED_CHANGE = 0b0001_0000;
        const NO_CHANGE = 0b0010_0000;
    }
}

#[derive(Debug, Clone, Default)]
#[cfg(not(feature = "hashed-transcript-data"))]
pub struct SpdmRuntimeInfo {
    connection_state: SpdmConnectionState,
    pub need_measurement_summary_hash: bool,
    pub need_measurement_signature: bool,
    pub message_a: ManagedBufferA,
    pub message_b: ManagedBufferB,
    pub message_c: ManagedBufferC,
    pub message_m: ManagedBufferM,
    pub content_changed: SpdmMeasurementContentChanged, // used by responder, set when content changed and spdm version is 1.2.
                                                        // used by requester, consume when measurement response report content changed.
}

#[derive(Clone, Default)]
#[cfg(feature = "hashed-transcript-data")]
pub struct SpdmRuntimeInfo {
    connection_state: SpdmConnectionState,
    pub need_measurement_summary_hash: bool,
    pub need_measurement_signature: bool,
    pub message_a: ManagedBufferA,
    pub digest_context_m1m2: Option<HashCtx>, // for M1/M2
    pub digest_context_l1l2: Option<HashCtx>, // for out of session get measurement/measurement
    pub content_changed: SpdmMeasurementContentChanged, // used by responder, set when content changed and spdm version is 1.2.
                                                        // used by requester, consume when measurement response report content changed.
}

impl SpdmRuntimeInfo {
    pub fn set_connection_state(&mut self, connection_state: SpdmConnectionState) {
        self.connection_state = connection_state;
    }

    pub fn get_connection_state(&self) -> SpdmConnectionState {
        self.connection_state
    }
}

#[derive(Default, Clone)]
pub struct SpdmProvisionInfo {
    pub my_cert_chain_data: [Option<SpdmCertChainData>; SPDM_MAX_SLOT_NUMBER],
    pub my_cert_chain: [Option<SpdmCertChainBuffer>; SPDM_MAX_SLOT_NUMBER],
    pub peer_root_cert_data: Option<SpdmCertChainData>,
}

#[derive(Default)]
pub struct SpdmPeerInfo {
    pub peer_cert_chain: [Option<SpdmCertChainBuffer>; SPDM_MAX_SLOT_NUMBER],
    pub peer_cert_chain_temp: Option<SpdmCertChainBuffer>,
}
