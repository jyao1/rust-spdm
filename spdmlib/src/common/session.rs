// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::key_schedule::SpdmKeySchedule;
use crate::config;
use crate::crypto;
use crate::error::SpdmResult;
use crate::error::SPDM_STATUS_BUFFER_TOO_SMALL;
use crate::error::SPDM_STATUS_CRYPTO_ERROR;
use crate::error::SPDM_STATUS_DECODE_AEAD_FAIL;
use crate::error::SPDM_STATUS_INVALID_STATE_LOCAL;

use zeroize::{Zeroize, ZeroizeOnDrop};

use codec::enum_builder;
use codec::{Codec, Reader, Writer};

use super::*;

enum_builder! {
    @U8
    EnumName: SpdmSessionState;
    EnumVal{
        // Before send KEY_EXCHANGE/PSK_EXCHANGE
        // or after END_SESSION
        SpdmSessionNotStarted => 0x0,
        // After send KEY_EXHCNAGE, before send FINISH
        SpdmSessionHandshaking => 0x1,
        // After send FINISH, before END_SESSION
        SpdmSessionEstablished => 0x2
    }
}
impl Default for SpdmSessionState {
    fn default() -> SpdmSessionState {
        SpdmSessionState::SpdmSessionNotStarted
    }
}

#[derive(Debug, Clone, Default)]
pub struct SpdmSessionCryptoParam {
    pub base_hash_algo: SpdmBaseHashAlgo,
    pub dhe_algo: SpdmDheAlgo,
    pub aead_algo: SpdmAeadAlgo,
    pub key_schedule_algo: SpdmKeyScheduleAlgo,
}

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SpdmSessionMasterSecret {
    pub dhe_secret: SpdmDheFinalKeyStruct,
    pub handshake_secret: SpdmDigestStruct,
    pub master_secret: SpdmDigestStruct,
}

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SpdmSessionSecretParam {
    pub encryption_key: SpdmAeadKeyStruct,
    pub salt: SpdmAeadIvStruct,
    pub sequence_number: u64,
}

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SpdmSessionHandshakeSecret {
    pub request_handshake_secret: SpdmDigestStruct,
    pub response_handshake_secret: SpdmDigestStruct,
    pub export_master_secret: SpdmDigestStruct,
    pub request_finished_key: SpdmDigestStruct,
    pub response_finished_key: SpdmDigestStruct,
    pub request_direction: SpdmSessionSecretParam,
    pub response_direction: SpdmSessionSecretParam,
}

#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SpdmSessionAppliationSecret {
    pub request_data_secret: SpdmDigestStruct,
    pub response_data_secret: SpdmDigestStruct,
    pub request_direction: SpdmSessionSecretParam,
    pub response_direction: SpdmSessionSecretParam,
}

#[derive(Debug, Clone, Default)]
pub struct SpdmSessionTransportParam {
    pub sequence_number_count: u8,
    pub max_random_count: u16,
}

#[derive(Debug, Clone, Default)]
#[cfg(not(feature = "hashed-transcript-data"))]
pub struct SpdmSessionRuntimeInfo {
    pub message_k: ManagedBufferK,
    pub message_f: ManagedBufferF,
    pub message_m: ManagedBufferM,
}

#[derive(Clone, Default)]
#[cfg(feature = "hashed-transcript-data")]
pub struct SpdmSessionRuntimeInfo {
    pub digest_context_th: Option<SpdmHashCtx>,
    pub digest_context_l1l2: Option<SpdmHashCtx>,
}

#[derive(Clone)]
pub struct SpdmSession {
    session_id: u32,
    use_psk: bool,
    session_state: SpdmSessionState,
    crypto_param: SpdmSessionCryptoParam,
    master_secret: SpdmSessionMasterSecret,
    handshake_secret: SpdmSessionHandshakeSecret,
    application_secret: SpdmSessionAppliationSecret,
    application_secret_backup: SpdmSessionAppliationSecret,
    transport_param: SpdmSessionTransportParam,
    pub runtime_info: SpdmSessionRuntimeInfo,
    key_schedule: SpdmKeySchedule,
    slot_id: u8,
    pub heartbeat_period: u8, // valid only when HEARTBEAT cap set
    pub secure_spdm_version_sel: u8,
}

impl Default for SpdmSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SpdmSession {
    pub fn new() -> Self {
        SpdmSession {
            session_id: INVALID_SESSION_ID,
            use_psk: false,
            session_state: SpdmSessionState::default(),
            crypto_param: SpdmSessionCryptoParam::default(),
            master_secret: SpdmSessionMasterSecret::default(),
            handshake_secret: SpdmSessionHandshakeSecret::default(),
            application_secret: SpdmSessionAppliationSecret::default(),
            application_secret_backup: SpdmSessionAppliationSecret::default(),
            transport_param: SpdmSessionTransportParam::default(),
            runtime_info: SpdmSessionRuntimeInfo::default(),
            key_schedule: SpdmKeySchedule::new(),
            slot_id: 0,
            heartbeat_period: 0,
            secure_spdm_version_sel: DMTF_SECURE_SPDM_VERSION_11,
        }
    }

    pub fn set_request_direction_sequence_number(&mut self, seq: u64) {
        self.application_secret.request_direction.sequence_number = seq;
    }

    pub fn get_request_direction_sequence_number(&self) -> u64 {
        self.application_secret.request_direction.sequence_number
    }

    pub fn set_response_direction_sequence_number(&mut self, seq: u64) {
        self.application_secret.response_direction.sequence_number = seq;
    }

    pub fn get_response_direction_sequence_number(&self) -> u64 {
        self.application_secret.response_direction.sequence_number
    }

    pub fn set_default(&mut self) {
        self.session_id = INVALID_SESSION_ID;
        self.use_psk = false;
        self.session_state = SpdmSessionState::default();
        self.crypto_param = SpdmSessionCryptoParam::default();
        self.master_secret = SpdmSessionMasterSecret::default();
        self.handshake_secret = SpdmSessionHandshakeSecret::default();
        self.application_secret = SpdmSessionAppliationSecret::default();
        self.application_secret_backup = SpdmSessionAppliationSecret::default();
        self.transport_param = SpdmSessionTransportParam::default();
        self.runtime_info = SpdmSessionRuntimeInfo::default();
        self.key_schedule = SpdmKeySchedule::default();
        self.heartbeat_period = 0;
        self.secure_spdm_version_sel = DMTF_SECURE_SPDM_VERSION_11;
    }

    pub fn get_session_id(&self) -> u32 {
        self.session_id
    }

    pub fn setup(&mut self, session_id: u32) -> SpdmResult {
        if self.session_id == INVALID_SESSION_ID {
            self.set_default();
            self.session_id = session_id;
            Ok(())
        } else {
            panic!("setup session occupied!");
        }
    }

    pub fn teardown(&mut self, session_id: u32) -> SpdmResult {
        if self.session_id == session_id {
            self.set_default();
            Ok(())
        } else {
            panic!("teardown session owned by other!");
        }
    }

    pub fn set_use_psk(&mut self, use_psk: bool) {
        self.use_psk = use_psk;
    }

    pub fn get_use_psk(&self) -> bool {
        self.use_psk
    }

    pub fn set_slot_id(&mut self, slot_id: u8) {
        self.slot_id = slot_id;
    }

    pub fn get_slot_id(&self) -> u8 {
        self.slot_id
    }

    pub fn set_dhe_secret(
        &mut self,
        spdm_version: SpdmVersion,
        dhe_secret: SpdmDheFinalKeyStruct,
    ) -> SpdmResult {
        self.master_secret.dhe_secret = dhe_secret; // take the ownership here!
        let key = &self.master_secret.dhe_secret.as_ref();

        // generate master_secret.handshake_secret and master_secret.master_secret
        let handshake_secret = if let Some(hs) = self.key_schedule.derive_handshake_secret(
            spdm_version,
            self.crypto_param.base_hash_algo,
            key,
        ) {
            hs
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };

        let key = handshake_secret.as_ref();
        let master_secret = if let Some(ms) = self.key_schedule.derive_master_secret(
            spdm_version,
            self.crypto_param.base_hash_algo,
            key,
        ) {
            ms
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };

        self.master_secret.handshake_secret = handshake_secret;
        self.master_secret.master_secret = master_secret;

        debug!(
            "!!! handshake_secret !!!: {:02x?}\n",
            self.master_secret.handshake_secret.as_ref()
        );
        debug!(
            "!!! master_secret !!!: {:02x?}\n",
            self.master_secret.master_secret.as_ref()
        );

        Ok(())
    }

    pub fn set_crypto_param(
        &mut self,
        base_hash_algo: SpdmBaseHashAlgo,
        dhe_algo: SpdmDheAlgo,
        aead_algo: SpdmAeadAlgo,
        key_schedule_algo: SpdmKeyScheduleAlgo,
    ) {
        self.crypto_param.base_hash_algo = base_hash_algo;
        self.crypto_param.dhe_algo = dhe_algo;
        self.crypto_param.aead_algo = aead_algo;
        self.crypto_param.key_schedule_algo = key_schedule_algo;
    }

    pub fn set_transport_param(&mut self, sequence_number_count: u8, max_random_count: u16) {
        self.transport_param.sequence_number_count = sequence_number_count;
        self.transport_param.max_random_count = max_random_count;
    }

    pub fn set_session_state(&mut self, session_state: SpdmSessionState) {
        self.session_state = session_state;
    }

    pub fn get_session_state(&self) -> SpdmSessionState {
        self.session_state
    }

    pub fn init_message_k(
        &mut self,
        #[cfg(not(feature = "hashed-transcript-data"))] message_k: &ManagedBufferK,
        #[cfg(feature = "hashed-transcript-data")] digest_context_th: &SpdmHashCtx,
    ) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.runtime_info.message_k = message_k.clone();
        }
        #[cfg(feature = "hashed-transcript-data")]
        {
            self.runtime_info.digest_context_th = Some(digest_context_th.clone());
        }
        Ok(())
    }
    pub fn append_message_k(&mut self, new_message: &[u8]) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.runtime_info
                .message_k
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            if self.runtime_info.digest_context_th.is_none() {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }

            crypto::hash::hash_ctx_update(
                self.runtime_info.digest_context_th.as_mut().unwrap(),
                new_message,
            )?;
        }

        Ok(())
    }
    pub fn reset_message_k(&mut self) {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.runtime_info.message_f.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            self.runtime_info.digest_context_th = None;
        }
    }

    pub fn append_message_f(&mut self, new_message: &[u8]) -> SpdmResult {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.runtime_info
                .message_f
                .append_message(new_message)
                .ok_or(SPDM_STATUS_BUFFER_FULL)?;
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            if self.runtime_info.digest_context_th.is_none() {
                return Err(SPDM_STATUS_INVALID_STATE_LOCAL);
            }

            crypto::hash::hash_ctx_update(
                self.runtime_info.digest_context_th.as_mut().unwrap(),
                new_message,
            )?;
        }

        Ok(())
    }
    pub fn reset_message_f(&mut self) {
        #[cfg(not(feature = "hashed-transcript-data"))]
        {
            self.runtime_info.message_f.reset_message();
        }

        #[cfg(feature = "hashed-transcript-data")]
        {
            self.runtime_info.digest_context_th = None;
        }
    }

    pub fn generate_handshake_secret(
        &mut self,
        spdm_version: SpdmVersion,
        th1: &SpdmDigestStruct,
    ) -> SpdmResult {
        // generate key
        info!("!!! generate_handshake_secret !!!:\n");
        let hash_algo = self.crypto_param.base_hash_algo;
        let aead_algo = self.crypto_param.aead_algo;

        self.handshake_secret.request_handshake_secret = if let Some(rhs) =
            self.key_schedule.derive_request_handshake_secret(
                spdm_version,
                hash_algo,
                self.master_secret.handshake_secret.as_ref(),
                th1.as_ref(),
            ) {
            rhs
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        debug!(
            "!!! request_handshake_secret !!!: {:02x?}\n",
            self.handshake_secret.request_handshake_secret.as_ref()
        );
        self.handshake_secret.response_handshake_secret = if let Some(rhs) =
            self.key_schedule.derive_response_handshake_secret(
                spdm_version,
                hash_algo,
                self.master_secret.handshake_secret.as_ref(),
                th1.as_ref(),
            ) {
            rhs
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        debug!(
            "!!! response_handshake_secret !!!: {:02x?}\n",
            self.handshake_secret.response_handshake_secret.as_ref()
        );
        self.handshake_secret.request_finished_key = if let Some(rfk) =
            self.key_schedule.derive_finished_key(
                spdm_version,
                hash_algo,
                self.handshake_secret.request_handshake_secret.as_ref(),
            ) {
            rfk
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        debug!(
            "!!! request_finished_key !!!: {:02x?}\n",
            self.handshake_secret.request_finished_key.as_ref()
        );
        self.handshake_secret.response_finished_key = if let Some(rfk) =
            self.key_schedule.derive_finished_key(
                spdm_version,
                hash_algo,
                self.handshake_secret.response_handshake_secret.as_ref(),
            ) {
            rfk
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        debug!(
            "!!! response_finished_key !!!: {:02x?}\n",
            self.handshake_secret.response_finished_key.as_ref()
        );

        let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
            spdm_version,
            hash_algo,
            aead_algo,
            self.handshake_secret.request_handshake_secret.as_ref(),
        ) {
            aki
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };

        self.handshake_secret.request_direction.encryption_key = res.0;
        self.handshake_secret.request_direction.salt = res.1;
        debug!(
            "!!! request_direction.encryption_key !!!: {:02x?}\n",
            self.handshake_secret
                .request_direction
                .encryption_key
                .as_ref()
        );
        debug!(
            "!!! request_direction.salt !!!: {:02x?}\n",
            self.handshake_secret.request_direction.salt.as_ref()
        );

        let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
            spdm_version,
            hash_algo,
            aead_algo,
            self.handshake_secret.response_handshake_secret.as_ref(),
        ) {
            aki
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        self.handshake_secret.response_direction.encryption_key = res.0;
        self.handshake_secret.response_direction.salt = res.1;
        debug!(
            "!!! response_direction.encryption_key !!!: {:02x?}\n",
            self.handshake_secret
                .response_direction
                .encryption_key
                .as_ref()
        );
        debug!(
            "!!! response_direction.salt !!!: {:02x?}\n",
            self.handshake_secret.response_direction.salt.as_ref()
        );

        self.handshake_secret.export_master_secret = if let Some(ems) =
            self.key_schedule.derive_export_master_secret(
                spdm_version,
                hash_algo,
                self.master_secret.master_secret.as_ref(),
            ) {
            ems
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };

        Ok(())
    }

    pub fn generate_data_secret(
        &mut self,
        spdm_version: SpdmVersion,
        th2: &SpdmDigestStruct,
    ) -> SpdmResult {
        // generate key
        info!("!!! generate_data_secret !!!:\n");
        let hash_algo = self.crypto_param.base_hash_algo;
        let aead_algo = self.crypto_param.aead_algo;

        self.application_secret.request_data_secret = if let Some(rds) =
            self.key_schedule.derive_request_data_secret(
                spdm_version,
                hash_algo,
                self.master_secret.master_secret.as_ref(),
                th2.as_ref(),
            ) {
            rds
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        self.application_secret.response_data_secret = if let Some(rds) =
            self.key_schedule.derive_response_data_secret(
                spdm_version,
                hash_algo,
                self.master_secret.master_secret.as_ref(),
                th2.as_ref(),
            ) {
            rds
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        debug!(
            "!!! request_data_secret !!!: {:02x?}\n",
            self.application_secret.request_data_secret.as_ref()
        );
        debug!(
            "!!! response_data_secret !!!: {:02x?}\n",
            self.application_secret.response_data_secret.as_ref()
        );

        let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
            spdm_version,
            hash_algo,
            aead_algo,
            self.application_secret.request_data_secret.as_ref(),
        ) {
            aki
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        self.application_secret.request_direction.encryption_key = res.0;
        self.application_secret.request_direction.salt = res.1;
        debug!(
            "!!! request_direction.encryption_key !!!: {:02x?}\n",
            self.application_secret
                .request_direction
                .encryption_key
                .as_ref()
        );
        debug!(
            "!!! request_direction.salt !!!: {:02x?}\n",
            self.application_secret.request_direction.salt.as_ref()
        );

        let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
            spdm_version,
            hash_algo,
            aead_algo,
            self.application_secret.response_data_secret.as_ref(),
        ) {
            aki
        } else {
            return Err(SPDM_STATUS_CRYPTO_ERROR);
        };
        self.application_secret.response_direction.encryption_key = res.0;
        self.application_secret.response_direction.salt = res.1;
        debug!(
            "!!! response_direction.encryption_key !!!: {:02x?}\n",
            self.application_secret
                .response_direction
                .encryption_key
                .as_ref()
        );
        debug!(
            "!!! response_direction.salt !!!: {:02x?}\n",
            self.application_secret.response_direction.salt.as_ref()
        );

        Ok(())
    }

    pub fn create_data_secret_update(
        &mut self,
        spdm_version: SpdmVersion,
        update_requester: bool,
        update_responder: bool,
    ) -> SpdmResult {
        info!(
            "!!! create_data_secret_update {:?} {:?} !!!:\n",
            update_requester, update_responder
        );
        let hash_algo = self.crypto_param.base_hash_algo;
        let aead_algo = self.crypto_param.aead_algo;

        if update_requester {
            self.application_secret_backup.request_data_secret =
                self.application_secret.request_data_secret.clone();
            self.application_secret_backup.request_direction =
                self.application_secret.request_direction.clone();

            self.application_secret.request_data_secret = if let Some(us) =
                self.key_schedule.derive_update_secret(
                    spdm_version,
                    hash_algo,
                    self.application_secret.request_data_secret.as_ref(),
                ) {
                us
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            };
            debug!(
                "!!! request_data_secret !!!: {:02x?}\n",
                self.application_secret.request_data_secret.as_ref()
            );

            let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
                spdm_version,
                hash_algo,
                aead_algo,
                self.application_secret.request_data_secret.as_ref(),
            ) {
                aki
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            };
            self.application_secret.request_direction.encryption_key = res.0;
            self.application_secret.request_direction.salt = res.1;
            debug!(
                "!!! request_direction.encryption_key !!!: {:02x?}\n",
                self.application_secret
                    .request_direction
                    .encryption_key
                    .as_ref()
            );
            debug!(
                "!!! request_direction.salt !!!: {:02x?}\n",
                self.application_secret.request_direction.salt.as_ref()
            );
            self.application_secret.request_direction.sequence_number = 0;
        }

        if update_responder {
            self.application_secret_backup.response_data_secret =
                self.application_secret.response_data_secret.clone();
            self.application_secret_backup.response_direction =
                self.application_secret.response_direction.clone();

            self.application_secret.response_data_secret = if let Some(us) =
                self.key_schedule.derive_update_secret(
                    spdm_version,
                    hash_algo,
                    self.application_secret.response_data_secret.as_ref(),
                ) {
                us
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            };
            debug!(
                "!!! response_data_secret !!!: {:02x?}\n",
                self.application_secret.response_data_secret.as_ref()
            );

            let res = if let Some(aki) = self.key_schedule.derive_aead_key_iv(
                spdm_version,
                hash_algo,
                aead_algo,
                self.application_secret.response_data_secret.as_ref(),
            ) {
                aki
            } else {
                return Err(SPDM_STATUS_CRYPTO_ERROR);
            };
            self.application_secret.response_direction.encryption_key = res.0;
            self.application_secret.response_direction.salt = res.1;
            debug!(
                "!!! response_direction.encryption_key !!!: {:02x?}\n",
                self.application_secret
                    .response_direction
                    .encryption_key
                    .as_ref()
            );
            debug!(
                "!!! response_direction.salt !!!: {:02x?}\n",
                self.application_secret.response_direction.salt.as_ref()
            );
            self.application_secret.response_direction.sequence_number = 0;
        }
        Ok(())
    }

    pub fn activate_data_secret_update(
        &mut self,
        _spdm_version: SpdmVersion,
        update_requester: bool,
        update_responder: bool,
        use_new_key: bool,
    ) -> SpdmResult {
        if !use_new_key {
            if update_requester {
                self.application_secret.request_data_secret =
                    self.application_secret_backup.request_data_secret.clone();
                self.application_secret.request_direction =
                    self.application_secret_backup.request_direction.clone();
            }
            if update_responder {
                self.application_secret.response_data_secret =
                    self.application_secret_backup.response_data_secret.clone();
                self.application_secret.response_direction =
                    self.application_secret_backup.response_direction.clone();
            }
        } else {
            if update_requester {
                self.application_secret_backup.request_data_secret = SpdmDigestStruct::default();
                self.application_secret_backup.request_direction =
                    SpdmSessionSecretParam::default();
            }
            if update_responder {
                self.application_secret_backup.response_data_secret = SpdmDigestStruct::default();
                self.application_secret_backup.response_direction =
                    SpdmSessionSecretParam::default();
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_hmac_with_response_finished_key(
        &self,
        message: &[u8],
    ) -> SpdmResult<SpdmDigestStruct> {
        crypto::hmac::hmac(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.response_finished_key.as_ref(),
            crypto::hash::hash_all(self.crypto_param.base_hash_algo, message)
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?
                .as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_hmac_with_response_finished_key(
        &self,
        message_hash: &[u8],
    ) -> SpdmResult<SpdmDigestStruct> {
        crypto::hmac::hmac(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.response_finished_key.as_ref(),
            message_hash,
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn generate_hmac_with_request_finished_key(
        &self,
        message: &[u8],
    ) -> SpdmResult<SpdmDigestStruct> {
        crypto::hmac::hmac(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.request_finished_key.as_ref(),
            crypto::hash::hash_all(self.crypto_param.base_hash_algo, message)
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?
                .as_ref(),
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn generate_hmac_with_request_finished_key(
        &self,
        message_hash: &[u8],
    ) -> SpdmResult<SpdmDigestStruct> {
        crypto::hmac::hmac(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.request_finished_key.as_ref(),
            message_hash,
        )
        .ok_or(SPDM_STATUS_CRYPTO_ERROR)
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn verify_hmac_with_response_finished_key(
        &self,
        message: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult {
        crypto::hmac::hmac_verify(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.response_finished_key.as_ref(),
            crypto::hash::hash_all(self.crypto_param.base_hash_algo, message)
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?
                .as_ref(),
            hmac,
        )
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn verify_hmac_with_response_finished_key(
        &self,
        message_hash: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult {
        crypto::hmac::hmac_verify(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.response_finished_key.as_ref(),
            message_hash,
            hmac,
        )
    }

    #[cfg(not(feature = "hashed-transcript-data"))]
    pub fn verify_hmac_with_request_finished_key(
        &self,
        message: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult {
        crypto::hmac::hmac_verify(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.request_finished_key.as_ref(),
            crypto::hash::hash_all(self.crypto_param.base_hash_algo, message)
                .ok_or(SPDM_STATUS_CRYPTO_ERROR)?
                .as_ref(),
            hmac,
        )
    }

    #[cfg(feature = "hashed-transcript-data")]
    pub fn verify_hmac_with_request_finished_key(
        &self,
        message_hash: &[u8],
        hmac: &SpdmDigestStruct,
    ) -> SpdmResult {
        crypto::hmac::hmac_verify(
            self.crypto_param.base_hash_algo,
            self.handshake_secret.request_finished_key.as_ref(),
            message_hash,
            hmac,
        )
    }

    pub fn export_keys(&mut self) -> (SpdmSessionSecretParam, SpdmSessionSecretParam) {
        (
            SpdmSessionSecretParam {
                encryption_key: self
                    .application_secret
                    .request_direction
                    .encryption_key
                    .clone(),
                salt: self.application_secret.request_direction.salt.clone(),
                sequence_number: self.application_secret.request_direction.sequence_number,
            },
            SpdmSessionSecretParam {
                encryption_key: self
                    .application_secret
                    .response_direction
                    .encryption_key
                    .clone(),
                salt: self.application_secret.response_direction.salt.clone(),
                sequence_number: self.application_secret.response_direction.sequence_number,
            },
        )
    }

    pub fn encode_spdm_secured_message(
        &mut self,
        app_buffer: &[u8],
        secured_buffer: &mut [u8],
        is_requester: bool,
    ) -> SpdmResult<usize> {
        match self.session_state {
            SpdmSessionState::SpdmSessionNotStarted => Err(SPDM_STATUS_INVALID_STATE_LOCAL),
            SpdmSessionState::SpdmSessionHandshaking => {
                if is_requester {
                    let r = self.encode_msg(
                        app_buffer,
                        secured_buffer,
                        &self.handshake_secret.request_direction,
                    );
                    self.handshake_secret.request_direction.sequence_number += 1;
                    r
                } else {
                    let r = self.encode_msg(
                        app_buffer,
                        secured_buffer,
                        &self.handshake_secret.response_direction,
                    );
                    self.handshake_secret.response_direction.sequence_number += 1;
                    r
                }
            }
            SpdmSessionState::SpdmSessionEstablished => {
                if is_requester {
                    let r = self.encode_msg(
                        app_buffer,
                        secured_buffer,
                        &self.application_secret.request_direction,
                    );
                    self.application_secret.request_direction.sequence_number += 1;
                    r
                } else {
                    let r = self.encode_msg(
                        app_buffer,
                        secured_buffer,
                        &self.application_secret.response_direction,
                    );
                    self.application_secret.response_direction.sequence_number += 1;
                    r
                }
            }
            _ => panic!("unknown session state"),
        }
    }

    pub fn decode_spdm_secured_message(
        &mut self,
        secured_buffer: &[u8],
        app_buffer: &mut [u8],
        is_requester: bool,
    ) -> SpdmResult<usize> {
        match self.session_state {
            SpdmSessionState::SpdmSessionNotStarted => Err(SPDM_STATUS_INVALID_STATE_LOCAL),
            SpdmSessionState::SpdmSessionHandshaking => {
                if is_requester {
                    let r = self.decode_msg(
                        secured_buffer,
                        app_buffer,
                        &self.handshake_secret.request_direction,
                    );
                    self.handshake_secret.request_direction.sequence_number += 1;
                    r
                } else {
                    let r = self.decode_msg(
                        secured_buffer,
                        app_buffer,
                        &self.handshake_secret.response_direction,
                    );
                    self.handshake_secret.response_direction.sequence_number += 1;
                    r
                }
            }
            SpdmSessionState::SpdmSessionEstablished => {
                if is_requester {
                    let r = self.decode_msg(
                        secured_buffer,
                        app_buffer,
                        &self.application_secret.request_direction,
                    );
                    self.application_secret.request_direction.sequence_number += 1;
                    r
                } else {
                    let r = self.decode_msg(
                        secured_buffer,
                        app_buffer,
                        &self.application_secret.response_direction,
                    );
                    self.application_secret.response_direction.sequence_number += 1;
                    r
                }
            }
            _ => Err(SPDM_STATUS_INVALID_STATE_LOCAL),
        }
    }

    fn encode_msg(
        &self,
        app_buffer: &[u8],
        secured_buffer: &mut [u8],
        secret_param: &SpdmSessionSecretParam,
    ) -> SpdmResult<usize> {
        let session_id = self.session_id;
        let aead_algo = self.crypto_param.aead_algo;
        let transport_param = &self.transport_param;

        let cipher_text_size = app_buffer.len() + 2;
        let tag_size = aead_algo.get_tag_size() as usize;

        let mut aad_buffer = [0u8; 6 + 8];
        let mut writer = Writer::init(&mut aad_buffer);
        let app_length = app_buffer.len() as u16;
        let length = cipher_text_size as u16 + tag_size as u16;
        session_id
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_BUFFER_TOO_SMALL)?;
        if transport_param.sequence_number_count != 0 {
            let sequence_number = secret_param.sequence_number;
            for i in 0..transport_param.sequence_number_count {
                let s = ((sequence_number >> (8 * i)) & 0xFF) as u8;
                s.encode(&mut writer)
                    .map_err(|_| SPDM_STATUS_BUFFER_TOO_SMALL)?;
            }
        }
        length
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_BUFFER_TOO_SMALL)?;
        let aad_size = writer.used();
        assert_eq!(aad_size, 6 + transport_param.sequence_number_count as usize);

        let mut plain_text_buf = [0; config::SENDER_BUFFER_SIZE];
        let mut writer = Writer::init(&mut plain_text_buf);
        app_length
            .encode(&mut writer)
            .map_err(|_| SPDM_STATUS_BUFFER_TOO_SMALL)?;
        let head_size = writer.used();
        assert_eq!(head_size, 2);
        plain_text_buf[head_size..(head_size + app_buffer.len())].copy_from_slice(app_buffer);

        let mut tag_buffer = [0u8; 16];

        let mut salt = secret_param.salt.data.clone();
        let sequence_number = secret_param.sequence_number;
        salt[0] ^= (sequence_number & 0xFF) as u8;
        salt[1] ^= ((sequence_number >> 8) & 0xFF) as u8;
        salt[2] ^= ((sequence_number >> 16) & 0xFF) as u8;
        salt[3] ^= ((sequence_number >> 24) & 0xFF) as u8;
        salt[4] ^= ((sequence_number >> 32) & 0xFF) as u8;
        salt[5] ^= ((sequence_number >> 40) & 0xFF) as u8;
        salt[6] ^= ((sequence_number >> 48) & 0xFF) as u8;
        salt[7] ^= ((sequence_number >> 56) & 0xFF) as u8;

        let (ret_cipher_text_size, ret_tag_size) = crypto::aead::encrypt(
            aead_algo,
            &secret_param.encryption_key.data[..(aead_algo.get_key_size() as usize)],
            &salt[..(aead_algo.get_iv_size() as usize)],
            &aad_buffer[..aad_size],
            &plain_text_buf[0..cipher_text_size],
            &mut tag_buffer[0..tag_size],
            &mut secured_buffer[aad_size..(aad_size + cipher_text_size)],
        )?;
        assert_eq!(ret_tag_size, tag_size);
        assert_eq!(ret_cipher_text_size, cipher_text_size);

        secured_buffer[..aad_size].copy_from_slice(&aad_buffer[..aad_size]);
        secured_buffer[(aad_size + cipher_text_size)..(aad_size + cipher_text_size + tag_size)]
            .copy_from_slice(&tag_buffer);

        Ok(aad_size + cipher_text_size + tag_size)
    }

    fn decode_msg(
        &self,
        secured_buffer: &[u8],
        app_buffer: &mut [u8],
        secret_param: &SpdmSessionSecretParam,
    ) -> SpdmResult<usize> {
        let session_id = self.session_id;
        let aead_algo = self.crypto_param.aead_algo;
        let transport_param = &self.transport_param;
        let tag_size = aead_algo.get_tag_size() as usize;

        let mut reader = Reader::init(secured_buffer);
        let read_session_id = u32::read(&mut reader).ok_or(SPDM_STATUS_DECODE_AEAD_FAIL)?;
        if read_session_id != session_id {
            error!("session_id mismatch!\n");
            return Err(SPDM_STATUS_DECODE_AEAD_FAIL);
        }
        if transport_param.sequence_number_count != 0 {
            let sequence_number = secret_param.sequence_number;
            for i in 0..transport_param.sequence_number_count {
                let s = u8::read(&mut reader).ok_or(SPDM_STATUS_DECODE_AEAD_FAIL)?;
                if s != ((sequence_number >> (8 * i)) & 0xFF) as u8 {
                    info!("sequence_num mismatch!\n");
                    return Err(SPDM_STATUS_DECODE_AEAD_FAIL);
                }
            }
        }
        let length = u16::read(&mut reader).ok_or(SPDM_STATUS_DECODE_AEAD_FAIL)?;
        let aad_size = reader.used();
        assert_eq!(aad_size, 6 + transport_param.sequence_number_count as usize);

        // secure buffer might be bigger for alignment
        if secured_buffer.len() < length as usize + aad_size {
            return Err(SPDM_STATUS_DECODE_AEAD_FAIL);
        }

        if (length as usize) < tag_size {
            return Err(SPDM_STATUS_DECODE_AEAD_FAIL);
        }

        let cipher_text_size = length as usize - tag_size;

        let mut plain_text_buf = [0; config::RECEIVER_BUFFER_SIZE];

        let mut salt = secret_param.salt.data.clone();
        let sequence_number = secret_param.sequence_number;
        salt[0] ^= (sequence_number & 0xFF) as u8;
        salt[1] ^= ((sequence_number >> 8) & 0xFF) as u8;
        salt[2] ^= ((sequence_number >> 16) & 0xFF) as u8;
        salt[3] ^= ((sequence_number >> 24) & 0xFF) as u8;
        salt[4] ^= ((sequence_number >> 32) & 0xFF) as u8;
        salt[5] ^= ((sequence_number >> 40) & 0xFF) as u8;
        salt[6] ^= ((sequence_number >> 48) & 0xFF) as u8;
        salt[7] ^= ((sequence_number >> 56) & 0xFF) as u8;

        let ret_plain_text_size = crypto::aead::decrypt(
            aead_algo,
            &secret_param.encryption_key.data[..(aead_algo.get_key_size() as usize)],
            &salt[..(aead_algo.get_iv_size() as usize)],
            &secured_buffer[..aad_size],
            &secured_buffer[aad_size..(aad_size + cipher_text_size)],
            &secured_buffer
                [(aad_size + cipher_text_size)..(aad_size + cipher_text_size + tag_size)],
            &mut plain_text_buf[..cipher_text_size],
        )?;

        let mut reader = Reader::init(&plain_text_buf);
        let app_length = u16::read(&mut reader).ok_or(SPDM_STATUS_DECODE_AEAD_FAIL)? as usize;
        if ret_plain_text_size < app_length + 2 {
            return Err(SPDM_STATUS_DECODE_AEAD_FAIL);
        }

        app_buffer[..app_length].copy_from_slice(&plain_text_buf[2..(app_length + 2)]);
        Ok(app_length)
    }
}

#[cfg(all(test,))]
mod tests_session {
    use super::*;

    #[test]
    fn test_case0_activate_data_secret_update() {
        let mut session = SpdmSession::default();
        let status = session
            .activate_data_secret_update(SpdmVersion::SpdmVersion12, true, true, false)
            .is_ok();
        assert!(status);

        let status = session
            .activate_data_secret_update(SpdmVersion::SpdmVersion12, true, false, false)
            .is_ok();
        assert!(status);

        let status = session
            .activate_data_secret_update(SpdmVersion::SpdmVersion12, false, false, false)
            .is_ok();
        assert!(status);
    }
    #[test]
    fn test_case0_decode_msg() {
        let mut session = SpdmSession::default();
        let session_id = 4294901758u32;
        let mut receive_buffer = [100u8; config::RECEIVER_BUFFER_SIZE];
        let mut decoded_receive_buffer = [0u8; config::RECEIVER_BUFFER_SIZE];

        session.setup(session_id).unwrap();
        session.set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);

        session.handshake_secret.request_direction = SpdmSessionSecretParam {
            encryption_key: SpdmAeadKeyStruct {
                data_size: 50,
                data: Box::new([10u8; SPDM_MAX_AEAD_KEY_SIZE]),
            },
            salt: SpdmAeadIvStruct {
                data_size: 50,
                data: Box::new([10u8; SPDM_MAX_AEAD_IV_SIZE]),
            },
            sequence_number: 100u64,
        };
        session.transport_param.sequence_number_count = 1;

        let status = session
            .decode_msg(
                &receive_buffer,
                &mut decoded_receive_buffer,
                &session.handshake_secret.request_direction,
            )
            .is_ok();
        assert!(!status);

        let mut witer = Writer::init(&mut receive_buffer);
        assert!(session_id.encode(&mut witer).is_ok());
        let status = session
            .decode_msg(
                &receive_buffer[0..100],
                &mut decoded_receive_buffer,
                &session.handshake_secret.request_direction,
            )
            .is_ok();
        assert!(!status);
    }
    #[test]
    fn test_case0_encode_msg() {
        let mut session = SpdmSession::default();
        let session_id = 4294901758u32;
        let send_buffer = [100u8; config::SENDER_BUFFER_SIZE - 0x40];
        let mut encoded_send_buffer = [0u8; config::SENDER_BUFFER_SIZE];

        session.setup(session_id).unwrap();
        session.set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        session.set_session_state(crate::common::session::SpdmSessionState::SpdmSessionHandshaking);
        session.transport_param.sequence_number_count = 1;
        println!("session.session_id::{:?}", session.session_id);
        let status = session
            .encode_msg(
                &send_buffer,
                &mut encoded_send_buffer,
                &session.handshake_secret.request_direction,
            )
            .is_ok();
        assert!(status);
    }
    #[test]
    #[should_panic]
    fn test_case0_setup() {
        let mut session = SpdmSession::default();
        session.session_id = 0xffffu32;
        let session_id = 4294901758u32;
        let _ = session.setup(session_id).is_err();
    }
    #[test]
    #[should_panic]
    fn test_case0_teardown() {
        let mut session = SpdmSession::default();
        session.session_id = 0xffffu32;
        let session_id = 4294901758u32;
        let _ = session.teardown(session_id).is_err();
    }
}
