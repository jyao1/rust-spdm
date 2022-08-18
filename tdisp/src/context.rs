// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use crate::message::*;
use crate::{
    common::{InternalError, TdispResult},
    config::MAX_TDISP_MESSAGE_SIZE,
    device::TdispConfiguration,
    state_machine::{TDIState, TdispStateMachine},
};
use zeroize::{self, Zeroize};

#[derive(Debug)]
pub struct TdispContext<'a> {
    pub version_sel: TdispVersion,

    pub tdi: InterfaceId,

    pub state_machine: TdispStateMachine,

    pub configuration: &'a mut dyn TdispConfiguration,

    pub spdm_session_id: u32,

    // volatile
    pub request_message: [u8; MAX_TDISP_MESSAGE_SIZE],
    pub request_code: TdispRequestResponseCode,
    pub response_message: [u8; MAX_TDISP_MESSAGE_SIZE],
    pub response_code: TdispRequestResponseCode,
}

impl<'a> TdispContext<'a> {
    pub fn new(
        interface_id: InterfaceId,
        configuration: &'a mut dyn TdispConfiguration,
        spdm_session_id: u32,
    ) -> Self {
        let context = TdispContext {
            version_sel: 0x10,
            state_machine: TdispStateMachine::new(),
            configuration,
            spdm_session_id,
            request_message: [0u8; MAX_TDISP_MESSAGE_SIZE],
            request_code: TdispRequestResponseCode::Unknown(0),
            response_message: [0u8; MAX_TDISP_MESSAGE_SIZE],
            response_code: TdispRequestResponseCode::Unknown(0),
            tdi: interface_id,
        };
        context.configuration.init_config().unwrap(); // let it panic, if the device fail to init.
        context
    }

    pub fn zero_request_message(&mut self) {
        self.request_message.zeroize();
        self.request_code = TdispRequestResponseCode::Unknown(0);
    }

    pub fn zero_response_message(&mut self) {
        self.response_message.zeroize();
        self.response_code = TdispRequestResponseCode::Unknown(0);
    }

    pub fn zero_messages(&mut self) {
        self.zero_request_message();
        self.zero_response_message();
    }

    // change the state
    pub fn to_state_config_unlocked(&mut self, _from: TDIState) -> TdispResult {
        if self.request_code != TdispRequestResponseCode::RequestStopInterfaceRequest {
            Err(InternalError::Violation)
        } else {
            self.configuration.erase_confidential_config()?;
            self.configuration.unlock_config()?;

            self.state_machine.to_state_config_unlocked();
            Ok(())
        }
    }

    pub fn to_state_config_locked(&mut self, from: TDIState) -> TdispResult {
        if from != TDIState::ConfigUnlocked
            || self.request_code != TdispRequestResponseCode::RequestLockInterfaceRequest
        {
            Err(InternalError::Violation)
        } else {
            self.configuration.lock_config()?;

            self.state_machine.to_state_config_locked();
            Ok(())
        }
    }

    pub fn to_state_run(&mut self, from: TDIState) -> TdispResult {
        if from != TDIState::ConfigLocked
            || self.request_code != TdispRequestResponseCode::RequestStartInterfaceRequest
        {
            Err(InternalError::Violation)
        } else {
            self.state_machine.to_state_run();
            Ok(())
        }
    }

    pub fn to_state_error(&mut self, _from: TDIState) -> TdispResult {
        self.state_machine.to_state_error();
        Ok(())
    }
}
