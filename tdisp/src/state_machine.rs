// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use ::codec::*;

enum_builder! {
    @U8
    EnumName: TDIState;
    EnumVal{
        // 1. In CONFIG_UNLOCKED the VMM configures the TDI to be assigned to a TVM.
        // 2. TVMs should not place confidential data into a TDI in this state.
        // 3. Memory Requests originating within a TVM must be rejected.
        // 4. Transitions to by STOP_INTERFACE_REQUEST message.
        // 5. DSM ensure no data leaked outside of device.
        ConfigUnlocked => 0x00,

        // 1. Transitions to after TDI configuration is finalized by the VMM.
        // 2. Transitions to by LOCK_INTERFACE_REQUEST message.
        // 3. Memory Requests originating within a TVM must be rejected.
        // 4. DSM must perform all necessary actions to lock the TDI configuration.
        // 5. DSM must start tracking the TDI for [changes](need clarify) that affect the configuration or the security of the TDI
        // 6. Transitions to ERROR when Changes are detected.
        // 7. If applicable, verify that an IDE stream has been established by the TSM between the host and the device.
        // 8. If the TVM approves of the device, the TVM may request the TSM to transition the TDI to RUN.
        ConfigLocked => 0x01,

        // 1. TDI resources are operational and permitted to be accessed and managed by the TVM.
        // 2. DSM must continue tracking the TDI for changes that affect the configuration or the security of the TDI
        // 3. Transitions to ERROR when Changes are detected.
        Run => 0x02,

        // 1. The TDI must not expose confidential TVM data.
        // 2. Memory Requests originating within a TVM must be rejected.
        // 3. The TDI must restrict TLP operations
        // 4. Before transition to CONFIG_UNLOCKED, all TVM confidential data must be cleared.
        Error => 0x03
    }
}

#[derive(Debug, Default)]
pub struct TdispStateMachine {
    pub current_state: TDIState,
}

impl Codec for TdispStateMachine {
    fn encode(&self, bytes: &mut Writer) {
        self.current_state.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let current_state = TDIState::read(r)?;

        Some(TdispStateMachine { current_state })
    }
}

impl TdispStateMachine {
    pub fn new() -> Self {
        TdispStateMachine {
            current_state: TDIState::ConfigUnlocked,
        }
    }

    #[inline]
    pub fn to_state_config_unlocked(&mut self) {
        self.current_state = TDIState::ConfigUnlocked;
    }

    #[inline]
    pub fn to_state_config_locked(&mut self) {
        self.current_state = TDIState::ConfigLocked;
    }

    #[inline]
    pub fn to_state_run(&mut self) {
        self.current_state = TDIState::Run;
    }

    #[inline]
    pub fn to_state_error(&mut self) {
        self.current_state = TDIState::Error;
    }

    #[inline]
    pub fn reset(&mut self) {
        self.to_state_config_unlocked();
    }
}
