// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use conquer_once::spin::OnceCell;

use crate::config::USER_MAX_SPDM_MSG_SIZE;
use crate::responder::ResponderContext;

#[derive(Clone)]
pub struct SpdmAppMessageHandler {
    pub dispatch_secured_app_message_cb: fn(
        ctx: &mut ResponderContext,
        session_id: u32,
        app_buffer: &[u8],
        auxiliary_app_data: &[u8],
    ) -> [u8; USER_MAX_SPDM_MSG_SIZE],
}

static SPDM_APP_MESSAGE_HANDLER: OnceCell<SpdmAppMessageHandler> = OnceCell::uninit();

static DEFAULT: SpdmAppMessageHandler = SpdmAppMessageHandler {
    dispatch_secured_app_message_cb: |_ctx: &mut ResponderContext,
                                      _session_id: u32,
                                      _app_buffer: &[u8],
                                      _auxiliary_app_data: &[u8]|
     -> [u8; USER_MAX_SPDM_MSG_SIZE] { unimplemented!() },
};

#[allow(dead_code)]
pub fn register(context: SpdmAppMessageHandler) -> bool {
    SPDM_APP_MESSAGE_HANDLER.try_init_once(|| context).is_ok()
}

pub fn dispatch_secured_app_message_cb(
    ctx: &mut ResponderContext,
    session_id: u32,
    app_buffer: &[u8],
    auxiliary_app_data: &[u8],
) -> [u8; USER_MAX_SPDM_MSG_SIZE] {
    (SPDM_APP_MESSAGE_HANDLER
        .try_get_or_init(|| DEFAULT.clone())
        .unwrap_or(&DEFAULT)
        .dispatch_secured_app_message_cb)(ctx, session_id, app_buffer, auxiliary_app_data)
}
