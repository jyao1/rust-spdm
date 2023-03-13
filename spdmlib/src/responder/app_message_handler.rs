// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use conquer_once::spin::OnceCell;

use crate::config::MAX_SPDM_MSG_SIZE;
use crate::error::SpdmResult;
use crate::responder::ResponderContext;

type SpdmAppMessageCbRes = ([u8; MAX_SPDM_MSG_SIZE], usize);

#[derive(Clone)]
pub struct SpdmAppMessageHandler {
    pub dispatch_secured_app_message_cb: fn(
        ctx: &mut ResponderContext,
        session_id: u32,
        app_buffer: &[u8],
        auxiliary_app_data: &[u8],
    ) -> SpdmResult<SpdmAppMessageCbRes>,
}

static SPDM_APP_MESSAGE_HANDLER: OnceCell<SpdmAppMessageHandler> = OnceCell::uninit();

static DEFAULT: SpdmAppMessageHandler = SpdmAppMessageHandler {
    dispatch_secured_app_message_cb: |_ctx: &mut ResponderContext,
                                      _session_id: u32,
                                      _app_buffer: &[u8],
                                      _auxiliary_app_data: &[u8]|
     -> SpdmResult<SpdmAppMessageCbRes> { unimplemented!() },
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
) -> SpdmResult<SpdmAppMessageCbRes> {
    (SPDM_APP_MESSAGE_HANDLER
        .try_get_or_init(|| DEFAULT.clone())
        .unwrap_or(&DEFAULT)
        .dispatch_secured_app_message_cb)(ctx, session_id, app_buffer, auxiliary_app_data)
}
