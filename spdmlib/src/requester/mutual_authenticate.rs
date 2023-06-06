// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::{
    error::{SpdmResult, SPDM_STATUS_INVALID_MSG_FIELD, SPDM_STATUS_INVALID_STATE_LOCAL},
    message::SpdmKeyExchangeMutAuthAttributes,
};

use super::RequesterContext;

impl<'a> RequesterContext<'a> {
    pub fn session_based_mutual_authenticate(&mut self, session_id: u32) -> SpdmResult<()> {
        self.common.construct_my_cert_chain()?;

        let spdm_session = self
            .common
            .get_session_via_id(session_id)
            .ok_or(SPDM_STATUS_INVALID_STATE_LOCAL)?;

        let mut_auth_requested = spdm_session.get_mut_auth_requested();
        match mut_auth_requested {
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ => Ok(()),
            SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_ENCAP_REQUEST
            | SpdmKeyExchangeMutAuthAttributes::MUT_AUTH_REQ_WITH_GET_DIGESTS => {
                self.get_encapsulated_request_response(session_id, mut_auth_requested)
            }
            _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}
