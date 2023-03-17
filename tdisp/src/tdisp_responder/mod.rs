// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

pub use crate::tdisp_codec::*;
pub use ::codec::*;
use spdmlib::{
    error::*,
    message::{VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct},
};

use crate::{
    config::{MAX_EXTENDED_ERROR_DATA_LENGTH, MAX_VENDOR_ID_LEN},
    context::{TdispContext, TdispMessageHeader, TdispRequestResponseCode},
    device::TdispConfiguration,
};

use core::mem;

use self::context::{
    ExtendedErrorData, GenericErrorResponseCode, InterfaceId, MessagePayloadResponseTdispError,
};

pub mod bind_p2p_stream_request_rsp;
pub mod device_interface_report_rsp;
pub mod device_interface_state_rsp;
pub mod lock_interface_request_rsp;
pub mod set_mmio_attribute_request_rsp;
pub mod start_interface_request_rsp;
pub mod stop_interface_request_rsp;
pub mod tdisp_capabilities_rsp;
pub mod tdisp_error_rsp;
pub mod tdisp_version_rsp;
pub mod unbind_p2p_stream_request_rsp;
pub mod vdm_response;

pub static mut TDISP_RESPONDER: Option<TdispResponder> = None;

pub struct TdispResponder<'a> {
    pub tdisp_requester_context: TdispContext<'a>,
}

pub fn vendor_defined_request_handler(
    vendor_defined_req_payload_struct: &VendorDefinedReqPayloadStruct,
) -> SpdmResult<VendorDefinedRspPayloadStruct> {
    let VendorDefinedReqPayloadStruct {
        req_length,
        vendor_defined_req_payload,
    } = vendor_defined_req_payload_struct;

    if (*req_length as usize) < mem::size_of::<TdispMessageHeader>() {
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    } else if unsafe { TDISP_RESPONDER.is_none() } {
        Err(SPDM_STATUS_INVALID_MSG_FIELD)
    } else {
        let tdisp_message_header = TdispMessageHeader::read_bytes(vendor_defined_req_payload);
        match tdisp_message_header {
            Some(tmh) => match tmh.message_type {
                TdispRequestResponseCode::RequestGetTdispVersion => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_tdisp_version(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestGetTdispCapabilities => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_tdisp_capabilities(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestLockInterfaceRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_lock_interface_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestGetDeviceInterfaceReport => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_device_interface_report(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestGetDeviceInterfaceState => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_device_interface_state(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestStartInterfaceRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_start_interface_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestStopInterfaceRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_stop_interface_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestBindP2pStreamRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_bind_p2p_stream_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestUnbindP2pStreamRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_unbind_p2p_stream_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestSetMmioAttributeRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_set_mmio_attribute_request(vendor_defined_req_payload_struct)
                },
                TdispRequestResponseCode::RequestVdmRequest => unsafe {
                    TDISP_RESPONDER
                        .as_mut()
                        .unwrap()
                        .handle_vdm_request(vendor_defined_req_payload_struct)
                },
                _ => Err(SPDM_STATUS_INVALID_MSG_FIELD),
            },
            None => Err(SPDM_STATUS_INVALID_MSG_FIELD),
        }
    }
}

impl<'a> TdispResponder<'a> {
    pub fn new(
        interface_id: InterfaceId,
        configuration: &'a mut dyn TdispConfiguration,
        spdm_session_id: u32,
    ) -> Self {
        TdispResponder {
            tdisp_requester_context: TdispContext::new(
                interface_id,
                configuration,
                spdm_session_id,
            ),
        }
    }
}

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_REQUEST: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::InvalidRequest,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_BUSY: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::Busy,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_INTERFACE_STATE:
    MessagePayloadResponseTdispError = MessagePayloadResponseTdispError {
    error_code: GenericErrorResponseCode::InvalidInterfaceState,
    error_data: 0,
    extended_error_data: ExtendedErrorData {
        registry_id: 0,
        vendor_id_len: 0,
        vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
    },
};

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_UNSPECIFIED: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::Unspecified,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_UNSUPPORTED_REQUEST:
    MessagePayloadResponseTdispError = MessagePayloadResponseTdispError {
    error_code: GenericErrorResponseCode::UnsupportedRequest,
    error_data: 0,
    extended_error_data: ExtendedErrorData {
        registry_id: 0,
        vendor_id_len: 0,
        vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
    },
};

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_VERSION_MISMATCH: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::VersionMismatch,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_INTERFACE: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::InvalidInterface,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_NONCE: MessagePayloadResponseTdispError =
    MessagePayloadResponseTdispError {
        error_code: GenericErrorResponseCode::InvalidNonce,
        error_data: 0,
        extended_error_data: ExtendedErrorData {
            registry_id: 0,
            vendor_id_len: 0,
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        },
    };

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INSUFFICIENT_ENTROPY:
    MessagePayloadResponseTdispError = MessagePayloadResponseTdispError {
    error_code: GenericErrorResponseCode::InsufficientEntropy,
    error_data: 0,
    extended_error_data: ExtendedErrorData {
        registry_id: 0,
        vendor_id_len: 0,
        vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
    },
};

pub const MESSAGE_PAYLOAD_RESPONSE_TDISP_ERROR_INVALID_DEVICE_CONFIGURATION:
    MessagePayloadResponseTdispError = MessagePayloadResponseTdispError {
    error_code: GenericErrorResponseCode::InvalidDeviceConfiguration,
    error_data: 0,
    extended_error_data: ExtendedErrorData {
        registry_id: 0,
        vendor_id_len: 0,
        vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
    },
};
