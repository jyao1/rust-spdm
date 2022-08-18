// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt::Debug;

use crate::common::{InternalError, TdispResult};
use crate::context::TdispContext;
use crate::tdisp_codec::*;
use crate::{
    config::{
        MAX_DEVICE_SPECIFIC_INFORMATION_LENGTH, MAX_EXTENDED_ERROR_DATA_LENGTH,
        MAX_MESSAGE_INTERNAL_BUFFER_SIZE, MAX_MMIO_RANGE_COUNT, MAX_VENDOR_ID_LEN,
        MAX_VERSION_COUNT,
    },
    state_machine::TdispStateMachine,
};

type ProtocolId = u8;
pub const PROTOCOL_ID: ProtocolId = 0x1;

enum_builder! {
    @U8
    EnumName: TdispRequestResponseCode;
    EnumVal{
        // request codes
        RequestGetTdispVersion => 0x81, // This request message must retrieve a device's TDISP version
        RequestGetTdispCapabilities => 0x82, // Retrieve protocol capabilities of the device
        RequestLockInterfaceRequest => 0x83, // Move TDI to CONFIG_LOCKED
        RequestGetDeviceInterfaceReport => 0x84, // Obtain a TDI report
        RequestGetDeviceInterfaceState => 0x85, // Obtain state of a TDI
        RequestStartInterfaceRequest => 0x86, // Start a TDI
        RequestStopInterfaceRequest => 0x87, // Stop and move TDI to CONFIG_UNLOCKED (if not already in CONFIG_UNLOCKED)
        RequestBindP2pStreamRequest => 0x88, // Bind a P2P stream
        RequestUnbindP2pStreamRequest => 0x89, // Unbind a P2P stream
        RequestSetMmioAttributeRequest => 0x8A, // Update attributes of specified MMIO range
        RequestVdmRequest => 0x8B, // Vendor-defined message request

        // response codes
        ResponseTdispVersion => 0x01, // Version supported by device
        ResponseTdispCapabilities => 0x02, // Protocol capabilities of the device
        ResponseLockInterfaceResponse => 0x03, // Response to LOCK_INTERFACE_REQUEST
        ResponseDeviceInterfaceReport => 0x04, // Report for a TDI
        ResponseDeviceInterfaceState => 0x05, // Returns TDI state
        ResponseStartInterfaceResponse => 0x06, // Response to request to move TDI to RUN
        ResponseStopInterfaceResponse => 0x07, // Response to a STOP_INTERFACE_REQUEST
        ResponseBindP2pStreamResponse => 0x08, // Response to bind P2P stream request
        ResponseUnbindP2pStreamResponse => 0x09, // Response to unbind P2P stream request
        ResponseSetMmioAttributeResponse => 0x0A, // Response to update MMIO range attributes
        ResponseVdmResponse => 0x0B, // Vendor-defined message response
        ResponseTdispError => 0x7F // Error in handling a request
    }
}

enum_builder! {
    @U16
    EnumName: GenericErrorResponseCode;
    EnumVal{
        InvalidRequest => 0x0001, // One or more request field is invalid.
        Busy => 0x0003, // the Responder may be able to process the request message if the request message is sent again in the future
        InvalidInterfaceState => 0x0004, // The Responder received the request while in the wrong state, or received an unexpected request
        Unspecified => 0x0005, // Unspecified error occurred
        UnsupportedRequest => 0x0007, // Request code is unsupporteda
        VersionMismatch => 0x0041, // The version in not supported
        VendorSpecificError => 0x00FF, // Vendor defined
        InvalidInterface => 0x0101, // INTERFACE_ID does not exist
        InvalidNonce => 0x0102, // The received nonce does not match the expected one
        InsufficientEntropy => 0x0103, // The Responder fails to generate nonce
        InvalidDeviceConfiguration => 0x0104 // Invalid/Unsupported device configurations
    }
}

#[derive(Debug)]
pub struct ExtendedErrorData {
    pub registry_id: u8,
    pub vendor_id_len: u8,
    pub vendor_id: [u8; MAX_VENDOR_ID_LEN],
    pub vendor_err_data: [u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
}

impl Default for ExtendedErrorData {
    fn default() -> Self {
        Self {
            registry_id: Default::default(),
            vendor_id_len: Default::default(),
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
            vendor_err_data: [0u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FunctionId {
    pub requester_id: u16,
    requester_segment: u8,
    pub requester_segment_valid: bool,
}

impl FunctionId {
    #[allow(dead_code)]
    fn get_requester_segment(&self) -> Option<u8> {
        if self.requester_segment_valid {
            Some(self.requester_segment)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    fn set_requester_segment(&mut self, requester_segment: u8) -> TdispResult {
        if self.requester_segment_valid {
            self.requester_segment = requester_segment;
            Ok(())
        } else {
            Err(InternalError::ErrStr(
                "requester segment is not allowed to change when RSV bit is cleared!",
            ))
        }
    }
}

impl TdispCodec for FunctionId {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.requester_id.encode(bytes);
        if self.requester_segment_valid {
            self.requester_segment.encode(bytes);
            1u8.encode(bytes); // Requester Segment Valid bit
        } else {
            0u16.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let requester_id = u16::read(r)?;
        let requester_segment = u8::read(r)?;
        let requester_segment_valid = u8::read(r)?;
        if requester_segment_valid == 0x1 {
            Some(FunctionId {
                requester_id,
                requester_segment,
                requester_segment_valid: true,
            })
        } else if requester_segment_valid == 0x0 {
            Some(FunctionId {
                requester_id,
                requester_segment: 0u8,
                requester_segment_valid: false,
            })
        } else {
            None
        }
    }
}

impl Codec for FunctionId {
    fn encode(&self, bytes: &mut Writer) {
        self.requester_id.encode(bytes);
        if self.requester_segment_valid {
            self.requester_segment.encode(bytes);
            1u8.encode(bytes); // Requester Segment Valid bit
        } else {
            0u16.encode(bytes);
        }
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let requester_id = u16::read(r)?;
        let requester_segment = u8::read(r)?;
        let requester_segment_valid = u8::read(r)?;
        if requester_segment_valid == 0x1 {
            Some(FunctionId {
                requester_id,
                requester_segment,
                requester_segment_valid: true,
            })
        } else if requester_segment_valid == 0x0 {
            Some(FunctionId {
                requester_id,
                requester_segment: 0u8,
                requester_segment_valid: false,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InterfaceId {
    pub function_id: FunctionId,
}

impl TdispCodec for InterfaceId {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.function_id.tdisp_encode(context, bytes);
        0u32.encode(bytes); // reserved
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let function_id = FunctionId::tdisp_read(context, r)?;
        let _ = u32::read(r)?;

        Some(InterfaceId { function_id })
    }
}

impl Codec for InterfaceId {
    fn encode(&self, bytes: &mut Writer) {
        self.function_id.encode(bytes);
        0u32.encode(bytes); // reserved
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let function_id = FunctionId::read(r)?;
        let _ = u32::read(r)?;

        Some(InterfaceId { function_id })
    }
}

pub type TdispVersion = u8;

#[derive(Debug, Default)]
pub struct TdispMessageHeader {
    pub tdisp_version: TdispVersion,
    pub message_type: TdispRequestResponseCode,
    pub interface_id: InterfaceId,
}

impl TdispCodec for TdispMessageHeader {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.tdisp_version.encode(bytes);
        self.message_type.encode(bytes);
        0u16.encode(bytes); // reserved
        self.interface_id.tdisp_encode(context, bytes);
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let tdisp_version = TdispVersion::read(r)?;
        let message_type = TdispRequestResponseCode::read(r)?;
        u16::read(r)?;
        let interface_id = InterfaceId::tdisp_read(context, r)?;

        Some(TdispMessageHeader {
            tdisp_version,
            message_type,
            interface_id,
        })
    }
}

impl Codec for TdispMessageHeader {
    fn encode(&self, bytes: &mut Writer) {
        self.tdisp_version.encode(bytes);
        self.message_type.encode(bytes);
        0u16.encode(bytes); // reserved
        self.interface_id.encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<Self> {
        let tdisp_version = TdispVersion::read(r)?;
        let message_type = TdispRequestResponseCode::read(r)?;
        u16::read(r)?;
        let interface_id = InterfaceId::read(r)?;

        Some(TdispMessageHeader {
            tdisp_version,
            message_type,
            interface_id,
        })
    }

    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadDummy {}

impl TdispCodec for MessagePayloadDummy {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadDummy {})
    }
}

impl Codec for MessagePayloadDummy {
    fn encode(&self, _bytes: &mut Writer) {}

    fn read(_: &mut Reader) -> Option<Self> {
        Some(MessagePayloadDummy {})
    }
}

#[derive(Debug, Default)]
pub struct TdispMessage<T = MessagePayloadDummy>
where
    T: TdispCodec + Default + Debug,
{
    pub tdisp_message_header: TdispMessageHeader,
    pub tdisp_message_payload: T,
}

impl<T> TdispCodec for TdispMessage<T>
where
    T: TdispCodec + Default + Debug,
{
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        PROTOCOL_ID.encode(bytes);
        self.tdisp_message_header.tdisp_encode(context, bytes);
        self.tdisp_message_payload.tdisp_encode(context, bytes);
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let _ = ProtocolId::read(r)?; // protocol id
        let tdisp_message_header = TdispMessageHeader::tdisp_read(context, r)?;
        let tdisp_message_payload = T::tdisp_read(context, r)?;

        Some(TdispMessage {
            tdisp_message_header,
            tdisp_message_payload,
        })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestGetVersion {}

impl TdispCodec for MessagePayloadRequestGetVersion {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadRequestGetVersion {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseVersion {
    pub version_num_count: u8,
    pub version_num_entry: [TdispVersion; MAX_VERSION_COUNT],
}

impl TdispCodec for MessagePayloadResponseVersion {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.version_num_count.encode(bytes);
        for version in self
            .version_num_entry
            .iter()
            .take(self.version_num_count as usize)
        {
            version.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let version_num_count = u8::read(r)?;
        let mut version_num_entry: [TdispVersion; MAX_VERSION_COUNT] = [0u8; MAX_VERSION_COUNT];
        for version in version_num_entry
            .iter_mut()
            .take(version_num_count as usize)
        {
            *version = TdispVersion::read(r)?;
        }

        Some(MessagePayloadResponseVersion {
            version_num_count,
            version_num_entry,
        })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestGetCapabilities {
    tsm_caps: u32,
}

impl TdispCodec for MessagePayloadRequestGetCapabilities {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.tsm_caps.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let tsm_caps = u32::read(r)?;

        Some(MessagePayloadRequestGetCapabilities { tsm_caps })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseCapabilities {
    pub dsm_caps: u32,
    pub req_msgs_supported: u128,
    pub lock_interface_flags_supported: u16,
    pub dev_addr_width: u8,
    pub num_req_this: u8,
    pub num_req_all: u8,
}

impl TdispCodec for MessagePayloadResponseCapabilities {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.dsm_caps.encode(bytes);
        self.req_msgs_supported.encode(bytes);
        self.lock_interface_flags_supported.encode(bytes);
        u24::new(0).encode(bytes); // reserved
        self.dev_addr_width.encode(bytes);
        self.num_req_this.encode(bytes);
        self.num_req_all.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let dsm_caps = u32::read(r)?;
        let req_msgs_supported = u128::read(r)?;
        let lock_interface_flags_supported = u16::read(r)?;
        let _ = u24::read(r)?; // reserved
        let dev_addr_width = u8::read(r)?;
        let num_req_this = u8::read(r)?;
        let num_req_all = u8::read(r)?;

        Some(MessagePayloadResponseCapabilities {
            dsm_caps,
            req_msgs_supported,
            lock_interface_flags_supported,
            dev_addr_width,
            num_req_this,
            num_req_all,
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct LockInterfaceFlag: u16 {
        const NO_FW_UPDATE = 0b0000_0000_0000_0001;
        const SYSTEM_CACHE_LINE_SIZE = 0b0000_0000_0000_0010;
        const LOCK_MSIX = 0b0000_0000_0000_0100;
        const BIND_P2P = 0b0000_0000_0000_1000;
        const ALL_REQUEST_REDIRECT = 0b0000_0000_0001_0000;
    }
}

impl TdispCodec for LockInterfaceFlag {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let bits = u16::read(r)?;

        LockInterfaceFlag::from_bits(bits)
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestLockInterface {
    pub flags: LockInterfaceFlag,
    pub stream_id_for_default_stream: u8,
    pub mmio_reporting_offset: u64,
    pub bind_p2p_address_mask: u64,
}

impl TdispCodec for MessagePayloadRequestLockInterface {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.flags.tdisp_encode(context, bytes);
        self.stream_id_for_default_stream.encode(bytes);
        0u8.encode(bytes); // reserved
        self.mmio_reporting_offset.encode(bytes);
        self.bind_p2p_address_mask.encode(bytes);
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let flags = LockInterfaceFlag::tdisp_read(context, r)?;
        let stream_id_for_default_stream = u8::read(r)?;
        let _ = u8::read(r)?; // reserved
        let mmio_reporting_offset = u64::read(r)?;
        let bind_p2p_address_mask = u64::read(r)?;
        Some(MessagePayloadRequestLockInterface {
            flags,
            stream_id_for_default_stream,
            mmio_reporting_offset,
            bind_p2p_address_mask,
        })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseLockInterface {
    pub start_interface_nonce: u128,
}

impl TdispCodec for MessagePayloadResponseLockInterface {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.start_interface_nonce.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let start_interface_nonce = u128::read(r)?;
        Some(MessagePayloadResponseLockInterface {
            start_interface_nonce,
        })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestGetDeviceInterfaceReport {
    pub offset: u16,
    pub length: u16,
}

impl TdispCodec for MessagePayloadRequestGetDeviceInterfaceReport {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.offset.encode(bytes);
        self.length.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let offset = u16::read(r)?;
        let length = u16::read(r)?;
        Some(MessagePayloadRequestGetDeviceInterfaceReport { offset, length })
    }
}

#[derive(Debug)]
pub struct MessagePayloadResponseDeviceInterfaceReport {
    pub portion_length: u16,
    pub reminder_length: u16,
    pub report_bytes: [u8; MAX_MESSAGE_INTERNAL_BUFFER_SIZE],
}

impl TdispCodec for MessagePayloadResponseDeviceInterfaceReport {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.portion_length.encode(bytes);
        self.reminder_length.encode(bytes);
        for b in self.report_bytes.iter().take(self.portion_length as usize) {
            b.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let portion_length = u16::read(r)?;
        let reminder_length = u16::read(r)?;
        let mut report_bytes: [u8; MAX_MESSAGE_INTERNAL_BUFFER_SIZE] =
            [0u8; MAX_MESSAGE_INTERNAL_BUFFER_SIZE];
        for b in report_bytes.iter_mut().take(portion_length as usize) {
            *b = u8::read(r)?;
        }

        Some(MessagePayloadResponseDeviceInterfaceReport {
            portion_length,
            reminder_length,
            report_bytes,
        })
    }
}

impl Default for MessagePayloadResponseDeviceInterfaceReport {
    fn default() -> Self {
        Self {
            portion_length: Default::default(),
            reminder_length: Default::default(),
            report_bytes: [0u8; MAX_MESSAGE_INTERNAL_BUFFER_SIZE],
        }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct InterfaceInfo: u16 {
        const DEVICE_FIRMWARE_UPDATES_NOT_PERMITTED = 0b0000_0000_0000_0001;
        const DMA_REQUESTS_WITHOUT_PASID = 0b0000_0000_0000_0010;
        const DMA_REQUESTS_WITH_PASID = 0b0000_0000_0000_0100;
        const ATS_SUPPORTED_ENABLED = 0b0000_0000_0000_1000;
        const PRS_SUPPORTED_ENABLED = 0b0000_0000_0001_0000;
    }
}

impl TdispCodec for InterfaceInfo {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let bits = u16::read(r)?;

        InterfaceInfo::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct MMIORangeAttribute: u16 {
        const MSI_X_TABLE = 0b0000_0000_0000_0001;
        const MSI_X_PBA = 0b0000_0000_0000_0010;
        const IS_NON_TEE_MEM = 0b0000_0000_0000_0100;
        const IS_MEM_ATTR_UPDATABLE = 0b0000_0000_0000_1000;
        const PRS_SUPPORTED_ENABLED = 0b0000_0000_0001_0000;
    }
}

impl TdispCodec for MMIORangeAttribute {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let bits = u16::read(r)?;

        MMIORangeAttribute::from_bits(bits)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MMIORange {
    pub first_4k_page_with_offset_added: u64,
    pub number_of_4k_pages: u32,
    pub range_attribute: MMIORangeAttribute,
    pub range_id: u16,
}

impl TdispCodec for MMIORange {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.first_4k_page_with_offset_added.encode(bytes);
        self.number_of_4k_pages.encode(bytes);
        self.range_attribute.tdisp_encode(context, bytes);
        self.range_id.encode(bytes);
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let first_4k_page_with_offset_added = u64::read(r)?;
        let number_of_4k_pages = u32::read(r)?;
        let range_attribute = MMIORangeAttribute::tdisp_read(context, r)?;
        let range_id = u16::read(r)?;

        Some(MMIORange {
            first_4k_page_with_offset_added,
            number_of_4k_pages,
            range_attribute,
            range_id,
        })
    }
}

#[derive(Debug)]
pub struct TDIReport {
    pub interface_info: InterfaceInfo,
    pub msi_x_message_control: u16,
    pub lnr_control: u16,
    pub tph_control: u32,
    pub mmio_range_count: u32,
    pub mmio_range: [MMIORange; MAX_MMIO_RANGE_COUNT],
    pub device_specific_info_len: u32,
    pub device_specific_info: [u8; MAX_DEVICE_SPECIFIC_INFORMATION_LENGTH],
}

impl TdispCodec for TDIReport {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.interface_info.tdisp_encode(context, bytes);
        self.msi_x_message_control.encode(bytes);
        self.lnr_control.encode(bytes);
        self.tph_control.encode(bytes);
        self.mmio_range_count.encode(bytes);
        for m in self.mmio_range.iter().take(self.mmio_range_count as usize) {
            m.tdisp_encode(context, bytes);
        }
        self.device_specific_info_len.encode(bytes);
        for d in self
            .device_specific_info
            .iter()
            .take(self.device_specific_info_len as usize)
        {
            d.encode(bytes);
        }
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let interface_info = InterfaceInfo::tdisp_read(context, r)?;
        let msi_x_message_control = u16::read(r)?;
        let lnr_control = u16::read(r)?;
        let tph_control = u32::read(r)?;
        let mmio_range_count = u32::read(r)?;
        let mut mmio_range: [MMIORange; MAX_MMIO_RANGE_COUNT] =
            [MMIORange::default(); MAX_MMIO_RANGE_COUNT];
        for m in mmio_range.iter_mut().take(mmio_range_count as usize) {
            *m = MMIORange::tdisp_read(context, r)?;
        }
        let device_specific_info_len = u32::read(r)?;
        let mut device_specific_info: [u8; MAX_DEVICE_SPECIFIC_INFORMATION_LENGTH] =
            [0u8; MAX_DEVICE_SPECIFIC_INFORMATION_LENGTH];
        for d in device_specific_info
            .iter_mut()
            .take(device_specific_info_len as usize)
        {
            *d = u8::read(r)?;
        }

        Some(TDIReport {
            interface_info,
            msi_x_message_control,
            lnr_control,
            tph_control,
            mmio_range_count,
            mmio_range,
            device_specific_info_len,
            device_specific_info,
        })
    }
}

impl Default for TDIReport {
    fn default() -> Self {
        Self {
            interface_info: Default::default(),
            msi_x_message_control: Default::default(),
            lnr_control: Default::default(),
            tph_control: Default::default(),
            mmio_range_count: Default::default(),
            mmio_range: Default::default(),
            device_specific_info_len: Default::default(),
            device_specific_info: [0u8; MAX_DEVICE_SPECIFIC_INFORMATION_LENGTH],
        }
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestGetDeviceInterfaceState {}

impl TdispCodec for MessagePayloadRequestGetDeviceInterfaceState {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadRequestGetDeviceInterfaceState {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseDeviceInterfaceState {
    pub tdi_state: TdispStateMachine,
}

impl TdispCodec for MessagePayloadResponseDeviceInterfaceState {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.tdi_state.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let tdi_state = TdispStateMachine::read(r)?;
        Some(MessagePayloadResponseDeviceInterfaceState { tdi_state })
    }
}

pub const NONCE_LENGTH: usize = 32; // specification defined

#[derive(Debug, Default)]
pub struct MessagePayloadRequestStartInterface {
    pub start_interface_nonce: [u8; NONCE_LENGTH],
}

impl TdispCodec for MessagePayloadRequestStartInterface {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        for b in self.start_interface_nonce.iter().take(NONCE_LENGTH) {
            b.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let mut start_interface_nonce: [u8; NONCE_LENGTH] = [0u8; NONCE_LENGTH];
        for b in start_interface_nonce.iter_mut().take(NONCE_LENGTH) {
            *b = u8::read(r)?;
        }
        Some(MessagePayloadRequestStartInterface {
            start_interface_nonce,
        })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseStartInterface {}

impl TdispCodec for MessagePayloadResponseStartInterface {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadResponseStartInterface {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestStopInterface {}

impl TdispCodec for MessagePayloadRequestStopInterface {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadRequestStopInterface {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseStopInterface {}

impl TdispCodec for MessagePayloadResponseStopInterface {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadResponseStopInterface {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestBindP2pStream {
    pub p2p_stream_id: u8,
}

impl TdispCodec for MessagePayloadRequestBindP2pStream {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.p2p_stream_id.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let p2p_stream_id = u8::read(r)?;
        Some(MessagePayloadRequestBindP2pStream { p2p_stream_id })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseBindP2pStream {}

impl TdispCodec for MessagePayloadResponseBindP2pStream {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadResponseBindP2pStream {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestUnbindP2pStream {
    pub p2p_stream_id: u8,
}

impl TdispCodec for MessagePayloadRequestUnbindP2pStream {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.p2p_stream_id.encode(bytes);
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let p2p_stream_id = u8::read(r)?;
        Some(MessagePayloadRequestUnbindP2pStream { p2p_stream_id })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseUnbindP2pStream {}

impl TdispCodec for MessagePayloadResponseUnbindP2pStream {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadResponseUnbindP2pStream {})
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadRequestSetMmioAttribute {
    pub mmio_range: MMIORange,
}

impl TdispCodec for MessagePayloadRequestSetMmioAttribute {
    fn tdisp_encode(&self, context: &mut TdispContext, bytes: &mut Writer) {
        self.mmio_range.tdisp_encode(context, bytes);
    }

    fn tdisp_read(context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let mmio_range = MMIORange::tdisp_read(context, r)?;
        Some(MessagePayloadRequestSetMmioAttribute { mmio_range })
    }
}

#[derive(Debug, Default)]
pub struct MessagePayloadResponseSetMmioAttribute {}

impl TdispCodec for MessagePayloadResponseSetMmioAttribute {
    fn tdisp_encode(&self, _context: &mut TdispContext, _bytes: &mut Writer) {}

    fn tdisp_read(_context: &mut TdispContext, _: &mut Reader) -> Option<Self> {
        Some(MessagePayloadResponseSetMmioAttribute {})
    }
}

#[derive(Debug)]
pub struct MessagePayloadResponseTdispError {
    pub error_code: GenericErrorResponseCode,
    pub error_data: u32,
    pub extended_error_data: ExtendedErrorData,
}

impl TdispCodec for MessagePayloadResponseTdispError {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        (self.error_code.get_u16() as u32).encode(bytes);
        self.error_data.encode(bytes);
        if self.error_code == GenericErrorResponseCode::VendorSpecificError {
            self.extended_error_data.registry_id.encode(bytes);
            self.extended_error_data.vendor_id_len.encode(bytes);
            for b in self
                .extended_error_data
                .vendor_id
                .iter()
                .take(self.extended_error_data.vendor_id_len as usize)
            {
                b.encode(bytes);
            }
            for b in self
                .extended_error_data
                .vendor_err_data
                .iter()
                .take(self.error_data as usize)
            {
                b.encode(bytes);
            }
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let error_code = u32::read(r)?;
        let error_data = u32::read(r)?;
        let mut extended_error_data = ExtendedErrorData::default();

        if GenericErrorResponseCode::VendorSpecificError.get_u16() as u32 == error_code {
            extended_error_data.registry_id = u8::read(r)?;
            extended_error_data.vendor_id_len = u8::read(r)?;
            for b in extended_error_data
                .vendor_id
                .iter_mut()
                .take(extended_error_data.vendor_id_len as usize)
            {
                *b = u8::read(r)?;
            }
            for b in extended_error_data
                .vendor_err_data
                .iter_mut()
                .take(error_data as usize)
            {
                *b = u8::read(r)?;
            }
        }
        let error_code = GenericErrorResponseCode::read_bytes(&error_code.to_le_bytes())?;

        Some(MessagePayloadResponseTdispError {
            error_code,
            error_data,
            extended_error_data,
        })
    }
}

#[derive(Debug)]
pub struct MessagePayloadRequestVDM {
    pub registry_id: u8,
    pub vendor_id_len: u8,
    pub vendor_id: [u8; MAX_VENDOR_ID_LEN],
    //pub vendor_data: [u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
}

impl Default for MessagePayloadRequestVDM {
    fn default() -> Self {
        Self {
            registry_id: Default::default(),
            vendor_id_len: Default::default(),
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        }
    }
}

impl TdispCodec for MessagePayloadRequestVDM {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.registry_id.encode(bytes);
        self.vendor_id_len.encode(bytes);
        for b in self.vendor_id.iter().take(self.vendor_id_len as usize) {
            b.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let registry_id = u8::read(r)?;
        let vendor_id_len = u8::read(r)?;
        let mut vendor_id: [u8; MAX_VENDOR_ID_LEN] = [0u8; MAX_VENDOR_ID_LEN];
        for b in vendor_id.iter_mut().take(vendor_id_len as usize) {
            *b = u8::read(r)?;
        }

        Some(MessagePayloadRequestVDM {
            registry_id,
            vendor_id_len,
            vendor_id,
        })
    }
}

#[derive(Debug)]
pub struct MessagePayloadResponseVDM {
    pub registry_id: u8,
    pub vendor_id_len: u8,
    pub vendor_id: [u8; MAX_VENDOR_ID_LEN],
    // pub vendor_data: [u8; MAX_EXTENDED_ERROR_DATA_LENGTH],
}

impl Default for MessagePayloadResponseVDM {
    fn default() -> Self {
        Self {
            registry_id: Default::default(),
            vendor_id_len: Default::default(),
            vendor_id: [0u8; MAX_VENDOR_ID_LEN],
        }
    }
}

impl TdispCodec for MessagePayloadResponseVDM {
    fn tdisp_encode(&self, _context: &mut TdispContext, bytes: &mut Writer) {
        self.registry_id.encode(bytes);
        self.vendor_id_len.encode(bytes);
        for b in self.vendor_id.iter().take(self.vendor_id_len as usize) {
            b.encode(bytes);
        }
    }

    fn tdisp_read(_context: &mut TdispContext, r: &mut Reader) -> Option<Self> {
        let registry_id = u8::read(r)?;
        let vendor_id_len = u8::read(r)?;
        let mut vendor_id: [u8; MAX_VENDOR_ID_LEN] = [0u8; MAX_VENDOR_ID_LEN];
        for b in vendor_id.iter_mut().take(vendor_id_len as usize) {
            *b = u8::read(r)?;
        }

        Some(MessagePayloadResponseVDM {
            registry_id,
            vendor_id_len,
            vendor_id,
        })
    }
}
