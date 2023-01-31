// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::spdm_codec::SpdmCodec;
use super::*;
use crate::config;
use codec::{Codec, Reader, Writer};

pub const MAX_SECURE_SPDM_VERSION_COUNT: usize = 0x02;
pub const MAX_VENDOR_ID_LENGTH: usize = 0xFF;
pub const MAX_OPAQUE_LIST_ELEMENTS_COUNT: usize = 3;

pub const DMTF_SPEC_ID: u32 = 0x444D546;
pub const DMTF_OPAQUE_VERSION: u8 = 0x01;
pub const SM_DATA_VERSION: u8 = 0x01;
pub const PADDING: u8 = 0x00;
pub const RESERVED: u8 = 0x00;
pub const DMTF_ID: u8 = 0x00;
pub const DMTF_VENDOR_LEN: u8 = 0x00;
pub const OPAQUE_LIST_TOTAL_ELEMENTS: u8 = 0x01;
pub const VERSION_SELECTION_SM_DATA_ID: u8 = 0x00;
pub const SUPPORTED_VERSION_LIST_SM_DATA_ID: u8 = 0x01;

pub const DMTF_SECURE_SPDM_VERSION_10: u8 = 0x10;
pub const DMTF_SECURE_SPDM_VERSION_11: u8 = 0x11;

pub const DMTF_SUPPORTED_SECURE_SPDM_VERSION_LIST: [SecuredMessageVersion;
    MAX_SECURE_SPDM_VERSION_COUNT] = [
    SecuredMessageVersion::from_secure_spdm_version(DMTF_SECURE_SPDM_VERSION_10),
    SecuredMessageVersion::from_secure_spdm_version(DMTF_SECURE_SPDM_VERSION_11),
];
pub const DMTF_SECURE_SPDM_VERSION_SELECTION: SecuredMessageVersion =
    SecuredMessageVersion::from_secure_spdm_version(DMTF_SECURE_SPDM_VERSION_10);

pub const REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT0: [u8; 20] = [
    0x46,
    0x54,
    0x4d,
    0x44,
    DMTF_OPAQUE_VERSION,
    OPAQUE_LIST_TOTAL_ELEMENTS,
    RESERVED,
    RESERVED,
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x07,
    0x00,
    SM_DATA_VERSION,
    SUPPORTED_VERSION_LIST_SM_DATA_ID,
    0x02,
    0x00,
    0x10,
    0x00,
    0x11,
    PADDING,
];

pub const RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT0: [u8; 16] = [
    0x46,
    0x54,
    0x4d,
    0x44,
    DMTF_OPAQUE_VERSION,
    OPAQUE_LIST_TOTAL_ELEMENTS,
    RESERVED,
    RESERVED,
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x04,
    0x00,
    SM_DATA_VERSION,
    VERSION_SELECTION_SM_DATA_ID,
    0x00,
    0x11,
];

pub const REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_FMT1: [u8; 16] = [
    OPAQUE_LIST_TOTAL_ELEMENTS,
    RESERVED,
    RESERVED,
    RESERVED,
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x07,
    0x00,
    SM_DATA_VERSION,
    SUPPORTED_VERSION_LIST_SM_DATA_ID,
    0x02,
    0x00,
    0x10,
    0x00,
    0x11,
    PADDING,
];

pub const RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_FMT1: [u8; 12] = [
    OPAQUE_LIST_TOTAL_ELEMENTS,
    RESERVED,
    RESERVED,
    RESERVED,
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x04,
    0x00,
    SM_DATA_VERSION,
    VERSION_SELECTION_SM_DATA_ID,
    0x00,
    0x11,
];

#[derive(Clone, Copy, Debug, Default)]
pub struct SecuredMessageVersion {
    pub major_version: u8,
    pub minor_version: u8,
    pub update_version_number: u8,
    pub alpha: u8,
}

impl SpdmCodec for SecuredMessageVersion {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        ((self.update_version_number << 4) + self.alpha).encode(bytes);
        ((self.major_version << 4) + self.minor_version).encode(bytes);
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SecuredMessageVersion> {
        let update_version_number_alpha = u8::read(r)?;
        let major_version_minor_version = u8::read(r)?;
        let update_version_number = update_version_number_alpha >> 4;
        let alpha = update_version_number_alpha & 0x0F;
        let major_version = major_version_minor_version >> 4;
        let minor_version = major_version_minor_version & 0x0F;

        Some(SecuredMessageVersion {
            major_version,
            minor_version,
            update_version_number,
            alpha,
        })
    }
}

impl SecuredMessageVersion {
    pub fn get_secure_spdm_version(self) -> u8 {
        (self.major_version << 4) + self.minor_version
    }

    pub const fn from_secure_spdm_version(secure_spdm_version: u8) -> Self {
        let major_version = secure_spdm_version >> 4;
        let minor_version = secure_spdm_version & 0x0F;
        Self {
            major_version,
            minor_version,
            update_version_number: 0,
            alpha: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SecuredMessageVersionList {
    pub version_count: u8,
    pub versions_list: [SecuredMessageVersion; MAX_SECURE_SPDM_VERSION_COUNT],
}

impl SpdmCodec for SecuredMessageVersionList {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        self.version_count.encode(bytes);
        for index in 0..self.version_count as usize {
            self.versions_list[index].spdm_encode(context, bytes);
        }
    }
    fn spdm_read(context: &mut SpdmContext, r: &mut Reader) -> Option<SecuredMessageVersionList> {
        let version_count = u8::read(r)?;
        let mut versions_list = [SecuredMessageVersion::default(); MAX_SECURE_SPDM_VERSION_COUNT];
        for d in versions_list.iter_mut().take(version_count as usize) {
            *d = SecuredMessageVersion::spdm_read(context, r)?;
        }

        Some(SecuredMessageVersionList {
            version_count,
            versions_list,
        })
    }
}

#[derive(Clone, Debug)]
pub struct OpaqueElementHeader {
    pub id: u8,
    pub vendor_len: u8,
    pub vendor_id: [u8; MAX_VENDOR_ID_LENGTH],
}

impl Default for OpaqueElementHeader {
    fn default() -> Self {
        Self {
            id: Default::default(),
            vendor_len: Default::default(),
            vendor_id: [0u8; MAX_VENDOR_ID_LENGTH],
        }
    }
}

impl SpdmCodec for OpaqueElementHeader {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        self.id.encode(bytes);
        self.vendor_len.encode(bytes);
        for index in 0..self.vendor_len as usize {
            self.vendor_id[index].encode(bytes);
        }
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<OpaqueElementHeader> {
        let id = u8::read(r)?;
        let vendor_len = u8::read(r)?;
        let mut vendor_id = [0u8; MAX_VENDOR_ID_LENGTH];
        for d in vendor_id.iter_mut().take(vendor_len as usize) {
            *d = u8::read(r)?;
        }

        Some(OpaqueElementHeader {
            id,
            vendor_len,
            vendor_id,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecuredMessageGeneralOpaqueDataHeader {
    pub spec_id: u32,
    pub opaque_version: u8,
    pub total_elements: u8,
}

impl SpdmCodec for SecuredMessageGeneralOpaqueDataHeader {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        if context
            .negotiate_info
            .opaque_data_support
            .contains(SpdmOpaqueSupport::OPAQUE_DATA_FMT1)
        {
            self.total_elements.encode(bytes);
            0u8.encode(bytes); // reserved 3 bytes, 1 byte here required by cargo clippy
        } else {
            self.spec_id.encode(bytes);
            self.opaque_version.encode(bytes);
            self.total_elements.encode(bytes);
        }
        0u16.encode(bytes); // reserved 2 bytes
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SecuredMessageGeneralOpaqueDataHeader> {
        let mut spec_id: u32 = 0;
        let mut opaque_version: u8 = 0;
        let total_elements: u8;

        if context
            .negotiate_info
            .opaque_data_support
            .contains(SpdmOpaqueSupport::OPAQUE_DATA_FMT1)
        {
            total_elements = u8::read(r)?;
            u8::read(r)?; // reserved 3 bytes
            u8::read(r)?;
            u8::read(r)?;
        } else {
            spec_id = u32::read(r)?;
            opaque_version = u8::read(r)?;
            total_elements = u8::read(r)?;
            u16::read(r)?; // reserved 2 bytes
        }

        Some(SecuredMessageGeneralOpaqueDataHeader {
            spec_id,
            opaque_version,
            total_elements,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpaqueElementDMTFVersionSelection {
    pub selected_version: SecuredMessageVersion,
}

impl SpdmCodec for OpaqueElementDMTFVersionSelection {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // ID: Shall be zero to indicate DMTF.
        0u8.encode(bytes); // VendorLen: Shall be zero. Note: DMTF does not have a vendor registry.
        4u16.encode(bytes); // OpaqueElementDataLen: Shall be the length of the remaining bytes excluding the AlignPadding.
        1u8.encode(bytes); // SMDataVersion: Shall identify the format of the remaining bytes. The value shall be one.
        0u8.encode(bytes); // SMDataID: Shall be a value of zero to indicate Secured Message version selection.
        self.selected_version.spdm_encode(context, bytes);
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<OpaqueElementDMTFVersionSelection> {
        u8::read(r)?; // ID
        u8::read(r)?; // VendorLen
        u16::read(r)?; // OpaqueElementDataLen
        u8::read(r)?; // SMDataVersion
        u8::read(r)?; // SMDataID
        let selected_version = SecuredMessageVersion::spdm_read(context, r)?;

        Some(OpaqueElementDMTFVersionSelection { selected_version })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpaqueElementDMTFSupportedVersion {
    pub secured_msg_vers: SecuredMessageVersionList,
}

impl SpdmCodec for OpaqueElementDMTFSupportedVersion {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        0u8.encode(bytes); // ID: Shall be zero to indicate DMTF.
        0u8.encode(bytes); // VendorLen: Shall be zero. Note: DMTF does not have a vendor registry.
        let opaque_element_data_len: u16 = 3 + 2 * self.secured_msg_vers.version_count as u16; // SMDataVersion + SMDataID + self.secured_msg_vers.version_count + 2 * count
        opaque_element_data_len.encode(bytes); // OpaqueElementDataLen: Shall be the length of the remaining bytes excluding the AlignPadding.
        1u8.encode(bytes); // SMDataVersion: Shall identify the format of the remaining bytes. The value shall be one.
        1u8.encode(bytes); // SMDataID: Shall be a value of one to indicate Supported version list.
        self.secured_msg_vers.spdm_encode(context, bytes);

        // padding
        let filled = bytes.used();
        let aligned_len = (filled + 3) & (!3);
        let align_padding = aligned_len - filled;
        for _i in 0..align_padding {
            0u8.encode(bytes);
        }
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<OpaqueElementDMTFSupportedVersion> {
        u8::read(r)?; // ID
        u8::read(r)?; // VendorLen
        u16::read(r)?; // OpaqueElementDataLen
        u8::read(r)?; // SMDataVersion
        u8::read(r)?; // SMDataID
        let secured_msg_vers = SecuredMessageVersionList::spdm_read(context, r)?;

        // padding
        let read = r.used();
        let aligned_len = (read + 3) & (!3);
        let align_padding = aligned_len - read;
        for _i in 0..align_padding {
            u8::read(r)?;
        }

        Some(OpaqueElementDMTFSupportedVersion { secured_msg_vers })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecuredMessageDMTFVersionSelection {
    pub secured_message_general_opaque_data_header: SecuredMessageGeneralOpaqueDataHeader,
    pub opaque_element_dmtf_version_selection_list:
        [OpaqueElementDMTFVersionSelection; MAX_OPAQUE_LIST_ELEMENTS_COUNT],
}

impl SpdmCodec for SecuredMessageDMTFVersionSelection {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        self.secured_message_general_opaque_data_header
            .spdm_encode(context, bytes);
        for index in 0..self
            .secured_message_general_opaque_data_header
            .total_elements as usize
        {
            self.opaque_element_dmtf_version_selection_list[index].spdm_encode(context, bytes);
        }
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SecuredMessageDMTFVersionSelection> {
        let secured_message_general_opaque_data_header =
            SecuredMessageGeneralOpaqueDataHeader::spdm_read(context, r)?;
        let mut opaque_element_dmtf_version_selection_list =
            [OpaqueElementDMTFVersionSelection::default(); MAX_OPAQUE_LIST_ELEMENTS_COUNT];
        for d in opaque_element_dmtf_version_selection_list
            .iter_mut()
            .take(secured_message_general_opaque_data_header.total_elements as usize)
        {
            *d = OpaqueElementDMTFVersionSelection {
                ..OpaqueElementDMTFVersionSelection::spdm_read(context, r)?
            };
        }

        Some(SecuredMessageDMTFVersionSelection {
            secured_message_general_opaque_data_header,
            opaque_element_dmtf_version_selection_list,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SecuredMessageDMTFSupportedVersion {
    pub secured_message_general_opaque_data_header: SecuredMessageGeneralOpaqueDataHeader,
    pub opaque_element_dmtf_supported_version_list:
        [OpaqueElementDMTFSupportedVersion; MAX_OPAQUE_LIST_ELEMENTS_COUNT],
}

impl SpdmCodec for SecuredMessageDMTFSupportedVersion {
    fn spdm_encode(&self, context: &mut SpdmContext, bytes: &mut Writer) {
        self.secured_message_general_opaque_data_header
            .spdm_encode(context, bytes);
        for index in 0..self
            .secured_message_general_opaque_data_header
            .total_elements as usize
        {
            self.opaque_element_dmtf_supported_version_list[index].spdm_encode(context, bytes);
        }
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SecuredMessageDMTFSupportedVersion> {
        let secured_message_general_opaque_data_header =
            SecuredMessageGeneralOpaqueDataHeader::spdm_read(context, r)?;
        let mut opaque_element_dmtf_supported_version_list =
            [OpaqueElementDMTFSupportedVersion::default(); MAX_OPAQUE_LIST_ELEMENTS_COUNT];
        if secured_message_general_opaque_data_header.total_elements
            > MAX_OPAQUE_LIST_ELEMENTS_COUNT as u8
        {
            return None;
        }
        for d in opaque_element_dmtf_supported_version_list
            .iter_mut()
            .take(secured_message_general_opaque_data_header.total_elements as usize)
        {
            *d = OpaqueElementDMTFSupportedVersion {
                ..OpaqueElementDMTFSupportedVersion::spdm_read(context, r)?
            };
        }

        Some(SecuredMessageDMTFSupportedVersion {
            secured_message_general_opaque_data_header,
            opaque_element_dmtf_supported_version_list,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SpdmOpaqueStruct {
    pub data_size: u16,
    pub data: [u8; config::MAX_SPDM_OPAQUE_SIZE],
}
impl Default for SpdmOpaqueStruct {
    fn default() -> SpdmOpaqueStruct {
        SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; config::MAX_SPDM_OPAQUE_SIZE],
        }
    }
}

impl SpdmCodec for SpdmOpaqueStruct {
    fn spdm_encode(&self, _context: &mut SpdmContext, bytes: &mut Writer) {
        self.data_size.encode(bytes);
        for d in self.data.iter().take(self.data_size as usize) {
            d.encode(bytes);
        }
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmOpaqueStruct> {
        let data_size = u16::read(r)?;
        if data_size > config::MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }
        let mut data = [0u8; config::MAX_SPDM_OPAQUE_SIZE];
        for d in data.iter_mut().take(data_size as usize) {
            *d = u8::read(r)?;
        }

        Some(SpdmOpaqueStruct { data_size, data })
    }
}

impl SpdmOpaqueStruct {
    pub fn rsp_get_dmtf_supported_secure_spdm_version_list(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersionList> {
        let mut r = Reader::init(&self.data[0..self.data_size as usize]);
        let secured_message_dmtf_supported_version =
            SecuredMessageDMTFSupportedVersion::spdm_read(context, &mut r)?;

        Some(SecuredMessageVersionList {
            ..secured_message_dmtf_supported_version.opaque_element_dmtf_supported_version_list[0]
                .secured_msg_vers
        })
    }

    pub fn req_get_dmtf_secure_spdm_version_selection(
        &self,
        context: &mut SpdmContext,
    ) -> Option<SecuredMessageVersion> {
        let mut r = Reader::init(&self.data[0..self.data_size as usize]);
        let secured_message_dmtf_version_selection =
            SecuredMessageDMTFVersionSelection::spdm_read(context, &mut r)?;

        Some(SecuredMessageVersion {
            ..secured_message_dmtf_version_selection.opaque_element_dmtf_version_selection_list[0]
                .selected_version
        })
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmOpaqueSupport: u8 {
        const OPAQUE_DATA_FMT0 = 0b0000_0001;
        const OPAQUE_DATA_FMT1 = 0b0000_0010;
    }
}

impl Codec for SpdmOpaqueSupport {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmOpaqueSupport> {
        let bits = u8::read(r)?;

        SpdmOpaqueSupport::from_bits(bits)
    }
}

impl SpdmOpaqueSupport {
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }
}
