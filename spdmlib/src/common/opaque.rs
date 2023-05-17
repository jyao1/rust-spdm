// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use super::spdm_codec::SpdmCodec;
use super::*;
use crate::{
    error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL, SPDM_STATUS_UNSUPPORTED_CAP},
    message::MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};
use codec::{Codec, Reader, Writer};

/// This is used in SpdmOpaqueStruct <- SpdmChallengeAuthResponsePayload / SpdmMeasurementsResponsePayload
/// It should be 1024 according to SPDM spec.
pub const MAX_SPDM_OPAQUE_SIZE: usize = 1024;

pub const MAX_SECURE_SPDM_VERSION_COUNT: usize = 0x02;
pub const MAX_OPAQUE_LIST_ELEMENTS_COUNT: usize = 3;

pub const DMTF_SPEC_ID: u32 = 0x444D546;
pub const DMTF_OPAQUE_VERSION: u8 = 0x01;
pub const SM_DATA_VERSION: u8 = 0x01;
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

pub const REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0277: [u8; 20] = [
    0x46,
    0x54,
    0x4d,
    0x44,
    DMTF_OPAQUE_VERSION,
    OPAQUE_LIST_TOTAL_ELEMENTS,
    0x00, // reserved
    0x00, // reserved
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x07,
    0x00,
    SM_DATA_VERSION,
    SUPPORTED_VERSION_LIST_SM_DATA_ID,
    0x02,
    0x00,
    DMTF_SECURE_SPDM_VERSION_10,
    0x00,
    DMTF_SECURE_SPDM_VERSION_11,
    0x00, // padding
];

pub const RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0277: [u8; 16] = [
    0x46,
    0x54,
    0x4d,
    0x44,
    DMTF_OPAQUE_VERSION,
    OPAQUE_LIST_TOTAL_ELEMENTS,
    0x00, // reserved
    0x00, // reserved
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x04,
    0x00,
    SM_DATA_VERSION,
    VERSION_SELECTION_SM_DATA_ID,
    0x00,
    DMTF_SECURE_SPDM_VERSION_11,
];

pub const REQ_DMTF_OPAQUE_DATA_SUPPORT_VERSION_LIST_DSP0274_FMT1: [u8; 16] = [
    OPAQUE_LIST_TOTAL_ELEMENTS,
    0x00, // reserved
    0x00, // reserved
    0x00, // reserved
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x07,
    0x00,
    SM_DATA_VERSION,
    SUPPORTED_VERSION_LIST_SM_DATA_ID,
    0x02,
    0x00,
    DMTF_SECURE_SPDM_VERSION_10,
    0x00,
    DMTF_SECURE_SPDM_VERSION_11,
    0x00, // padding
];

pub const RSP_DMTF_OPAQUE_DATA_VERSION_SELECTION_DSP0274_FMT1: [u8; 12] = [
    OPAQUE_LIST_TOTAL_ELEMENTS,
    0x00, // reserved
    0x00, // reserved
    0x00, // reserved
    DMTF_ID,
    DMTF_VENDOR_LEN,
    0x04,
    0x00,
    SM_DATA_VERSION,
    VERSION_SELECTION_SM_DATA_ID,
    0x00,
    DMTF_SECURE_SPDM_VERSION_11,
];

#[derive(Clone, Copy, Debug, Default)]
pub struct SecuredMessageVersion {
    pub major_version: u8,
    pub minor_version: u8,
    pub update_version_number: u8,
    pub alpha: u8,
}

impl SpdmCodec for SecuredMessageVersion {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += ((self.update_version_number << 4) + self.alpha)
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += ((self.major_version << 4) + self.minor_version)
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
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
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .version_count
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for index in 0..self.version_count as usize {
            cnt += self.versions_list[index]
                .spdm_encode(context, bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
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
    pub vendor_id: [u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
}

impl Default for OpaqueElementHeader {
    fn default() -> Self {
        Self {
            id: Default::default(),
            vendor_len: Default::default(),
            vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
        }
    }
}

impl SpdmCodec for OpaqueElementHeader {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self.id.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        cnt += self
            .vendor_len
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for index in 0..self.vendor_len as usize {
            cnt += self.vendor_id[index]
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<OpaqueElementHeader> {
        let id = u8::read(r)?;
        let vendor_len = u8::read(r)?;
        let mut vendor_id = [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN];
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
    pub total_elements: u8,
}

impl SpdmCodec for SecuredMessageGeneralOpaqueDataHeader {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        if context.negotiate_info.spdm_version_sel.get_u8() < SpdmVersion::SpdmVersion12.get_u8() {
            cnt += DMTF_SPEC_ID
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += DMTF_OPAQUE_VERSION
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += self
                .total_elements
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        } else if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1
        {
            cnt += self
                .total_elements
                .encode(bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved 3 bytes, 1 byte here required by cargo clippy
        } else {
            return Err(SPDM_STATUS_UNSUPPORTED_CAP);
        }
        cnt += 0u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // reserved 2 bytes
        Ok(cnt)
    }
    fn spdm_read(
        context: &mut SpdmContext,
        r: &mut Reader,
    ) -> Option<SecuredMessageGeneralOpaqueDataHeader> {
        let total_elements: u8;

        if context.negotiate_info.spdm_version_sel.get_u8() < SpdmVersion::SpdmVersion12.get_u8() {
            let spec_id = u32::read(r)?;
            if spec_id != DMTF_SPEC_ID {
                return None;
            }
            let opaque_version = u8::read(r)?;
            if opaque_version != DMTF_OPAQUE_VERSION {
                return None;
            }
            total_elements = u8::read(r)?;
            u16::read(r)?; // reserved 2 bytes
        } else if context.negotiate_info.opaque_data_support == SpdmOpaqueSupport::OPAQUE_DATA_FMT1
        {
            total_elements = u8::read(r)?;
            u8::read(r)?; // reserved 3 bytes
            u8::read(r)?;
            u8::read(r)?;
        } else {
            return None;
        }

        Some(SecuredMessageGeneralOpaqueDataHeader { total_elements })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpaqueElementDMTFVersionSelection {
    pub selected_version: SecuredMessageVersion,
}

impl SpdmCodec for OpaqueElementDMTFVersionSelection {
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ID: Shall be zero to indicate DMTF.
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // VendorLen: Shall be zero. Note: DMTF does not have a vendor registry.
        cnt += 4u16.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // OpaqueElementDataLen: Shall be the length of the remaining bytes excluding the AlignPadding.
        cnt += 1u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // SMDataVersion: Shall identify the format of the remaining bytes. The value shall be one.
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // SMDataID: Shall be a value of zero to indicate Secured Message version selection.
        cnt += self
            .selected_version
            .spdm_encode(context, bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        Ok(cnt)
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
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // ID: Shall be zero to indicate DMTF.
        cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // VendorLen: Shall be zero. Note: DMTF does not have a vendor registry.
        let opaque_element_data_len: u16 = 3 + 2 * self.secured_msg_vers.version_count as u16; // SMDataVersion + SMDataID + self.secured_msg_vers.version_count + 2 * count
        cnt += opaque_element_data_len
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // OpaqueElementDataLen: Shall be the length of the remaining bytes excluding the AlignPadding.
        cnt += 1u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // SMDataVersion: Shall identify the format of the remaining bytes. The value shall be one.
        cnt += 1u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?; // SMDataID: Shall be a value of one to indicate Supported version list.
        cnt += self.secured_msg_vers.spdm_encode(context, bytes)?;

        // padding
        let filled = bytes.used();
        let aligned_len = (filled + 3) & (!3);
        let align_padding = aligned_len - filled;
        for _i in 0..align_padding {
            cnt += 0u8.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
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
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .secured_message_general_opaque_data_header
            .spdm_encode(context, bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for index in 0..self
            .secured_message_general_opaque_data_header
            .total_elements as usize
        {
            cnt += self.opaque_element_dmtf_version_selection_list[index]
                .spdm_encode(context, bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
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
    fn spdm_encode(
        &self,
        context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .secured_message_general_opaque_data_header
            .spdm_encode(context, bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for index in 0..self
            .secured_message_general_opaque_data_header
            .total_elements as usize
        {
            cnt += self.opaque_element_dmtf_supported_version_list[index]
                .spdm_encode(context, bytes)
                .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
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
    pub data: [u8; MAX_SPDM_OPAQUE_SIZE],
}
impl Default for SpdmOpaqueStruct {
    fn default() -> SpdmOpaqueStruct {
        SpdmOpaqueStruct {
            data_size: 0,
            data: [0u8; MAX_SPDM_OPAQUE_SIZE],
        }
    }
}

impl SpdmCodec for SpdmOpaqueStruct {
    fn spdm_encode(
        &self,
        _context: &mut SpdmContext,
        bytes: &mut Writer,
    ) -> Result<usize, SpdmStatus> {
        let mut cnt = 0usize;
        cnt += self
            .data_size
            .encode(bytes)
            .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        for d in self.data.iter().take(self.data_size as usize) {
            cnt += d.encode(bytes).map_err(|_| SPDM_STATUS_BUFFER_FULL)?;
        }
        Ok(cnt)
    }
    fn spdm_read(_context: &mut SpdmContext, r: &mut Reader) -> Option<SpdmOpaqueStruct> {
        let data_size = u16::read(r)?;
        if data_size > MAX_SPDM_OPAQUE_SIZE as u16 {
            return None;
        }
        let mut data = [0u8; MAX_SPDM_OPAQUE_SIZE];
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
        const OPAQUE_DATA_FMT1 = 0b0000_0010;
        const VALID_MASK = Self::OPAQUE_DATA_FMT1.bits;
    }
}

impl Codec for SpdmOpaqueSupport {
    fn encode(&self, bytes: &mut Writer) -> Result<usize, codec::EncodeErr> {
        self.bits().encode(bytes)
    }

    fn read(r: &mut Reader) -> Option<SpdmOpaqueSupport> {
        let bits = u8::read(r)?;

        SpdmOpaqueSupport::from_bits(bits)
    }
}

impl SpdmOpaqueSupport {
    /// return true if no more than one is selected
    /// return false if two or more is selected
    pub fn is_no_more_than_one_selected(&self) -> bool {
        self.bits() == 0 || self.bits() & (self.bits() - 1) == 0
    }

    pub fn is_valid(&self) -> bool {
        (self.bits & Self::VALID_MASK.bits) != 0
    }

    pub fn is_valid_one_select(&self) -> bool {
        self.is_no_more_than_one_selected() && self.is_valid()
    }
}
