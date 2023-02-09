use codec::{Codec, Reader, Writer};

bitflags! {
    #[derive(Default)]
    pub struct SpdmRequestCapabilityFlags: u32 {
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_CAP_MASK = Self::PSK_CAP.bits | 0b0000_1000_0000_0000;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP = 0b0000_0010_0000_0000_0000_0000;
    }
}

impl Codec for SpdmRequestCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmRequestCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmRequestCapabilityFlags::from_bits(bits)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct SpdmResponseCapabilityFlags: u32 {
        const CACHE_CAP = 0b0000_0001;
        const CERT_CAP = 0b0000_0010;
        const CHAL_CAP = 0b0000_0100;
        const MEAS_CAP_NO_SIG = 0b0000_1000;
        const MEAS_CAP_SIG = 0b0001_0000;
        const MEAS_CAP_MASK = Self::MEAS_CAP_NO_SIG.bits | Self::MEAS_CAP_SIG.bits;
        const MEAS_FRESH_CAP = 0b0010_0000;
        const ENCRYPT_CAP = 0b0100_0000;
        const MAC_CAP = 0b1000_0000;
        const MUT_AUTH_CAP = 0b0000_0001_0000_0000;
        const KEY_EX_CAP = 0b0000_0010_0000_0000;
        const PSK_CAP = 0b0000_0100_0000_0000;
        const PSK_CAP_WITH_CONTEXT = 0b0000_1000_0000_0000;
        const PSK_CAP_MASK = Self::PSK_CAP.bits | Self::PSK_CAP_WITH_CONTEXT.bits;
        const ENCAP_CAP = 0b0001_0000_0000_0000;
        const HBEAT_CAP = 0b0010_0000_0000_0000;
        const KEY_UPD_CAP = 0b0100_0000_0000_0000;
        const HANDSHAKE_IN_THE_CLEAR_CAP = 0b1000_0000_0000_0000;
        const PUB_KEY_ID_CAP = 0b0000_0001_0000_0000_0000_0000;
        const CHUNK_CAP = 0b0000_0010_0000_0000_0000_0000;

        // responder only
        const ALIAS_CERT_CAP = 0b0000_0100_0000_0000_0000_0000;
        const SET_CERT_CAP = 0b0000_1000_0000_0000_0000_0000;
        const CSR_CAP = 0b0001_0000_0000_0000_0000_0000;
        const CERT_INSTALL_RESET_CAP = 0b0010_0000_0000_0000_0000_0000;
    }
}

impl Codec for SpdmResponseCapabilityFlags {
    fn encode(&self, bytes: &mut Writer) {
        self.bits().encode(bytes);
    }

    fn read(r: &mut Reader) -> Option<SpdmResponseCapabilityFlags> {
        let bits = u32::read(r)?;

        SpdmResponseCapabilityFlags::from_bits(bits)
    }
}
