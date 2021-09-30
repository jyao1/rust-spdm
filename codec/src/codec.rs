// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::fmt::Debug;

/// Read from a byte slice.
pub struct Reader<'a> {
    buf: &'a [u8],
    offs: usize,
}

impl<'a> Reader<'a> {
    pub fn init(bytes: &[u8]) -> Reader {
        Reader {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn rest(&mut self) -> &[u8] {
        let ret = &self.buf[self.offs..];
        self.offs = self.buf.len();
        ret
    }

    pub fn take(&mut self, len: usize) -> Option<&[u8]> {
        if self.left() < len {
            return None;
        }

        let current = self.offs;
        self.offs += len;
        Some(&self.buf[current..current + len])
    }

    pub fn any_left(&self) -> bool {
        self.offs < self.buf.len()
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn sub(&mut self, len: usize) -> Option<Reader> {
        self.take(len).map(Reader::init)
    }
}

/// Write to a byte slice.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    offs: usize,
}

impl<'a> Writer<'a> {
    pub fn init(bytes: &mut [u8]) -> Writer {
        Writer {
            buf: bytes,
            offs: 0,
        }
    }

    pub fn extend_from_slice(&mut self, value: &[u8]) -> Option<usize> {
        if self.left() < value.len() {
            return None;
        }
        let added = value.len();
        for (i, v) in value.iter().enumerate().take(added) {
            self.buf[self.offs + i] = *v;
        }
        self.offs += added;
        Some(added)
    }

    pub fn push(&mut self, value: u8) -> Option<u8> {
        if self.left() < 1 {
            return None;
        }
        self.buf[self.offs] = value;
        self.offs += 1;
        Some(value)
    }

    pub fn left(&self) -> usize {
        self.buf.len() - self.offs
    }

    pub fn used(&self) -> usize {
        self.offs
    }

    pub fn used_slice(&self) -> &[u8] {
        &self.buf[..self.offs]
    }

    pub fn mut_used_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..self.offs]
    }
}

/// Things we can encode and read from a Reader.
pub trait Codec: Debug + Sized {
    /// Encode yourself by appending onto `bytes`.
    /// TBD: Encode may fail if the caller encodes too many data that exceeds the max size of preallocated slice.
    /// Should we assert() here? or return to caller to let the caller handle it?
    fn encode(&self, bytes: &mut Writer);

    /// Decode yourself by fiddling with the `Reader`.
    /// Return Some if it worked, None if not.
    fn read(_: &mut Reader) -> Option<Self>;

    /// Convenience function to get the results of `encode()`.
    // fn get_encoding(&self) -> Writer {
    //     let mut ret = Vec::new();
    //     self.encode(&mut ret);
    //     ret
    // }

    /// Read one of these from the front of `bytes` and
    /// return it.
    fn read_bytes(bytes: &[u8]) -> Option<Self> {
        let mut rd = Reader::init(bytes);
        Self::read(&mut rd)
    }
}

// Encoding functions.
pub fn decode_u8(bytes: &[u8]) -> Option<u8> {
    Some(bytes[0])
}

impl Codec for u8 {
    fn encode(&self, bytes: &mut Writer) {
        bytes.push(*self);
    }
    fn read(r: &mut Reader) -> Option<u8> {
        r.take(1).and_then(decode_u8)
    }
}

pub fn put_u16(v: u16, out: &mut [u8]) {
    out[0] = v as u8;
    out[1] = (v >> 8) as u8;
}

pub fn decode_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from(bytes[0]) | (u16::from(bytes[1]) << 8))
}

impl Codec for u16 {
    fn encode(&self, bytes: &mut Writer) {
        let mut b16 = [0u8; 2];
        put_u16(*self, &mut b16);
        bytes.extend_from_slice(&b16);
    }

    fn read(r: &mut Reader) -> Option<u16> {
        r.take(2).and_then(decode_u16)
    }
}

// Make a distinct type for u24, even though it's a u32 underneath
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, Default)]
pub struct u24(u32);

impl u24 {
    pub fn new(v: u32) -> u24 {
        assert_eq!(v >> 24, 0);
        u24(v)
    }

    pub fn get(&self) -> u32 {
        self.0
    }

    fn decode(bytes: &[u8]) -> Option<u24> {
        Some(u24(u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)))
    }
}

impl Codec for u24 {
    fn encode(&self, bytes: &mut Writer) {
        bytes.push(self.0 as u8);
        bytes.push((self.0 >> 8) as u8);
        bytes.push((self.0 >> 16) as u8);
    }

    fn read(r: &mut Reader) -> Option<u24> {
        r.take(3).and_then(u24::decode)
    }
}

pub fn decode_u32(bytes: &[u8]) -> Option<u32> {
    Some(
        u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 24),
    )
}

impl Codec for u32 {
    fn encode(&self, bytes: &mut Writer) {
        bytes.push(*self as u8);
        bytes.push((*self >> 8) as u8);
        bytes.push((*self >> 16) as u8);
        bytes.push((*self >> 24) as u8);
    }

    fn read(r: &mut Reader) -> Option<u32> {
        r.take(4).and_then(decode_u32)
    }
}

pub fn put_u64(v: u64, bytes: &mut [u8]) {
    bytes[0] = v as u8;
    bytes[1] = (v >> 8) as u8;
    bytes[2] = (v >> 16) as u8;
    bytes[3] = (v >> 24) as u8;
    bytes[4] = (v >> 32) as u8;
    bytes[5] = (v >> 40) as u8;
    bytes[6] = (v >> 48) as u8;
    bytes[7] = (v >> 56) as u8;
}

pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    Some(
        u64::from(bytes[0])
            | (u64::from(bytes[1]) << 8)
            | (u64::from(bytes[2]) << 16)
            | (u64::from(bytes[3]) << 24)
            | (u64::from(bytes[4]) << 32)
            | (u64::from(bytes[5]) << 40)
            | (u64::from(bytes[6]) << 48)
            | (u64::from(bytes[7]) << 56),
    )
}

impl Codec for u64 {
    fn encode(&self, bytes: &mut Writer) {
        let mut b64 = [0u8; 8];
        put_u64(*self, &mut b64);
        bytes.extend_from_slice(&b64);
    }

    fn read(r: &mut Reader) -> Option<u64> {
        r.take(8).and_then(decode_u64)
    }
}

#[cfg(test)]
mod tests {
    use crate::codec::Codec;
    use crate::codec::{Reader, Writer};
    use crate::u24;

    #[test]
    fn test_u64() {
        let u8_slice = &mut [0u8; 8];
        u8_slice[1] = 1;
        {
            let mut writer = Writer::init(u8_slice);
            let value = 100u64;
            value.encode(&mut writer);
        }

        let mut reader = Reader::init(u8_slice);
        assert_eq!(8, reader.left());
        assert_eq!(u64::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_u32() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 100u32;
        value.encode(&mut witer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(u32::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_u16() {
        let u8_slice = &mut [0u8; 2];
        let mut witer = Writer::init(u8_slice);
        let value = 10u16;
        value.encode(&mut witer);

        let mut reader = Reader::init(u8_slice);
        assert_eq!(2, reader.left());
        assert_eq!(u16::read(&mut reader).unwrap(), 10);
    }
    #[test]
    fn test_u24() {
        let u8_slice = &mut [0u8; 3];
        let mut witer = Writer::init(u8_slice);
        let value = u24::new(100);
        value.encode(&mut witer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(3, reader.left());
        assert_eq!(u24::read(&mut reader).unwrap().0, u24::new(100).0);
    }
    #[test]
    #[should_panic]
    fn test_u24_max_size() {
        let _ = u24::new(1 << 24);
    }
    #[test]
    fn test_u8() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 100u8;
        value.encode(&mut witer);
        let mut reader = Reader::init(u8_slice);
        assert_eq!(4, reader.left());
        assert_eq!(u8::read(&mut reader).unwrap(), 100);
    }
    #[test]
    fn test_case0_rest() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 0xAA5555AAu32;
        value.encode(&mut witer);
        let mut reader = Reader::init(u8_slice);
        let rust_ret = reader.rest();
        assert_eq!(rust_ret[0], 0xAA);
        assert_eq!(rust_ret[1], 0x55);
        assert_eq!(rust_ret[2], 0x55);
        assert_eq!(rust_ret[3], 0xAA);
    }
    #[test]
    fn test_case0_any_left() {
        let u8_slice = &mut [0u8; 4];
        let reader = Reader {
            buf: u8_slice,
            offs: 0,
        };
        assert_eq!(reader.any_left(), true);
    }
    #[test]
    fn test_case1_any_left() {
        let u8_slice = &mut [0u8; 4];
        let reader = Reader {
            buf: u8_slice,
            offs: 4,
        };
        assert_eq!(reader.any_left(), false);
    }
    #[test]
    fn test_case0_read_bytes() {
        let u8_slice = &mut [0u8; 4];
        let mut witer = Writer::init(u8_slice);
        let value = 0xAA5555AAu32;
        value.encode(&mut witer);
        assert_eq!(u32::read_bytes(u8_slice).unwrap(), 0xAA5555AAu32);
    }
    #[test]
    fn test_case0_sub() {
        let u8_slice = &mut [100u8; 4];
        let mut reader = Reader {
            buf: u8_slice,
            offs: 4,
        };
        assert_eq!(reader.sub(4).is_none(), true);
    }
}
