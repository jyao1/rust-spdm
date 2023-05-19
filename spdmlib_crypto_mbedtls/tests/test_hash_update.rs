// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#[cfg(feature = "hashed-transcript-data")]
mod test {
    #[test]
    fn test_hash_update() {
        use spdmlib::crypto::hash;
        use spdmlib::protocol::SpdmBaseHashAlgo;
        hash::register(spdmlib_crypto_mbedtls::hash_impl::DEFAULT.clone());

        // Len = 8
        // Msg = d3
        // MD = 28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1
        let mut ctx = hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_256).unwrap();
        let data = &from_hex("d3").unwrap();
        let md =
            &from_hex("28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1").unwrap();
        hash::hash_ctx_update(&mut ctx, data).unwrap();
        let res = hash::hash_ctx_finalize(ctx).unwrap();
        assert_eq!(res.as_ref(), md);

        // Len = 512
        // Msg = 5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509
        // MD = 42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa
        let mut ctx2 = hash::hash_ctx_init(SpdmBaseHashAlgo::TPM_ALG_SHA_256).unwrap();
        let data = &from_hex("5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509").unwrap();
        let md =
            &from_hex("42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa").unwrap();
        hash::hash_ctx_update(&mut ctx2, &data.as_slice()[0..10]).unwrap();
        let mut ctx3 = ctx2.clone();
        hash::hash_ctx_update(&mut ctx2, &data[10..]).unwrap();
        hash::hash_ctx_update(&mut ctx3, &data[10..]).unwrap();
        let res = hash::hash_ctx_finalize(ctx2).unwrap();
        let res3 = hash::hash_ctx_finalize(ctx3).unwrap();
        assert_eq!(res.as_ref(), md);
        assert_eq!(res3.as_ref(), md);
    }

    fn from_hex(hex_str: &str) -> Result<Vec<u8>, String> {
        if hex_str.len() % 2 != 0 {
            return Err(String::from(
                "Hex string does not have an even number of digits",
            ));
        }

        let mut result = Vec::with_capacity(hex_str.len() / 2);
        for digits in hex_str.as_bytes().chunks(2) {
            let hi = from_hex_digit(digits[0])?;
            let lo = from_hex_digit(digits[1])?;
            result.push((hi * 0x10) | lo);
        }
        Ok(result)
    }

    fn from_hex_digit(d: u8) -> Result<u8, String> {
        use core::ops::RangeInclusive;
        const DECIMAL: (u8, RangeInclusive<u8>) = (0, b'0'..=b'9');
        const HEX_LOWER: (u8, RangeInclusive<u8>) = (10, b'a'..=b'f');
        const HEX_UPPER: (u8, RangeInclusive<u8>) = (10, b'A'..=b'F');
        for (offset, range) in &[DECIMAL, HEX_LOWER, HEX_UPPER] {
            if range.contains(&d) {
                return Ok(d - range.start() + offset);
            }
        }
        Err(format!("Invalid hex digit '{}'", d as char))
    }
}
