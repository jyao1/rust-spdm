// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

extern crate alloc;
use alloc::boxed::Box;

use spdmlib::crypto::{SpdmDhe, SpdmDheKeyExchange};
use spdmlib::protocol::{
    SpdmDheAlgo, SpdmDheExchangeStruct, SpdmDheFinalKeyStruct, SPDM_MAX_DHE_KEY_SIZE,
};

pub static DEFAULT: SpdmDhe = SpdmDhe {
    generate_key_pair_cb: generate_key_pair,
};

use core::ffi::{c_int, c_uchar, c_void};

use super::ffi::{
    spdm_ecdh_compute_shared_p256, spdm_ecdh_compute_shared_p384, spdm_ecdh_gen_public_p256,
    spdm_ecdh_gen_public_p384,
};

fn generate_key_pair(
    dhe_algo: SpdmDheAlgo,
) -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange>)> {
    match dhe_algo {
        SpdmDheAlgo::SECP_256_R1 => SpdmDheKeyExchangeP256::generate_key_pair(),
        SpdmDheAlgo::SECP_384_R1 => SpdmDheKeyExchangeP384::generate_key_pair(),
        SpdmDheAlgo::SECP_521_R1 => None,
        SpdmDheAlgo::FFDHE_2048 => None,
        SpdmDheAlgo::FFDHE_3072 => None,
        SpdmDheAlgo::FFDHE_4096 => None,
        _ => None,
    }
}

extern "C" fn f_rng(_rng_state: *mut c_void, output: *mut c_uchar, len: usize) -> c_int {
    use core::arch::x86_64::_rdrand64_step;
    let mut remain = len;
    while remain > 8 {
        remain -= 8;
        let mut count = 0;
        unsafe {
            while _rdrand64_step(&mut *(output.add(remain) as *mut u64)) != 1 || count > 5 {
                count += 1;
            }
            if count > 5 {
                return 1;
            }
        }
    }
    let mut buf = [0u8; 8];
    unsafe {
        let mut count = 0;
        while _rdrand64_step(&mut *(buf.as_mut_ptr() as *mut u64)) != 1 || count > 5 {
            count += 1;
        }
        if count > 5 {
            return 1;
        }
        core::slice::from_raw_parts_mut(output, remain).copy_from_slice(&buf[0..remain]);
    }
    0
}

const MAX_PRIVATE_KEY_LEN: usize = 512;
struct EphemeralPrivateKey {
    pub key_len: usize,
    pub key: [u8; MAX_PRIVATE_KEY_LEN],
}

struct SpdmDheKeyExchangeP256(EphemeralPrivateKey);

impl SpdmDheKeyExchangeP256 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange>)> {
        let mut private_key = EphemeralPrivateKey {
            key_len: MAX_PRIVATE_KEY_LEN,
            key: [0u8; MAX_PRIVATE_KEY_LEN],
        };
        let mut public_key = SpdmDheExchangeStruct::default();
        unsafe {
            private_key.key_len = MAX_PRIVATE_KEY_LEN;
            public_key.data_size = 512;
            let mut data_size = 512usize;
            let ret = spdm_ecdh_gen_public_p256(
                public_key.data.as_mut_ptr(),
                &mut data_size,
                private_key.key.as_mut_ptr(),
                &mut private_key.key_len,
                f_rng as *const c_void,
                core::ptr::null(),
            );
            if ret == 0 {
                public_key.data_size = data_size as u16;
                let public_key = mbedtls_public_key_to_spdm_public_key(public_key);
                let res: Box<dyn SpdmDheKeyExchange> = Box::new(Self(private_key));
                Some((public_key, res))
            } else {
                None
            }
        }
    }
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP256 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let mut final_key = SpdmDheFinalKeyStruct::default();
        let peer_pub_key = peer_pub_key.clone();
        let peer_pub_key = spdm_public_key_to_mbedtls_public_key(peer_pub_key);
        unsafe {
            let mut final_key_size = SPDM_MAX_DHE_KEY_SIZE;
            let res = spdm_ecdh_compute_shared_p256(
                self.0.key.as_ptr(),
                self.0.key_len,
                peer_pub_key.data.as_ptr(),
                peer_pub_key.data_size as usize,
                final_key.data.as_mut_ptr(),
                &mut final_key_size,
                f_rng as *const c_void,
                core::ptr::null(),
            );
            if res == 0 {
                final_key.data_size = final_key_size as u16;
                Some(final_key)
            } else {
                None
            }
        }
    }
}

struct SpdmDheKeyExchangeP384(EphemeralPrivateKey);

impl SpdmDheKeyExchangeP384 {
    fn generate_key_pair() -> Option<(SpdmDheExchangeStruct, Box<dyn SpdmDheKeyExchange>)> {
        let mut private_key = EphemeralPrivateKey {
            key_len: MAX_PRIVATE_KEY_LEN,
            key: [0u8; MAX_PRIVATE_KEY_LEN],
        };
        let mut public_key = SpdmDheExchangeStruct::default();
        unsafe {
            private_key.key_len = MAX_PRIVATE_KEY_LEN;
            public_key.data_size = 512;
            let mut data_size = 512usize;
            let ret = spdm_ecdh_gen_public_p384(
                public_key.data.as_mut_ptr(),
                &mut data_size,
                private_key.key.as_mut_ptr(),
                &mut private_key.key_len,
                f_rng as *const c_void,
                core::ptr::null(),
            );
            if ret == 0 {
                // convert mbedtls public_key to spdm public key format
                public_key.data_size = data_size as u16;
                let public_key = mbedtls_public_key_to_spdm_public_key(public_key);
                let res: Box<dyn SpdmDheKeyExchange> = Box::new(Self(private_key));
                Some((public_key, res))
            } else {
                None
            }
        }
    }
}

fn mbedtls_public_key_to_spdm_public_key(origin: SpdmDheExchangeStruct) -> SpdmDheExchangeStruct {
    let mut key = SpdmDheExchangeStruct {
        data_size: origin.data_size - 1,
        data: [0u8; SPDM_MAX_DHE_KEY_SIZE],
    };
    key.data[0..(key.data_size as usize)].copy_from_slice(&origin.as_ref()[1..]);
    key
}

fn spdm_public_key_to_mbedtls_public_key(origin: SpdmDheExchangeStruct) -> SpdmDheExchangeStruct {
    let mut key = SpdmDheExchangeStruct::default();
    key.data[0] = 0x04;
    key.data_size = origin.data_size + 1;
    key.data[1..(key.data_size as usize)].copy_from_slice(origin.as_ref());
    key
}

impl SpdmDheKeyExchange for SpdmDheKeyExchangeP384 {
    fn compute_final_key(
        self: Box<Self>,
        peer_pub_key: &SpdmDheExchangeStruct,
    ) -> Option<SpdmDheFinalKeyStruct> {
        let peer_pub_key = peer_pub_key.clone();
        let peer_pub_key = spdm_public_key_to_mbedtls_public_key(peer_pub_key);
        let mut final_key = SpdmDheFinalKeyStruct::default();
        unsafe {
            let mut final_key_size = SPDM_MAX_DHE_KEY_SIZE;
            let res = spdm_ecdh_compute_shared_p384(
                self.0.key.as_ptr(),
                self.0.key_len,
                peer_pub_key.data.as_ptr(),
                peer_pub_key.data_size as usize,
                final_key.data.as_mut_ptr(),
                &mut final_key_size,
                f_rng as *const c_void,
                core::ptr::null(),
            );
            if res == 0 {
                final_key.data_size = final_key_size as u16;
                Some(final_key)
            } else {
                None
            }
        }
    }
}

#[cfg(all(test,))]
mod tests {
    use super::*;

    #[test]
    fn test_case0_dhe() {
        for dhe_algo in [SpdmDheAlgo::SECP_256_R1, SpdmDheAlgo::SECP_384_R1].iter() {
            let (exchange1, private1) = generate_key_pair(*dhe_algo).unwrap();
            let (exchange2, private2) = generate_key_pair(*dhe_algo).unwrap();

            let peer1 = private1.compute_final_key(&exchange2).unwrap();
            let peer2 = private2.compute_final_key(&exchange1).unwrap();

            assert_eq!(peer1.as_ref(), peer2.as_ref());
        }
    }
    #[test]
    fn test_case1_dhe() {
        for dhe_algo in [
            SpdmDheAlgo::SECP_521_R1,
            SpdmDheAlgo::FFDHE_2048,
            SpdmDheAlgo::FFDHE_3072,
            SpdmDheAlgo::FFDHE_4096,
            SpdmDheAlgo::empty(),
        ]
        .iter()
        {
            assert_eq!(generate_key_pair(*dhe_algo).is_none(), true);
        }
    }
}
