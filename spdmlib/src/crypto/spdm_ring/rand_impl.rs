// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crate::crypto::SpdmCryptoRandom;
use crate::error::SpdmResult;

pub static DEFAULT: SpdmCryptoRandom = SpdmCryptoRandom {
    get_random_cb: get_random,
};

fn get_random(data: &mut [u8]) -> SpdmResult<usize> {
    let rng = ring::rand::SystemRandom::new();

    let mut len = data.len();
    while len > 0 {
        let rand_data: [u8; 64] = ring::rand::generate(&rng).unwrap().expose();
        if len > 64 {
            data.copy_from_slice(&rand_data);
            len -= 64;
        } else {
            data.copy_from_slice(&rand_data[0..len]);
            break;
        }
    }

    Ok(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case0_get_random() {
        let data = &mut [100u8; 16];
        let data_len = get_random(data);

        match data_len {
            Ok(16) => {assert!(true)}
            _ => {
                panic!()
            }
        }
    }
    #[test]
    #[should_panic]
    fn test_case1_get_random() {
        let data = &mut [100u8; 80];
        let data_len = get_random(data);

        match data_len {
            Ok(16) => {assert!(true)}
            _ => {
                panic!()
            }
        }
    }
}
