// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use core::ffi::{c_int, c_uchar, c_void};

extern "C" {
    pub fn spdm_aead_aes_gcm_encrypt(
        key: *const c_uchar,
        key_size: usize,
        iv: *const c_uchar,
        iv_size: usize,
        a_data: *const c_uchar,
        a_data_size: usize,
        data_in: *const c_uchar,
        data_in_size: usize,
        tag_out: *mut c_uchar,
        tag_size: usize,
        data_out: *mut c_uchar,
        data_out_size: *mut usize,
    ) -> c_int;

    pub fn spdm_aead_aes_gcm_decrypt(
        key: *const c_uchar,
        key_size: usize,
        iv: *const c_uchar,
        iv_size: usize,
        a_data: *const c_uchar,
        a_data_size: usize,
        data_in: *const c_uchar,
        data_in_size: usize,
        tag: *const c_uchar,
        tag_size: usize,
        data_out: *mut c_uchar,
        data_out_size: *mut usize,
    ) -> c_int;

    pub fn spdm_aead_chacha20_poly1305_encrypt(
        key: *const c_uchar,
        key_size: usize,
        iv: *const c_uchar,
        iv_size: usize,
        a_data: *const c_uchar,
        a_data_size: usize,
        data_in: *const c_uchar,
        data_in_size: usize,
        tag: *mut c_uchar,
        tag_size: usize,
        data_out: *mut c_uchar,
        data_out_size: *mut usize,
    ) -> c_int;

    pub fn spdm_aead_chacha20_poly1305_decrypt(
        key: *const c_uchar,
        key_size: usize,
        iv: *const c_uchar,
        iv_size: usize,
        a_data: *const c_uchar,
        a_data_size: usize,
        data_in: *const c_uchar,
        data_in_size: usize,
        tag: *const c_uchar,
        tag_size: usize,
        data_out: *mut c_uchar,
        data_out_size: *mut usize,
    ) -> c_int;

    pub fn spdm_pk_verify(
        md_type: c_int,
        cert: *const c_uchar,
        cert_size: usize,
        data: *const c_uchar,
        data_size: usize,
        signature: *const c_uchar,
        signature_size: usize,
    ) -> c_int;

    pub fn spdm_rsa_pss_verify(
        md_type: c_int,
        cert: *const c_uchar,
        cert_size: usize,
        data: *const c_uchar,
        data_size: usize,
        signature: *const c_uchar,
        signature_size: usize,
    ) -> c_int;

    pub fn spdm_verify_cert_chain(certchain: *const c_uchar, certchain_size: usize) -> c_int;

    pub fn spdm_ecdh_compute_shared_p256(
        private_key: *const c_uchar,
        private_key_len: usize,
        peer_public_key: *const c_uchar,
        peer_public_key_len: usize,
        shared_key: *mut c_uchar,
        shared_ken_len: *mut usize,
        random_fn: *const c_void,
        random_fn_param: *const c_void,
    ) -> c_int;

    pub fn spdm_ecdh_gen_public_p256(
        public_key: *mut c_uchar,
        public_key_len: *mut usize,
        private_key: *mut c_uchar,
        private_key_len: *mut usize,
        random_fn: *const c_void,
        random_fn_param: *const c_void,
    ) -> c_int;

    pub fn spdm_ecdh_compute_shared_p384(
        private_key: *const c_uchar,
        private_key_len: usize,
        peer_public_key: *const c_uchar,
        peer_public_key_len: usize,
        shared_key: *mut c_uchar,
        shared_ken_len: *mut usize,
        random_fn: *const c_void,
        random_fn_param: *const c_void,
    ) -> c_int;

    pub fn spdm_ecdh_gen_public_p384(
        public_key: *mut c_uchar,
        public_key_len: *mut usize,
        private_key: *mut c_uchar,
        private_key_len: *mut usize,
        random_fn: *const c_void,
        random_fn_param: *const c_void,
    ) -> c_int;

    pub fn mbedtls_sha256(
        data: *const c_uchar,
        data_len: usize,
        digest: *mut c_uchar,
        is224: c_int,
    ) -> c_int;
    pub fn mbedtls_sha512(
        data: *const c_uchar,
        data_len: usize,
        digest: *mut c_uchar,
        is384: c_int,
    ) -> c_int;

    pub fn mbedtls_md_info_from_type(md_type: c_int) -> *mut c_void;

    pub fn mbedtls_hkdf_expand(
        md: *const c_void,
        prk: *const c_uchar,
        prk_len: usize,
        info: *const c_uchar,
        info_len: usize,
        okm: *mut c_uchar,
        okm_len: usize,
    ) -> c_int;

    pub fn mbedtls_md_hmac(
        md_info: *const c_void,
        key: *const c_uchar,
        keylen: usize,
        input: *const c_uchar,
        ilen: usize,
        output: *mut c_uchar,
    ) -> c_int;

    pub fn mbedtls_md_get_size(md_info: *const c_void) -> c_uchar;
}
