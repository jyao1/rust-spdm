// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::env;

fn main() {
    mbedtls_support();
}

fn mbedtls_support() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut b = cc::Build::new();
    b.include("mbedtls/include")
        .file("src/aead_impl_chacha20_poly1305.c")
        .file("src/aead_impl_gcm.c")
        .file("src/dhe_impl.c")
        .file("src/asym_verify_impl.c")
        .file("src/cert_operation_impl.c");
    if !(os == "none" || os == "uefi" || os == "windows") {
        b.pic(true);
    }
    b.compile("spdmcrypto");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedx509");
    println!("cargo:rustc-link-lib=static=spdmcrypto");
    println!("cargo:rustc-link-search=native={}/mbedtls/library", dir);
}
