// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![allow(unused)]

use super::{USE_ECDH, USE_ECDSA};
use spdmlib::common;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::config;
use spdmlib::protocol::*;
use std::path::PathBuf;

/// Get test_key Dir
pub fn get_test_key_directory() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = crate_dir.parent().expect("can't find parent dir");
    crate_dir.to_path_buf()
}

/// Create requester config and provision info
pub fn req_create_info() -> common::SpdmProvisionInfo {
    let mut peer_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/ca.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/ca.cert.der")
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/inter.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/inter.cert.der")
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/end_responder.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/end_responder.cert.der")
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    log::info!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    peer_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    peer_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    peer_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    peer_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: None,
        my_cert_chain: None,
        peer_cert_chain_data: Some(peer_cert_chain_data),
        peer_cert_chain_root_hash: None,
        default_version: SpdmVersion::SpdmVersion12,
    };

    provision_info
}

pub fn rsp_create_info() -> common::SpdmProvisionInfo {
    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let crate_dir = get_test_key_directory();
    let ca_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/ca.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/ca.cert.der")
    };
    log::info!("{}", ca_file_path.display());
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/inter.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/inter.cert.der")
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        crate_dir.join("test_key/EcP384/end_responder.cert.der")
    } else {
        crate_dir.join("test_key/Rsa3072/end_responder.cert.der")
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    log::info!(
        "total cert size - {:?} = {:?} + {:?} + {:?}",
        ca_len + inter_len + leaf_len,
        ca_len,
        inter_len,
        leaf_len
    );
    my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
    my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
    my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
    my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
        .copy_from_slice(leaf_cert.as_ref());

    let provision_info = common::SpdmProvisionInfo {
        my_cert_chain_data: Some(my_cert_chain_data),
        my_cert_chain: None,
        peer_cert_chain_data: None,
        peer_cert_chain_root_hash: None,
        default_version: SpdmVersion::SpdmVersion12,
    };

    provision_info
}
