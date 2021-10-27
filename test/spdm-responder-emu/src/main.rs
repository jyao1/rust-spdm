// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use log::LevelFilter;
use simple_logger::SimpleLogger;

use std::net::{TcpListener, TcpStream};
use std::u32;

use codec::{Codec, Reader, Writer};
use common::SpdmTransportEncap;
use mctp_transport::MctpTransportEncap;
use pcidoe_transport::{
    PciDoeDataObjectType, PciDoeMessageHeader, PciDoeTransportEncap, PciDoeVendorId,
};
use spdm_emu::crypto_callback::ASYM_SIGN_IMPL;
use spdm_emu::socket_io_transport::SocketIoTransport;
use spdm_emu::spdm_emu::*;
use spdmlib::msgs::*;
use spdmlib::{common, responder};

fn process_socket_message(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
    buffer: &[u8],
) -> bool {
    if buffer.len() < SOCKET_HEADER_LEN {
        return false;
    }
    let mut reader = Reader::init(&buffer[..SOCKET_HEADER_LEN]);
    let socket_header = SpdmSocketHeader::read(&mut reader).unwrap();

    let res = (
        socket_header.transport_type.to_be(),
        socket_header.command.to_be(),
        &buffer[SOCKET_HEADER_LEN..],
    );

    match socket_header.command.to_be() {
        SOCKET_SPDM_COMMAND_TEST => {
            send_hello(stream, transport_encap, res.0);
            true
        }
        SOCKET_SPDM_COMMAND_STOP => {
            send_stop(stream, transport_encap, res.0);
            false
        }
        SOCKET_SPDM_COMMAND_NORMAL => true,
        _ => {
            if USE_PCIDOE {
                send_pci_discovery(stream, transport_encap, res.0, buffer)
            } else {
                send_unknown(stream, transport_encap, res.0);
                false
            }
        }
    }
}

// A new logger enables the user to choose log level by setting a `SPDM_LOG` environment variable.
// Use the `Trace` level by default.
fn new_logger_from_env() -> SimpleLogger {
    let level = match std::env::var("SPDM_LOG") {
        Ok(x) => match x.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            _ => LevelFilter::Error,
        },
        _ => LevelFilter::Trace,
    };

    SimpleLogger::new().with_level(level)
}

fn main() {
    new_logger_from_env().init().unwrap();

    let listener = TcpListener::bind("127.0.0.1:2323").expect("Couldn't bind to the server");
    println!("server start!");

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let mctp_transport_encap = &mut MctpTransportEncap {};

    for stream in listener.incoming() {
        let mut stream = stream.expect("Read stream error!");
        println!("new connection!");
        let mut need_continue;
        loop {
            let res = handle_message(
                &mut stream,
                if USE_PCIDOE {
                    pcidoe_transport_encap
                } else {
                    mctp_transport_encap
                },
            );
            match res {
                Ok(_spdm_result) => {
                    need_continue = true;
                }
                Err((used, buffer)) => {
                    need_continue = process_socket_message(
                        &mut stream,
                        if USE_PCIDOE {
                            pcidoe_transport_encap
                        } else {
                            mctp_transport_encap
                        },
                        &buffer[0..used],
                    );
                }
            }
            if !need_continue {
                // TBD: return or break??
                return;
            }
        }
    }
}

fn handle_message(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
) -> Result<bool, (usize, [u8; 1024])> {
    println!("handle_message!");
    let mut socket_io_transport = SocketIoTransport::new(stream);

    let config_info = common::SpdmConfigInfo {
        spdm_version: [SpdmVersion::SpdmVersion10, SpdmVersion::SpdmVersion11],
        rsp_capabilities: SpdmResponseCapabilityFlags::CERT_CAP
        | SpdmResponseCapabilityFlags::CHAL_CAP
        | SpdmResponseCapabilityFlags::MEAS_CAP_SIG
        | SpdmResponseCapabilityFlags::MEAS_FRESH_CAP
        | SpdmResponseCapabilityFlags::ENCRYPT_CAP
        | SpdmResponseCapabilityFlags::MAC_CAP
        //| SpdmResponseCapabilityFlags::MUT_AUTH_CAP
        | SpdmResponseCapabilityFlags::KEY_EX_CAP
        | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT
        | SpdmResponseCapabilityFlags::ENCAP_CAP
        | SpdmResponseCapabilityFlags::HBEAT_CAP
        | SpdmResponseCapabilityFlags::KEY_UPD_CAP, // | SpdmResponseCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmResponseCapabilityFlags::PUB_KEY_ID_CAP
        rsp_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        measurement_hash_algo: SpdmMeasurementHashAlgo::TPM_ALG_SHA_384,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: if USE_ECDH {
            SpdmDheAlgo::SECP_384_R1
        } else {
            SpdmDheAlgo::FFDHE_3072
        },
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048,
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        ..Default::default()
    };

    let mut my_cert_chain_data = SpdmCertChainData {
        ..Default::default()
    };

    let ca_file_path = if USE_ECDSA {
        "test_key/EcP384/ca.cert.der"
    } else {
        "test_key/Rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/EcP384/inter.cert.der"
    } else {
        "test_key/Rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/EcP384/end_responder.cert.der"
    } else {
        "test_key/Rsa3072/end_responder.cert.der"
    };
    let leaf_cert = std::fs::read(leaf_file_path).expect("unable to read leaf cert!");

    let ca_len = ca_cert.len();
    let inter_len = inter_cert.len();
    let leaf_len = leaf_cert.len();
    println!(
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
    };

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );

    loop {
        // if failed, receieved message can't be processed. then the message will need caller to deal.
        // now caller need to deal with message in context.
        let res = context.process_message();
        match res {
            Ok(spdm_result) => {
                if spdm_result {
                    continue;
                } else {
                    // send unknown spdm command
                    return Ok(false);
                }
            }
            Err((used, buffer)) => {
                return Err((used, buffer));
            }
        }
    }
}

pub fn send_hello(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
    tranport_type: u32,
) {
    println!("get hello");

    let mut payload = [0u8; 1024];

    let used = transport_encap
        .encap(b"Server Hello!\0", &mut payload[..], false)
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        tranport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_TEST,
        &payload[..used],
    );
}

pub fn send_unknown(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
    transport_type: u32,
) {
    println!("get unknown");

    let mut payload = [0u8; 1024];

    let used = transport_encap.encap(b"", &mut payload[..], false).unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_UNKOWN,
        &payload[..used],
    );
}

pub fn send_stop(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
    transport_type: u32,
) {
    println!("get stop");

    let mut payload = [0u8; 1024];

    let used = transport_encap.encap(b"", &mut payload[..], false).unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_STOP,
        &payload[..used],
    );
}

pub fn send_pci_discovery(
    stream: &mut TcpStream,
    transport_encap: &mut dyn SpdmTransportEncap,
    transport_type: u32,
    buffer: &[u8],
) -> bool {
    let mut reader = Reader::init(buffer);
    let mut unknown_message = false;
    match PciDoeMessageHeader::read(&mut reader) {
        Some(pcidoe_header) => {
            match pcidoe_header.vendor_id {
                PciDoeVendorId::PciDoeVendorIdPciSig => {}
                _ => unknown_message = true,
            }
            match pcidoe_header.data_object_type {
                PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery => {}
                _ => unknown_message = true,
            }
        }
        None => unknown_message = true,
    }

    let payload = &mut [1u8, 0u8, 0u8, 0u8];

    match u8::read(&mut reader) {
        None => unknown_message = true,
        Some(discovery_index) => match discovery_index {
            0 => {
                payload[2] = 0;
                payload[3] = 1;
            }
            1 => {
                payload[2] = 1;
                payload[3] = 2;
            }
            2 => {
                payload[2] = 2;
                payload[3] = 0;
            }
            _ => unknown_message = true,
        },
    }
    if unknown_message {
        send_unknown(stream, transport_encap, transport_type);
        return false;
    }

    let payload_len = 4;
    let mut transport_buffer = [0u8; 1024];
    let mut writer = Writer::init(&mut transport_buffer);
    let pcidoe_header = PciDoeMessageHeader {
        vendor_id: PciDoeVendorId::PciDoeVendorIdPciSig,
        data_object_type: PciDoeDataObjectType::PciDoeDataObjectTypeDoeDiscovery,
        payload_length: 4,
    };
    pcidoe_header.encode(&mut writer);
    let header_size = writer.used();
    transport_buffer[header_size..(header_size + payload_len)].copy_from_slice(payload);
    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        SOCKET_TRANSPORT_TYPE_PCI_DOE,
        spdm_emu::spdm_emu::SOCKET_SPDM_COMMAND_NORMAL,
        &transport_buffer[..(header_size + payload_len)],
    );
    //need continue
    true
}
