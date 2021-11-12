// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use common::SpdmTransportEncap;

use log::LevelFilter;
use log::*;
use simple_logger::SimpleLogger;

use spdmlib::common;
use spdmlib::config;
use spdmlib::msgs::*;
use spdmlib::requester;

use mctp_transport::MctpTransportEncap;
use pcidoe_transport::PciDoeTransportEncap;
use spdm_emu::socket_io_transport::SocketIoTransport;
use spdm_emu::spdm_emu::*;
use std::net::TcpStream;

fn send_receive_hello(
    stream: &mut TcpStream,
    transport_encap: &mut dyn common::SpdmTransportEncap,
    transport_type: u32,
) {
    println!("send test");
    let mut payload = [0u8; 1024];

    let used = transport_encap
        .encap(b"Client Hello!\0", &mut payload[..], false)
        .unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        SOCKET_SPDM_COMMAND_TEST,
        &payload[0..used],
    );
    let mut buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..]).unwrap();
}

fn send_receive_stop(
    stream: &mut TcpStream,
    transport_encap: &mut dyn common::SpdmTransportEncap,
    transport_type: u32,
) {
    println!("send stop");

    let mut payload = [0u8; 1024];

    let used = transport_encap.encap(b"", &mut payload[..], false).unwrap();

    let _buffer_size = spdm_emu::spdm_emu::send_message(
        stream,
        transport_type,
        SOCKET_SPDM_COMMAND_STOP,
        &payload[0..used],
    );
    let mut buffer = [0u8; config::MAX_SPDM_TRANSPORT_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..]).unwrap();
}

fn test_spdm(
    socket_io_transport: &mut SocketIoTransport,
    transport_encap: &mut dyn SpdmTransportEncap,
) {
    let config_info = common::SpdmConfigInfo {
        spdm_version: [SpdmVersion::SpdmVersion10, SpdmVersion::SpdmVersion11],
        req_capabilities: SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        //| SpdmRequestCapabilityFlags::MUT_AUTH_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP, // | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
        // | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
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

    let mut peer_cert_chain_data = SpdmCertChainData {
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
    };

    let mut context = requester::RequesterContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );

    if context.init_connection().is_err() {
        return;
    }

    if context.send_receive_spdm_digest().is_err() {
        return;
    }

    if context.send_receive_spdm_certificate(0).is_err() {
        return;
    }

    if context
        .send_receive_spdm_challenge(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .is_err()
    {
        return;
    }

    if context
        .send_receive_spdm_measurement(
            None,
            SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
            0,
        )
        .is_err()
    {
        return;
    }

    let result = context.start_session(
        false,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    );
    if let Ok(session_id) = result {
        info!("\nSession established ... session_id {:0x?}\n", session_id);
        info!("Key Information ...\n");

        let session = context.common.get_session_via_id(session_id).unwrap();
        let (request_direction, response_direction) = session.export_keys();
        info!(
            "equest_direction.encryption_key {:0x?}\n",
            request_direction.encryption_key.as_ref()
        );
        info!(
            "equest_direction.salt {:0x?}\n",
            request_direction.salt.as_ref()
        );
        info!(
            "esponse_direction.encryption_key {:0x?}\n",
            response_direction.encryption_key.as_ref()
        );
        info!(
            "esponse_direction.salt {:0x?}\n",
            response_direction.salt.as_ref()
        );

        if context.send_receive_spdm_heartbeat(session_id).is_err() {
            return;
        }

        if context
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .is_err()
        {
            return;
        }

        if context
            .send_receive_spdm_measurement(
                Some(session_id),
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                0,
            )
            .is_err()
        {
            return;
        }

        if context.end_session(session_id).is_err() {
            return;
        }
    } else {
        info!("\nSession session_id not got\n");
    }

    let result = context.start_session(
        true,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    );
    if let Ok(session_id) = result {
        if context.end_session(session_id).is_err() {
            info!("\nSession session_id is err\n");
        }
    } else {
        info!("\nSession session_id not got\n");
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

    let since_the_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    println!("current unit time epoch - {:?}", since_the_epoch.as_secs());

    let mut socket =
        TcpStream::connect("127.0.0.1:2323").expect("Couldn't connect to the server...");

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let mctp_transport_encap = &mut MctpTransportEncap {};

    let transport_encap: &mut dyn SpdmTransportEncap = if USE_PCIDOE {
        pcidoe_transport_encap
    } else {
        mctp_transport_encap
    };

    let transport_type = if USE_PCIDOE {
        SOCKET_TRANSPORT_TYPE_PCI_DOE
    } else {
        SOCKET_TRANSPORT_TYPE_MCTP
    };

    send_receive_hello(&mut socket, transport_encap, transport_type);

    let socket_io_transport = &mut SocketIoTransport::new(&mut socket);
    test_spdm(socket_io_transport, transport_encap);

    send_receive_stop(&mut socket, transport_encap, transport_type);
}
