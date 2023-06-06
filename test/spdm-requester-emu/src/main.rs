// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

#![forbid(unsafe_code)]

use common::SpdmTransportEncap;

use log::LevelFilter;
use log::*;
use simple_logger::SimpleLogger;

use spdm_emu::crypto_callback::SECRET_ASYM_IMPL_INSTANCE;
use spdm_emu::secret_impl_sample::SECRET_PSK_IMPL_INSTANCE;
use spdmlib::common;
use spdmlib::common::SpdmOpaqueSupport;
use spdmlib::common::ST1;
use spdmlib::config;
use spdmlib::message::*;
use spdmlib::protocol::*;
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
    let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..], ST1).unwrap();
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
    let mut buffer = [0u8; config::RECEIVER_BUFFER_SIZE];
    let (_transport_type, _command, _payload) =
        spdm_emu::spdm_emu::receive_message(stream, &mut buffer[..], ST1).unwrap();
}

fn test_spdm(
    socket_io_transport: &mut SocketIoTransport,
    transport_encap: &mut dyn SpdmTransportEncap,
) {
    let req_capabilities = SpdmRequestCapabilityFlags::CERT_CAP
        | SpdmRequestCapabilityFlags::CHAL_CAP
        | SpdmRequestCapabilityFlags::ENCRYPT_CAP
        | SpdmRequestCapabilityFlags::MAC_CAP
        | SpdmRequestCapabilityFlags::KEY_EX_CAP
        | SpdmRequestCapabilityFlags::PSK_CAP
        | SpdmRequestCapabilityFlags::ENCAP_CAP
        | SpdmRequestCapabilityFlags::HBEAT_CAP
        | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    // | SpdmRequestCapabilityFlags::HANDSHAKE_IN_THE_CLEAR_CAP
    // | SpdmRequestCapabilityFlags::PUB_KEY_ID_CAP
    let req_capabilities = if cfg!(feature = "mut-auth") {
        req_capabilities | SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    } else {
        req_capabilities
    };

    let config_info = common::SpdmConfigInfo {
        spdm_version: [
            SpdmVersion::SpdmVersion10,
            SpdmVersion::SpdmVersion11,
            SpdmVersion::SpdmVersion12,
        ],
        req_capabilities,
        req_ct_exponent: 0,
        measurement_specification: SpdmMeasurementSpecification::DMTF,
        base_asym_algo: if USE_ECDSA {
            SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
        },
        base_hash_algo: SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        dhe_algo: SpdmDheAlgo::SECP_384_R1,
        aead_algo: SpdmAeadAlgo::AES_256_GCM,
        req_asym_algo: if USE_ECDSA {
            SpdmReqAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
        } else {
            SpdmReqAsymAlgo::TPM_ALG_RSASSA_3072
        },
        key_schedule_algo: SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        opaque_support: SpdmOpaqueSupport::OPAQUE_DATA_FMT1,
        data_transfer_size: config::MAX_SPDM_MSG_SIZE as u32,
        max_spdm_msg_size: config::MAX_SPDM_MSG_SIZE as u32,
        ..Default::default()
    };

    let mut peer_root_cert_data = SpdmCertChainData {
        ..Default::default()
    };

    let ca_file_path = if USE_ECDSA {
        "test_key/ecp384/ca.cert.der"
    } else {
        "test_key/rsa3072/ca.cert.der"
    };
    let ca_cert = std::fs::read(ca_file_path).expect("unable to read ca cert!");
    let inter_file_path = if USE_ECDSA {
        "test_key/ecp384/inter.cert.der"
    } else {
        "test_key/rsa3072/inter.cert.der"
    };
    let inter_cert = std::fs::read(inter_file_path).expect("unable to read inter cert!");
    let leaf_file_path = if USE_ECDSA {
        "test_key/ecp384/end_responder.cert.der"
    } else {
        "test_key/rsa3072/end_responder.cert.der"
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
    peer_root_cert_data.data_size = (ca_len) as u16;
    peer_root_cert_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());

    let provision_info = if cfg!(feature = "mut-auth") {
        spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        let mut my_cert_chain_data = SpdmCertChainData {
            ..Default::default()
        };

        my_cert_chain_data.data_size = (ca_len + inter_len + leaf_len) as u16;
        my_cert_chain_data.data[0..ca_len].copy_from_slice(ca_cert.as_ref());
        my_cert_chain_data.data[ca_len..(ca_len + inter_len)].copy_from_slice(inter_cert.as_ref());
        my_cert_chain_data.data[(ca_len + inter_len)..(ca_len + inter_len + leaf_len)]
            .copy_from_slice(leaf_cert.as_ref());

        common::SpdmProvisionInfo {
            my_cert_chain_data: [
                Some(my_cert_chain_data),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: Some(peer_root_cert_data),
        }
    } else {
        common::SpdmProvisionInfo {
            my_cert_chain_data: [None, None, None, None, None, None, None, None],
            my_cert_chain: [None, None, None, None, None, None, None, None],
            peer_root_cert_data: Some(peer_root_cert_data),
        }
    };

    let mut context = requester::RequesterContext::new(
        socket_io_transport,
        transport_encap,
        config_info,
        provision_info,
    );

    if context.init_connection().is_err() {
        panic!("init_connection failed!");
    }

    if context.send_receive_spdm_digest(None).is_err() {
        panic!("send_receive_spdm_digest failed!");
    }

    if context.send_receive_spdm_certificate(None, 0).is_err() {
        panic!("send_receive_spdm_certificate failed!");
    }

    if context
        .send_receive_spdm_challenge(
            0,
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
        )
        .is_err()
    {
        panic!("send_receive_spdm_challenge failed!");
    }

    let mut total_number: u8 = 0;
    let mut spdm_measurement_record_structure = SpdmMeasurementRecordStructure::default();
    if context
        .send_receive_spdm_measurement(
            None,
            0,
            SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
            SpdmMeasurementOperation::SpdmMeasurementRequestAll,
            &mut total_number,
            &mut spdm_measurement_record_structure,
        )
        .is_err()
    {
        panic!("send_receive_spdm_measurement failed!");
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
            panic!("send_receive_spdm_heartbeat failed");
        }

        if context
            .send_receive_spdm_key_update(session_id, SpdmKeyUpdateOperation::SpdmUpdateAllKeys)
            .is_err()
        {
            panic!("send_receive_spdm_key_update failed");
        }

        if context
            .send_receive_spdm_measurement(
                Some(session_id),
                0,
                SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber,
                &mut total_number,
                &mut spdm_measurement_record_structure,
            )
            .is_err()
        {
            panic!("send_receive_spdm_measurement failed");
        }

        if context.send_receive_spdm_digest(Some(session_id)).is_err() {
            panic!("send_receive_spdm_digest failed");
        }

        if context
            .send_receive_spdm_certificate(Some(session_id), 0)
            .is_err()
        {
            panic!("send_receive_spdm_certificate failed");
        }

        if context.end_session(session_id).is_err() {
            panic!("end_session failed");
        }
    } else {
        panic!("\nSession session_id not got\n");
    }

    let result = context.start_session(
        true,
        0,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    );
    if let Ok(session_id) = result {
        if context.end_session(session_id).is_err() {
            panic!("\nSession session_id is err\n");
        }
    } else {
        panic!("\nSession session_id not got\n");
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

    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    #[cfg(feature = "spdm-mbedtls")]
    spdm_emu::crypto::crypto_mbedtls_register_handles();

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
