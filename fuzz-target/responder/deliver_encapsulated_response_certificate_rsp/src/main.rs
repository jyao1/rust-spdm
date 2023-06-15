// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
use spdmlib::common::SpdmConnectionState;
use spdmlib::protocol::*;

fn fuzz_handle_encap_response_certificate(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::crypto::cert_operation::register(FAKE_CERT_OPERATION.clone());
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle encap certificate from requester'
    // - description: '<p>Responder process encapsulated CERTIFICATE and no need to verify the authority of cert chain.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel =
            context.common.negotiate_info.req_capabilities_sel
                | SpdmRequestCapabilityFlags::ENCAP_CAP
                | SpdmRequestCapabilityFlags::CERT_CAP;
        context.common.negotiate_info.rsp_capabilities_sel =
            context.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::ENCAP_CAP;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());

        let _ = context.handle_encap_response_certificate(data).is_err();
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle encap certificate from requester'
    // - description: '<p>Responder process encapsulated CERTIFICATE and pass the verification of provisioned root cert.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.req_capabilities_sel =
            context.common.negotiate_info.req_capabilities_sel
                | SpdmRequestCapabilityFlags::ENCAP_CAP
                | SpdmRequestCapabilityFlags::CERT_CAP;
        context.common.negotiate_info.rsp_capabilities_sel =
            context.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::ENCAP_CAP;
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.common.peer_info.peer_cert_chain_temp = Some(SpdmCertChainBuffer::default());

        // to pass the verification of provisioned root cert with fake cert_operation
        let mut fake_root = SpdmCertChainData::default();
        // range [60..93] of seed `encap_get_certificate.raw` is fake root cert
        fake_root.data_size = 33;
        let start_index = 60;
        let end_index = start_index + fake_root.data_size as usize;
        if data.len() >= end_index {
            fake_root.data[0..fake_root.data_size as usize]
                .copy_from_slice(&data[start_index..end_index]);
        }
        context.common.provision_info.peer_root_cert_data = Some(fake_root);

        let _ = context.handle_encap_response_certificate(data).is_err();
    }
}

#[cfg(not(feature = "use_libfuzzer"))]
fn main() {
    #[cfg(all(feature = "fuzzlogfile", feature = "fuzz"))]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("traces")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();
    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata =
                include_bytes!("../../../in/deliver_encapsulated_response_certificate_rsp/encap_get_certificate.raw");
            fuzz_handle_encap_response_certificate(fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_encap_response_certificate(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_encap_response_certificate(data);
    });
}
