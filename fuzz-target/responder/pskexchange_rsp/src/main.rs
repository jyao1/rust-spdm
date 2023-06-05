// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::config::MAX_SPDM_SESSION_COUNT;
use fuzzlib::spdmlib::common::session::SpdmSession;
use fuzzlib::{common::SpdmConnectionState, common::SpdmOpaqueSupport, *};
use spdmlib::protocol::*;

fn fuzz_handle_spdm_psk_exchange(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());

    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK exchange request'
    // - description: '<p>Respond PSK exchange rsp and skip PSK_FINISH.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        context.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        context.common.negotiate_info.rsp_capabilities_sel =
            context.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT;

        context.common.reset_runtime_info();
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.handle_spdm_psk_exchange(data);
    }

    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK exchange request'
    // - description: '<p>Respond PSK exchange rsp with PSK_CAP_WITH_CONTEXT cap.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        context.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        context.common.negotiate_info.rsp_capabilities_sel =
            context.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::PSK_CAP_WITHOUT_CONTEXT;

        context.common.reset_runtime_info();
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.handle_spdm_psk_exchange(data);
    }

    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle PSK exchange request'
    // - description: '<p>Respond PSK exchange rsp with session limit exceeded.</p>'
    // -
    {
        let (config_info, provision_info) = rsp_create_info();
        let shared_buffer = SharedBuffer::new();
        let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(
            &mut socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );
        context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
        context.common.negotiate_info.opaque_data_support = SpdmOpaqueSupport::OPAQUE_DATA_FMT1;
        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        context.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        context.common.negotiate_info.rsp_capabilities_sel =
            context.common.negotiate_info.rsp_capabilities_sel
                | SpdmResponseCapabilityFlags::PSK_CAP_WITH_CONTEXT;

        context.common.reset_runtime_info();
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        for i in 0..MAX_SPDM_SESSION_COUNT {
            context.common.session[i] = SpdmSession::new();
            context.common.session[i].setup(4294836221).unwrap();
        }
        context.handle_spdm_psk_exchange(data);
    }
}
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
            let fuzzdata = [17, 46, 43];
            fuzz_handle_spdm_psk_exchange(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_psk_exchange(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_psk_exchange(data);
    });
}
