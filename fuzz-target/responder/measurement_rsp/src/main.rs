// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    spdmlib::common::SpdmConnectionState,
    spdmlib::protocol::*,
    *,
};

fn fuzz_handle_spdm_measurement(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement request'
    // - description: '<p>Respond MEASUREMENTS without session.</p>'
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
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.measurement_specification_sel =
            SpdmMeasurementSpecification::DMTF;
        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.handle_spdm_measurement(None, data);
    }
    // TCD:
    // - id: 0
    // - title: 'Fuzz SPDM handle measurement request'
    // - description: '<p>Respond MEASUREMENTS in a session.</p>'
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
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.measurement_hash_sel =
            SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.measurement_specification_sel =
            SpdmMeasurementSpecification::DMTF;
        context.common.provision_info.my_cert_chain = [
            Some(get_rsp_cert_chain_buff()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ];
        context.common.session[0] = SpdmSession::new();
        context.common.session[0].setup(4294836221).unwrap();
        context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
        context.common.session[0].set_crypto_param(
            SpdmBaseHashAlgo::TPM_ALG_SHA_384,
            SpdmDheAlgo::SECP_384_R1,
            SpdmAeadAlgo::AES_256_GCM,
            SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
        );
        context
            .common
            .runtime_info
            .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

        context.handle_spdm_measurement(Some(4294836221), data);
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

    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());
    spdmlib::secret::psk::register(SECRET_PSK_IMPL_INSTANCE.clone());
    #[cfg(not(feature = "fuzz"))]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            // Here you can replace the single-step debugging value in the fuzzdata array.
            let fuzzdata = [17, 224, 0, 0];
            fuzz_handle_spdm_measurement(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_measurement(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_measurement(data);
    });
}
