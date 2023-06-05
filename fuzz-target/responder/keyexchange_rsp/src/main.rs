// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{common::SpdmOpaqueSupport, *};
use spdmlib::common::SpdmConnectionState;
use spdmlib::protocol::*;

fn fuzz_handle_spdm_key_exchange(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
    spdmlib::secret::measurement::register(SECRET_MEASUREMENT_IMPL_INSTANCE.clone());

    let (config_info, provision_info) = rsp_create_info();
    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

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

    context.common.reset_runtime_info();
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    context.handle_spdm_key_exchange(data);
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
            let fuzzdata = [
                17, 228, 0, 0, 254, 255, 0, 0, 164, 168, 149, 35, 47, 201, 46, 27, 159, 172, 140,
                250, 56, 72, 129, 27, 241, 183, 219, 225, 241, 166, 116, 200, 20, 253, 145, 57,
                222, 45, 78, 168, 5, 106, 25, 148, 247, 253, 178, 151, 59, 213, 123, 199, 11, 108,
                92, 59, 33, 210, 5, 89, 52, 18, 79, 67, 12, 199, 200, 127, 207, 2, 92, 244, 184,
                140, 1, 63, 239, 90, 154, 1, 33, 57, 212, 7, 189, 192, 196, 254, 66, 150, 138, 127,
                89, 215, 107, 166, 163, 99, 184, 59, 232, 234, 137, 81, 162, 177, 220, 235, 235,
                171, 95, 178, 148, 83, 120, 80, 222, 234, 96, 254, 120, 223, 93, 247, 191, 95, 75,
                190, 151, 183, 121, 147, 55, 40, 61, 132, 20, 0, 70, 84, 77, 68, 1, 1, 0, 0, 0, 0,
                5, 0, 1, 1, 1, 0, 17, 0, 0, 0, 0, 0,
            ];
            fuzz_handle_spdm_key_exchange(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_key_exchange(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_key_exchange(data);
    });
}
