// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{
    spdmlib::common::session::{SpdmSession, SpdmSessionState},
    *,
};
use spdmlib::protocol::*;

fn fuzz_handle_spdm_heartbeat(data: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

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
    context.common.session[0] = SpdmSession::new();
    context.common.session[0].setup(4294901758).unwrap();
    context.common.session[0].set_session_state(SpdmSessionState::SpdmSessionEstablished);
    context.common.session[0].set_crypto_param(
        SpdmBaseHashAlgo::TPM_ALG_SHA_384,
        SpdmDheAlgo::SECP_384_R1,
        SpdmAeadAlgo::AES_256_GCM,
        SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE,
    );

    context.handle_spdm_heartbeat(4294901758, data);
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
            let fuzzdata = [17, 46, 43];
            fuzz_handle_spdm_heartbeat(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_heartbeat(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_heartbeat(data);
    });
}
