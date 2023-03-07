// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::{spdmlib::common::session::SpdmSession, *};
use spdmlib::protocol::*;

fn fuzz_handle_spdm_psk_exchange(data: &[u8]) {
    let (config_info, provision_info) = rsp_create_info();
    let (config_info1, provision_info1) = rsp_create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let mctp_transport_encap = &mut MctpTransportEncap {};

    let transport_encap: &mut dyn SpdmTransportEncap = if USE_PCIDOE {
        pcidoe_transport_encap
    } else {
        mctp_transport_encap
    };

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL.clone());

    {
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);
        let mut context = responder::ResponderContext::new(config_info, provision_info);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        context.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;
        context.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

        context.common.reset_runtime_info();

        let _ = context.handle_spdm_psk_exchange(data, transport_encap, &mut socket_io_transport);
    }

    {
        let shared_buffer = SharedBuffer::new();
        let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

        let mut context = responder::ResponderContext::new(config_info1, provision_info1);

        context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
        context.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
        context.common.negotiate_info.dhe_sel = SpdmDheAlgo::SECP_384_R1;
        context.common.negotiate_info.aead_sel = SpdmAeadAlgo::AES_256_GCM;
        context.common.negotiate_info.req_asym_sel = SpdmReqAsymAlgo::TPM_ALG_RSAPSS_2048;
        context.common.negotiate_info.key_schedule_sel = SpdmKeyScheduleAlgo::SPDM_KEY_SCHEDULE;

        context.common.reset_runtime_info();
        context.common.session[0] = SpdmSession::new();
        context.common.session[1] = SpdmSession::new();
        context.common.session[2] = SpdmSession::new();
        context.common.session[3] = SpdmSession::new();
        context.common.session[0].setup(4294901758).unwrap();
        context.common.session[1].setup(4294901758).unwrap();
        context.common.session[2].setup(4294901758).unwrap();
        context.common.session[3].setup(4294901758).unwrap();
        let _ = context.handle_spdm_psk_exchange(data, transport_encap, &mut socket_io_transport);
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
