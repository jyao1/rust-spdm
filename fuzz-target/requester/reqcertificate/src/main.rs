// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_certificate(fuzzdata: &[u8]) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);
    spdmlib::crypto::cert_operation::register(FUZZ_CERT);
    spdmlib::crypto::hash::register(FUZZ_HASH);

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );


    // version_rsp
    responder.common.reset_runtime_info();
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
    responder.common.provision_info.my_cert_chain = Some(REQ_CERT_CHAIN_DATA);

    // digest_rsp

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    // version_req


    //algorithm_req
    // requester
    //     .common
    //     .negotiate_info
    //     .measurement_specification_sel = SpdmMeasurementSpecification::DMTF;
    // requester.common.negotiate_info.measurement_hash_sel = SpdmMeasurementHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    requester.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;

    // digest_req

    let _ = requester.send_receive_spdm_certificate(0).is_err();
}

fn main() {
    #[cfg(feature = "fuzzlog")]
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
    // if cfg!(feature = "analysis") {
    //     let args: Vec<String> = std::env::args().collect();
    //     println!("{:?}", args);
    //     if args.len() < 2 {
    //         println!("Please enter the path of the crash file as the first parameter");
    //         return;
    //     }
    //     let path = &args[1];
    //     let data = std::fs::read(path).expect("read crash file fail");
    //     fuzz_send_receive_spdm_certificate(data.as_slice());
    // } else {
    //     afl::fuzz!(|data: &[u8]| {
    //         fuzz_send_receive_spdm_certificate(data);
    //     });
    // }
    fuzz_send_receive_spdm_certificate(&[1,2,3,4]);
}
