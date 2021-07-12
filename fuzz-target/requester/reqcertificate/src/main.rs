// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;

fn fuzz_send_receive_spdm_certificate(fuzzdata: &[u8], number: i8) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata, number);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    // capability 
    responder.common.negotiate_info.req_ct_exponent_sel = 0;
    responder.common.negotiate_info.req_capabilities_sel =SpdmRequestCapabilityFlags::CERT_CAP
    | SpdmRequestCapabilityFlags::CHAL_CAP
    | SpdmRequestCapabilityFlags::ENCRYPT_CAP
    | SpdmRequestCapabilityFlags::MAC_CAP
    //| SpdmRequestCapabilityFlags::MUT_AUTH_CAP
    | SpdmRequestCapabilityFlags::KEY_EX_CAP
    | SpdmRequestCapabilityFlags::PSK_CAP
    | SpdmRequestCapabilityFlags::ENCAP_CAP
    | SpdmRequestCapabilityFlags::HBEAT_CAP
    | SpdmRequestCapabilityFlags::KEY_UPD_CAP;
    responder.common.negotiate_info.rsp_ct_exponent_sel =
        responder.common.config_info.rsp_ct_exponent;
    responder.common.negotiate_info.rsp_capabilities_sel =
        responder.common.config_info.rsp_capabilities;


    // algorithm
    responder.common.negotiate_info.measurement_specification_sel =SpdmMeasurementSpecification::DMTF;
            responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
            responder.common.negotiate_info.base_asym_sel = SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384;
            for alg in [
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeDHE,
                    alg_fixed_count: 2,
                    alg_supported: SpdmAlg::SpdmAlgoDhe(responder.common.config_info.dhe_algo),
                    alg_ext_count: 0,
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeAEAD,
                    alg_fixed_count: 2,
                    alg_supported: SpdmAlg::SpdmAlgoAead(responder.common.config_info.aead_algo),
                    alg_ext_count: 0,
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeReqAsym,
                    alg_fixed_count: 2,
                    alg_supported: SpdmAlg::SpdmAlgoReqAsym(
                        responder.common.config_info.req_asym_algo,
                    ),
                    alg_ext_count: 0,
                },
                SpdmAlgStruct {
                    alg_type: SpdmAlgType::SpdmAlgTypeKeySchedule,
                    alg_fixed_count: 2,
                    alg_supported: SpdmAlg::SpdmAlgoKeySchedule(
                        responder.common.config_info.key_schedule_algo,
                    ),
                    alg_ext_count: 0,
                },
            ]
                .iter()
                .take(4 as usize)
            {
                match alg.alg_supported {
                    SpdmAlg::SpdmAlgoDhe(v) => responder.common.negotiate_info.dhe_sel = v,
                    SpdmAlg::SpdmAlgoAead(v) => responder.common.negotiate_info.aead_sel = v,
                    SpdmAlg::SpdmAlgoReqAsym(v) => responder.common.negotiate_info.req_asym_sel = v,
                    SpdmAlg::SpdmAlgoKeySchedule(v) => {
                        responder.common.negotiate_info.key_schedule_sel = v
                    }
                    SpdmAlg::SpdmAlgoUnknown(_v) => {}
                }
            }


    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    // capability
    requester.common.negotiate_info.req_ct_exponent_sel =
        requester.common.config_info.req_ct_exponent;
    requester.common.negotiate_info.req_capabilities_sel =
        requester.common.config_info.req_capabilities;
    requester.common.negotiate_info.rsp_capabilities_sel =  SpdmResponseCapabilityFlags::CERT_CAP
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
    | SpdmResponseCapabilityFlags::KEY_UPD_CAP;

    //algorithm


    let _ = requester.init_connection().is_err();

    let _ = requester.send_receive_spdm_digest().is_err();

    let _ = requester.send_receive_spdm_certificate(0).is_err();
}

// use fuzzlib::SPDM_PATH;

fn main() {
    // afl::fuzz!(|data: &[u8]| {
    // fuzz_send_receive_spdm_certificate(data, 5);
    // });
    fuzz_send_receive_spdm_certificate(
        &[10, 11, 23, 12, 44, 66, 78, 8, 5, 33, 4, 5, 6, 8, 2, 44],
        5,
    );
}
