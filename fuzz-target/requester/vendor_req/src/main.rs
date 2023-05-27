// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::*;
use spdmlib::common::SpdmConnectionState;
use spdmlib::message::{
    RegistryOrStandardsBodyID, VendorDefinedReqPayloadStruct, VendorIDStruct,
    MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN,
};
use spdmlib::protocol::*;

fn fuzz_send_spdm_vendor_defined_request(fuzzdata: &[u8]) {
    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer, fuzzdata);
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );
    responder.common.provision_info.my_cert_chain = [
        Some(SpdmCertChainBuffer {
            data_size: 512u16,
            data: [0u8; 4 + SPDM_MAX_HASH_SIZE + config::MAX_SPDM_CERT_CHAIN_DATA_SIZE],
        }),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ];
    responder.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    responder.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    responder
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester =
        fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );

    requester.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    requester.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;

    let standard_id: RegistryOrStandardsBodyID = RegistryOrStandardsBodyID::DMTF;
    let vendor_idstruct: VendorIDStruct = VendorIDStruct {
        len: 0,
        vendor_id: [0u8; MAX_SPDM_VENDOR_DEFINED_VENDOR_ID_LEN],
    };
    let req_payload_struct: VendorDefinedReqPayloadStruct = VendorDefinedReqPayloadStruct {
        req_length: 0,
        vendor_defined_req_payload: [0u8; config::MAX_SPDM_MSG_SIZE - 7 - 2],
    };

    let _ = requester
        .send_spdm_vendor_defined_request(None, standard_id, vendor_idstruct, req_payload_struct)
        .is_ok();
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
                1, 0, 1, 0, 48, 0, 0, 0, 17, 2, 255, 1, 127, 0, 0, 0, 0, 17, 3, 0, 1, 40, 175,
            ];
            fuzz_send_spdm_vendor_defined_request(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_send_spdm_vendor_defined_request(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_send_spdm_vendor_defined_request(data);
    });
}
