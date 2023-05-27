// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use fuzzlib::spdmlib::error::SpdmResult;
use fuzzlib::spdmlib::message::{
    register_vendor_defined_struct, VendorDefinedReqPayloadStruct, VendorDefinedRspPayloadStruct,
    VendorDefinedStruct,
};
use fuzzlib::*;
use spdmlib::common::SpdmConnectionState;
use spdmlib::protocol::*;

fn fuzz_handle_spdm_vendor_defined_request(data: &[u8]) {
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

    context.common.provision_info.my_cert_chain = [
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
    context.common.negotiate_info.spdm_version_sel = SpdmVersion::SpdmVersion12;
    context.common.negotiate_info.base_hash_sel = SpdmBaseHashAlgo::TPM_ALG_SHA_384;
    context
        .common
        .runtime_info
        .set_connection_state(SpdmConnectionState::SpdmConnectionNegotiated);

    let vendor_defined_func: for<'r> fn(&'r VendorDefinedReqPayloadStruct) -> Result<_, _> =
        |_vendor_defined_req_payload_struct| -> SpdmResult<VendorDefinedRspPayloadStruct> {
            let mut vendor_defined_res_payload_struct = VendorDefinedRspPayloadStruct {
                rsp_length: 0,
                vendor_defined_rsp_payload: [0; config::MAX_SPDM_MSG_SIZE - 7 - 2],
            };
            vendor_defined_res_payload_struct.rsp_length = 8;
            vendor_defined_res_payload_struct.vendor_defined_rsp_payload[0..8]
                .clone_from_slice(b"deadbeef");
            Ok(vendor_defined_res_payload_struct)
        };

    register_vendor_defined_struct(VendorDefinedStruct {
        vendor_defined_request_handler: vendor_defined_func,
    });

    context.handle_spdm_vendor_defined_request(None, data);
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
            let fuzzdata = [17, 129, 0, 0];
            fuzz_handle_spdm_vendor_defined_request(&fuzzdata);
        } else {
            let path = &args[1];
            let data = std::fs::read(path).expect("read crash file fail");
            fuzz_handle_spdm_vendor_defined_request(data.as_slice());
        }
    }
    #[cfg(feature = "fuzz")]
    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_vendor_defined_request(data);
    });
}
