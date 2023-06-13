// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

// import commonly used items from the prelude:
use fuzzlib::*;
use spdmlib::message::*;
use spdmlib::protocol::*;

fn run_spdm(spdm: Vec<i32>) {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};

    spdmlib::secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );

    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info,
    );
    println!("Run sequence {:?}", &spdm);
    for i in spdm.iter() {
        match i {
            1 => {
                if requester.send_receive_spdm_version().is_err() {
                    println!("{:?} error in send_receive_spdm_version", &spdm);
                    return;
                }
            }
            2 => {
                if requester.send_receive_spdm_capability().is_err() {
                    println!("{:?} error in send_receive_spdm_capability", &spdm);
                    return;
                }
            }
            3 => {
                if requester.send_receive_spdm_algorithm().is_err() {
                    println!("{:?} error in send_receive_spdm_algorithm", &spdm);
                    return;
                }
            }
            4 => {
                if requester.send_receive_spdm_digest(None).is_err() {
                    println!("{:?} 4, error in send_receive_spdm_digest", &spdm);
                    return;
                }
            }
            5 => {
                if requester.send_receive_spdm_certificate(None, 0).is_err() {
                    println!("{:?} 5, error in send_receive_spdm_certificate", &spdm);
                    return;
                }
            }
            6 => {
                if requester
                    .send_receive_spdm_challenge(
                        0,
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    )
                    .is_err()
                {
                    println!("{:?} 6, error in send_receive_spdm_challenge", &spdm);
                    return;
                }
            }
            7 => {
                let mut total_number = 0;
                let mut spdm_measurement_record_structure =
                    SpdmMeasurementRecordStructure::default();
                if requester
                    .send_receive_spdm_measurement(
                        None,
                        0,
                        SpdmMeasurementAttributes::SIGNATURE_REQUESTED,
                        SpdmMeasurementOperation::SpdmMeasurementRequestAll,
                        &mut total_number,
                        &mut spdm_measurement_record_structure,
                    )
                    .is_err()
                {
                    println!("{:?} 7, error in send_receive_spdm_measurement", &spdm);
                    return;
                }
            }
            8 => {
                if requester
                    .send_receive_spdm_key_exchange(
                        0,
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                    )
                    .is_err()
                {
                    println!("{:?} 8, error in send_receive_spdm_key_exchange", &spdm);
                    return;
                };
            }
            9 => {
                if requester
                    .send_receive_spdm_psk_exchange(
                        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
                        None,
                    )
                    .is_err()
                {
                    println!("{:?} 9, error in send_receive_spdm_psk_exchange", &spdm);
                    return;
                };
            }
            _ => {}
        }
    }
}

fn permutation(from: &[i32], count: usize, bool_array: &mut [bool], last_vec: Vec<i32>) {
    if last_vec.len() == count {
        run_spdm(last_vec);
        return;
    }

    for (i, &n) in from.iter().enumerate() {
        if bool_array[i] {
            continue;
        }

        let mut last_vec = last_vec.clone();
        last_vec.push(n);
        bool_array[i] = true;

        permutation(from, count, bool_array, last_vec);

        bool_array[i] = false;
    }
}

fn main() {
    let nums = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    permutation(&nums, nums.len(), &mut vec![false; nums.len()], Vec::new());
}
