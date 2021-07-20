// import commonly used items from the prelude:
use rand::prelude::*;
use fuzzlib::*;

fn main() {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    // let mctp_transport_encap = &mut MctpTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);


    let mut responder = responder::ResponderContext::new(
        &mut device_io_responder,
        pcidoe_transport_encap,
        rsp_config_info,
        rsp_provision_info,
    );


    let pcidoe_transport_encap2 = &mut PciDoeTransportEncap {};
    let mut device_io_requester = fake_device_io::FakeSpdmDeviceIo::new(&shared_buffer, &mut responder);

    let mut requester = requester::RequesterContext::new(
        &mut device_io_requester,
        pcidoe_transport_encap2,
        req_config_info,
        req_provision_info   
    );

    fn non_repetitive_sequence() -> Vec<[u8;9]> {
        let mut sequence = Vec::new();
        
        sequence.push([1,2,3,4,5,6,7,8,9]);
        sequence

    }
    let mut sequence = non_repetitive_sequence(); 
    while let Some(list) = sequence.pop() {
        for i in list.iter() {
            match i {
                1 => {requester.send_receive_spdm_version().expect("version error")},
                2 => {requester.send_receive_spdm_capability().expect("cabability error")},
                3 => {requester.send_receive_spdm_algorithm().expect("algorithms error")},
                4 => {requester.send_receive_spdm_digest().expect("digest error")},
                5 => {requester.send_receive_spdm_certificate(0).expect("certificate error")},
                6 => {requester.send_receive_spdm_challenge(0,SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone).expect("challenge error")},
                7 => {requester.send_receive_spdm_measurement(SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber, 0).expect("measurement error")},
                8 => {requester.send_receive_spdm_key_exchange(0, SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone).expect("key_exchange error");},
                9 => {requester.send_receive_spdm_psk_exchange(SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone).expect("key_exchange error");},
                _ => {}
            }
        }
    }

}