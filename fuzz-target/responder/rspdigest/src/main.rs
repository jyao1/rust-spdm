use fuzzlib::*;

fn fuzz_handle_spdm_digest(data: &[u8]) {
    let (config_info, provision_info) = rsp_create_info();
    let pcidoe_transport_encap = &mut PciDoeTransportEncap {};
    let mctp_transport_encap = &mut MctpTransportEncap {};

    spdmlib::crypto::asym_sign::register(ASYM_SIGN_IMPL);

    let shared_buffer = SharedBuffer::new();
    let mut socket_io_transport = FakeSpdmDeviceIoReceve::new(&shared_buffer);

    let mut context = responder::ResponderContext::new(
        &mut socket_io_transport,
        if USE_PCIDOE {
            pcidoe_transport_encap
        } else {
            mctp_transport_encap
        },
        config_info,
        provision_info,
    );

    context.handle_spdm_algorithm(&[
        17, 227, 4, 0, 48, 0, 1, 0, 128, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 2, 32, 16, 0, 3, 32, 2, 0, 4, 32, 2, 0, 5, 32, 1, 0,
    ]);
    context.handle_spdm_digest(data);
    let mut req_buf = [0u8; 1024];
    socket_io_transport.receive(&mut req_buf).unwrap();
    println!("Received: {:?}", req_buf);
}
fn main() {
    #[cfg(feature = "fuzzlog")]
    flexi_logger::Logger::try_with_str("info")
        .unwrap()
        .log_to_file(
            FileSpec::default()
                .directory("digest")
                .basename("foo")
                .discriminant("Sample4711A")
                .suffix("trc"),
        )
        .print_message()
        .create_symlink("current_run")
        .start()
        .unwrap();

    afl::fuzz!(|data: &[u8]| {
        fuzz_handle_spdm_digest(data);
    });
}
