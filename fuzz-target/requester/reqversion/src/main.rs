
use fuzzlib::*;
use log::LevelFilter;
use simple_logger::SimpleLogger;

static mut FUZZBUFFER: &[u8] = &[0];

struct FuzzSpdmDeviceIoReceve<'a> {
    data: &'a SharedBuffer
}

impl<'a> FuzzSpdmDeviceIoReceve<'a> {
    pub fn new(data: &'a SharedBuffer) -> Self {
        FuzzSpdmDeviceIoReceve {
            data: data
        }
    }
}

impl SpdmDeviceIo for FuzzSpdmDeviceIoReceve<'_> {

    fn receive(&mut self, read_buffer: &mut [u8]) -> Result<usize, usize> {
        let len = self.data.get_buffer(read_buffer);
        log::info!("responder receive RAW - {:02x?}\n", &read_buffer[0..len]);
        Ok(len)
    }

    fn send(&mut self, buffer: &[u8]) -> SpdmResult {
        unsafe{self.data.set_buffer(FUZZBUFFER)};
        log::info!("responder send    RAW - {:02x?}\n", buffer);
        Ok(())
    }

    fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}


fn fuzz_send_receive_spdm_version() {
    let (rsp_config_info, rsp_provision_info) = rsp_create_info();
    let (req_config_info, req_provision_info) = req_create_info();

    let shared_buffer = SharedBuffer::new();
    let mut device_io_responder = FuzzSpdmDeviceIoReceve::new(&shared_buffer);

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

    if requester.send_receive_spdm_version().is_err() {
        panic!("send receive spdm version error");
    }
}

fn new_logger_from_env() -> SimpleLogger {
    let level = match std::env::var("SPDM_LOG") {
        Ok(x) => match x.to_lowercase().as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            _ => LevelFilter::Error,
        },
        _ => LevelFilter::Trace,
    };

    SimpleLogger::new().with_level(level)
}


fn main() {

    new_logger_from_env().init().unwrap(); 
    
    unsafe {
        FUZZBUFFER = &[01, 00, 01, 00, 05, 00, 00, 00, 11, 04, 00, 00, 00, 02, 00, 10, 00, 11, 00, 00];
    }
    
    fuzz_send_receive_spdm_version();
}
