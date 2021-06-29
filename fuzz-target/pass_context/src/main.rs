mod pass_responder;
use pass_responder::*;

mod pass_requester;


fn main() {
    println!("run version");
    pass_rsp_handle_spdm_version();
    println!("run capability");
    pass_rsp_handle_spdm_capability();
    println!("run algorithm");
    pass_rsp_handle_spdm_algorithm();
    println!("run digests");
    pass_rsp_handle_spdm_digest();
    println!("run certificate");
    pass_rsp_handle_spdm_certificate();
    println!("run challenge");
    pass_rsp_handle_spdm_challenge();
    println!("run measurement");
    pass_rsp_handle_spdm_measurement();
    println!("run key exchange");
    pass_rsp_handle_spdm_key_exchange();
    println!("run psk exchange");
    pass_rsp_handle_spdm_psk_exchange();

}
