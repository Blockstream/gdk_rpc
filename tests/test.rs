extern crate libc;
extern crate stderrlog;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;

use serde_json::Value;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

const GA_OK: i32 = 0;

#[repr(C)]
pub struct GA_json {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GA_session {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GA_auth_handler {
    _private: [u8; 0],
}

#[link(name = "gdk_rpc")]
extern "C" {
    fn GA_get_networks(ret: *mut *const GA_json) -> i32;
    fn GA_get_available_currencies(sess: *const GA_session, ret: *mut *const GA_json) -> i32;

    fn GA_create_session(ret: *mut *mut GA_session) -> i32;
    fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32) -> i32;

    fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32;
    fn GA_get_subaccount(sess: *const GA_session, index: u32, ret: *mut *const GA_json) -> i32;

    fn GA_get_receive_address(
        sess: *const GA_session,
        subaccount: u32,
        ret: *mut *const c_char,
    ) -> i32;

    fn GA_get_balance(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_json,
    ) -> i32;

    fn GA_register_user(
        sess: *mut GA_session,
        _hw_device: *const GA_json,
        mnemonic: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    ) -> i32;
    fn GA_login(
        sess: *mut GA_session,
        _hw_device: *const GA_json,
        mnemonic: *const c_char,
        password: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    ) -> i32;

    fn GA_get_transactions(
        sess: *mut GA_session,
        details: *const GA_json,
        ret: *mut *const GA_json,
    ) -> i32;

    fn GA_create_transaction(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_json,
    ) -> i32;

    fn GA_sign_transaction(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GA_send_transaction(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GA_auth_handler_get_status(handler: *const GA_auth_handler, ret: *mut *const GA_json)
        -> i32;
    fn GA_destroy_auth_handler(handler: *const GA_auth_handler) -> i32;

    fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32;
    fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32;
}

#[test]
fn main() {
    //stderrlog::new().module(module_path!()).init().unwrap();
    stderrlog::new().verbosity(3).init().unwrap();

    unsafe {
        let mut nets: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_networks(&mut nets));
        debug!("networks: {:?}\n", json_obj(nets));

        let mut sess: *mut GA_session = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_create_session(&mut sess));
        debug!("obtained session");

        let network = CString::new("regtest").unwrap();
        assert_eq!(GA_OK, GA_connect(sess, network.as_ptr(), 5));
        debug!("connected");

        let hw_device = make_json(json!({ "type": "trezor" }));
        let mnemonic = CString::new(
            "plunge wash chimney soap magic luggage bulk mixed chuckle utility come light",
        )
        .unwrap();
        let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
        assert_eq!(
            GA_OK,
            GA_register_user(sess, hw_device, mnemonic.as_ptr(), &mut auth_handler)
        );
        debug!("register status: {:?}", get_status(auth_handler));

        let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
        let password = CString::new("").unwrap();
        assert_eq!(
            GA_OK,
            GA_login(
                sess,
                hw_device,
                mnemonic.as_ptr(),
                password.as_ptr(),
                &mut auth_handler,
            )
        );
        debug!("log in status: {:?}", get_status(auth_handler));

        let mut currencies: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_available_currencies(sess, &mut currencies));
        debug!("currencies: {:?}\n", json_obj(currencies));

        let details = make_json(json!({ "page": 0 }));
        let mut txs: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_transactions(sess, details, &mut txs));
        debug!("txs: {:#?}\n", json_obj(txs));

        let mut subaccounts: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_subaccounts(sess, &mut subaccounts));
        debug!("subaccounts: {:#?}\n", json_obj(subaccounts));

        let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
        let mut balance: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_balance(sess, details, &mut balance));
        debug!("balance: {:#?}\n", json_obj(balance));

        let mut recv_addr: *const c_char = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_receive_address(sess, 0, &mut recv_addr));
        debug!("recv addr: {:#?}\n", read_str(recv_addr));

        let details = make_json(
            //json!({ "addresses": [ {"address":"bitcoin:2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b?amount=0.001"} ] }),
            json!({ "addresses": [ {"address":"2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b", "satoshi": 569000} ] }),
        );
        let mut tx_detail_unsigned: *const GA_json = std::ptr::null_mut();
        assert_eq!(
            GA_OK,
            GA_create_transaction(sess, details, &mut tx_detail_unsigned)
        );
        debug!("create_transaction: {:#?}\n", json_obj(tx_detail_unsigned));

        let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
        assert_eq!(
            GA_OK,
            GA_sign_transaction(sess, tx_detail_unsigned, &mut auth_handler)
        );
        let sign_status = get_status(auth_handler);
        debug!("sign_transaction status: {:#?}\n", sign_status);

        let tx_detail_signed = make_json(sign_status.get("result").unwrap().clone());
        let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
        assert_eq!(
            GA_OK,
            GA_send_transaction(sess, tx_detail_signed, &mut auth_handler)
        );
        debug!("send_transaction status: {:#?}\n", get_status(auth_handler));
    }
}

fn json_obj(json: *const GA_json) -> Value {
    let mut s: *const c_char = std::ptr::null_mut();
    unsafe { assert_eq!(GA_OK, GA_convert_json_to_string(json, &mut s)) };
    let s = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    serde_json::from_str(&s).unwrap()
}

fn make_json(val: Value) -> *const GA_json {
    let cstr = CString::new(val.to_string()).unwrap();
    let mut json: *const GA_json = std::ptr::null_mut();
    unsafe {
        assert_eq!(GA_OK, GA_convert_string_to_json(cstr.as_ptr(), &mut json));
    }
    json
}

fn get_status(auth_handler: *const GA_auth_handler) -> Value {
    let mut status: *const GA_json = std::ptr::null_mut();
    unsafe { assert_eq!(GA_OK, GA_auth_handler_get_status(auth_handler, &mut status)) }
    json_obj(status)
}

fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}
