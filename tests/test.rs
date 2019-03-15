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

    fn GA_create_session(ret: *mut *mut GA_session) -> i32;
    fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32) -> i32;

    fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32;

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
        debug!("registered");

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
        debug!("logged in");

        let details = make_json(json!({ "page": 0 }));
        let mut txs: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_transactions(sess, details, &mut txs));
        debug!("txs: {:#?}\n", json_obj(txs));

        let mut subaccounts: *const GA_json = std::ptr::null_mut();
        assert_eq!(GA_OK, GA_get_subaccounts(sess, &mut subaccounts));
        debug!("subaccounts: {:#?}\n", json_obj(subaccounts));
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
