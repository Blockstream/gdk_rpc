extern crate libc;
#[macro_use]
extern crate serde_json;

use serde_json::Value;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

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
    fn GA_get_networks(ret: *mut *const GA_json);
    fn GA_create_session(ret: *mut *mut GA_session);
    fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32);
    fn GA_register_user(
        sess: *mut GA_session,
        _hw_device: *const GA_json,
        mnemonic: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    );
    fn GA_login(
        sess: *mut GA_session,
        _hw_device: *const GA_json,
        mnemonic: *const c_char,
        password: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    );

    fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char);
    fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json);
}

#[test]
fn main() {
    unsafe {
        let mut nets: *const GA_json = std::ptr::null_mut();
        GA_get_networks(&mut nets);
        println!("networks: {:#?}\n", json_obj(nets));

        let mut sess: *mut GA_session = std::ptr::null_mut();
        GA_create_session(&mut sess);

        let network = CString::new("regtest").unwrap();
        GA_connect(sess, network.as_ptr(), 5);

        let hw_device = make_json(json!({ "type": "trezor" }));
        let mnemonic = CString::new("kite kite kite").unwrap();
        let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
        GA_register_user(sess, hw_device, mnemonic.as_ptr(), &mut auth_handler);

        let password = CString::new("horse battery").unwrap();
        GA_login(
            sess,
            hw_device,
            mnemonic.as_ptr(),
            password.as_ptr(),
            &mut auth_handler,
        );
    }
}

fn json_obj(json: *const GA_json) -> Value {
    let mut s: *const c_char = std::ptr::null_mut();
    unsafe { GA_convert_json_to_string(json, &mut s) };
    let s = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    serde_json::from_str(&s).unwrap()
}

fn make_json(val: Value) -> *const GA_json {
    let cstr = CString::new(val.to_string()).unwrap();
    let mut json: *const GA_json = std::ptr::null_mut();
    unsafe {
        GA_convert_string_to_json(cstr.as_ptr(), &mut json);
    }
    json
}
