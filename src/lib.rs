extern crate bitcoincore_rpc;
extern crate serde;
#[macro_use]
extern crate serde_json;
extern crate libc;

use serde_json::Value;

use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::os::raw::c_char;

// TODO: return status

#[derive(Debug)]
#[repr(C)]
pub struct GA_json(Value);

impl GA_json {
    fn ptr(data: Value) -> *const GA_json {
        unsafe { transmute(Box::new(GA_json(data))) }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct GA_session {
    sid: u32,
    uid: Option<u32>,
    network: Option<String>,
    log_level: Option<u32>,
}

impl GA_session {
    fn ptr(sid: u32) -> *const GA_session {
        let sess = GA_session {
            sid,
            uid: None,
            network: None,
            log_level: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct GA_auth_handler(u32);
impl GA_auth_handler {
    fn ptr(method: u32) -> *const GA_auth_handler {
        let handler = GA_auth_handler(method);
        unsafe { transmute(Box::new(handler)) }
    }
}

fn make_str(data: String) -> *const c_char {
    CString::new(data).unwrap().into_raw()
}

fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}

//
// Networks
//

#[no_mangle]
pub extern "C" fn GA_get_networks(ret: *mut *const GA_json) {
    unsafe {
        *ret = GA_json::ptr(json!([ {
            "address_explorer_url": "https://blockstream.info/address/",
            "bech32_prefix": "bc",
            "default_peers": [],
            "development": false,
            "liquid": false,
            "mainnet": true,
            "name": "Bitcoin",
            "network": "mainnet",
            "p2pkh_version": 0,
            "p2sh_version": 5,
            "service_chain_code": "",
            "service_pubkey": "",
            "tx_explorer_url": "https://blockstream.info/tx/",
            "wamp_cert_pins": [],
            "wamp_onion_url": "",
            "wamp_url": ""
        } ]));
    }
}

// GA_generate_mnemonic
// GA_encrypt + GA_decrypt - mock

//
// Session & account management
//

#[no_mangle]
pub extern "C" fn GA_create_session(ret: *mut *const GA_session) {
    println!("GA_create_session()");
    unsafe {
        *ret = GA_session::ptr(1234);
    }
}

#[no_mangle]
pub extern "C" fn GA_destroy_session(sess: *const GA_session) {
    unsafe {
        drop(&*sess);
    }
}

#[no_mangle]
pub extern "C" fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32) {
    let sess = unsafe { &mut *sess };
    let network = read_str(network);
    sess.network = Some(network);
    sess.log_level = Some(log_level);
    println!("GA_connect() {:?}", sess);
}

#[no_mangle]
pub extern "C" fn GA_disconnect(sess: *mut GA_session) {
    let sess = unsafe { &mut *sess };
    sess.network = None;
    println!("GA_disconnect() {:?}", sess);
}

#[no_mangle]
pub extern "C" fn GA_register_user(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    auth_handler: *mut *const GA_auth_handler,
) {
    let sess = unsafe { &mut *sess };
    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);

    sess.uid = Some(9876);
    unsafe {
        *auth_handler = GA_auth_handler::ptr(0);
    }

    println!("GA_register_user({}) {:?}", mnemonic, sess);
}

#[no_mangle]
pub extern "C" fn GA_login(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    password: *const c_char,
    auth_handler: *mut *const GA_auth_handler,
) {
    let sess = unsafe { &mut *sess };
    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);
    let password = read_str(password);

    sess.uid = Some(9876);
    unsafe {
        *auth_handler = GA_auth_handler::ptr(0);
    }

    println!("GA_login({}, {}) {:?}", mnemonic, password, sess);
}

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    println!("GA_convert_json {:?} => {:?}", json, res);
    unsafe {
        *ret = make_str(res);
    }
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) {
    let jstr = read_str(jstr);
    let json = serde_json::from_str(&jstr).expect("invalid json for string_to_json");
    println!("GA_convert_string {:?} => {:?}", jstr, json);
    unsafe {
        *ret = GA_json::ptr(json);
    }
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_string(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const c_char,
) {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = json.get(&path).expect("path missing").to_string();
    println!("GA_convert_json_value_to_string {:?} => {:?}", path, res);
    unsafe {
        *ret = make_str(res);
    }
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint32(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u32,
) {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = json
        .get(&path)
        .expect("path missing")
        .as_u64()
        .expect("invalid number") as u32;
    println!("GA_convert_json_value_to_uint32 {:?} => {:?}", path, res);
    unsafe {
        *ret = res;
    }
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint64(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u64,
) {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = json
        .get(&path)
        .expect("path missing")
        .as_u64()
        .expect("invalid number");
    println!("GA_convert_json_value_to_uint64 {:?} => {:?}", path, res);
    unsafe {
        *ret = res;
    }
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_json(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const GA_json,
) {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let jstr = json.get(&path).expect("path missing").to_string();
    let res = serde_json::from_str(&jstr).expect("invaliud json for json_value_to_json");
    println!("GA_convert_json_value_to_json {:?} => {:?}", path, res);
    unsafe {
        *ret = GA_json::ptr(res);
    }
}

#[no_mangle]
pub extern "C" fn GA_destroy_json(ptr: *mut GA_json) {
    // TODO make sure this works
    unsafe {
        drop(&*ptr);
    }
}

#[no_mangle]
pub extern "C" fn GA_destroy_string(ptr: *mut c_char) {
    unsafe {
        // retake pointer and drop
        let _ = CString::from_raw(ptr);
    }
}
