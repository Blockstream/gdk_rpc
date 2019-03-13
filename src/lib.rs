extern crate bitcoincore_rpc;
extern crate serde;
#[macro_use]
extern crate serde_json;
extern crate libc;

use serde_json::Value;

use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::os::raw::c_char;

#[repr(C)]
pub struct GA_json(Value);

fn ptr(data: Value) -> *const GA_json {
    unsafe { transmute(Box::new(GA_json(data))) }
}

fn ret_str(output: &mut c_char, data: String) {
    let cstr = CString::new(data).unwrap();
    unsafe {
        libc::strcpy(output, cstr.as_ptr());
    }
}

#[no_mangle]
pub extern "C" fn GA_get_networks(output: &mut *const GA_json) {
    *output = ptr(json!([ {
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

// GA_create_session + GA_destroy_session
// GA_connect + GA_disconnect
// GA_register
// GA_generate_mnemonic
// GA_encrypt + GA_decrypt - mock


#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, output: &mut c_char) {
    let j = unsafe { &*json };
    let res = j.0.to_string();
    println!("GA_convert_json {:?} => {:?}", j.0, res);
    ret_str(output, res);
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(input: *const c_char, output: &mut *const GA_json) {
    let cstr = unsafe { CStr::from_ptr(input) };
    let jstr = cstr.to_str().expect("invalid string for string_to_json");
    println!("GA_convert_string {:?}", jstr);
    *output = ptr(serde_json::from_str(&jstr).expect("invalid json for string_to_json"));
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_string(
    json: *const GA_json,
    path: *const c_char,
    output: &mut c_char,
) {
    let j = unsafe { &*json };
    let path = unsafe { CStr::from_ptr(path) }
        .to_str()
        .expect("invalid path");
    let res = j.0.get(&path).expect("path missing").to_string();
    println!("GA_convert_json_value_to_string {:?} => {:?}", path, res);
    ret_str(output, res);
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint32(
    json: *const GA_json,
    path: *const c_char,
    output: &mut u32,
) {
    let j = unsafe { &*json };
    let path = unsafe { CStr::from_ptr(path) }
        .to_str()
        .expect("invalid path");
    let res = j
        .0
        .get(&path)
        .expect("path missing")
        .as_u64()
        .expect("invalid number") as u32;
    println!("GA_convert_json_value_to_uint32 {:?} => {:?}", path, res);
    *output = res;
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint64(
    json: *const GA_json,
    path: *const c_char,
    output: &mut u64,
) {
    let j = unsafe { &*json };
    let path = unsafe { CStr::from_ptr(path) }
        .to_str()
        .expect("invalid path");
    let res = j
        .0
        .get(&path)
        .expect("path missing")
        .as_u64()
        .expect("invalid number");
    println!("GA_convert_json_value_to_uint64 {:?} => {:?}", path, res);
    *output = res;
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_json(
    json: *const GA_json,
    path: *const c_char,
    output: &mut *const GA_json,
) {
    let j = unsafe { &*json };
    let path = unsafe { CStr::from_ptr(path) }
        .to_str()
        .expect("invalid path");
    let jstr = j.0.get(&path).expect("path missing").to_string();
    let res = serde_json::from_str(&jstr).expect("invaliud json for json_value_to_json");
    println!("GA_convert_json_value_to_json {:?} => {:?}", path, res);
    *output = ptr(res);
}

#[no_mangle]
pub extern "C" fn GA_destroy_json(ptr: *const GA_json) {
    // TODO make sure this works
    unsafe {
        drop(&*ptr);
    }
}
