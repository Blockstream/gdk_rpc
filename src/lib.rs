#![recursion_limit = "128"]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate jsonrpc;
extern crate libc;
extern crate secp256k1;
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;

pub mod errors;
pub mod network;
pub mod wallet;

use bitcoincore_rpc::RpcApi;
use serde_json::Value;

use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::os::raw::c_char;

use network::Network;
use wallet::Wallet;

const GA_OK: i32 = 0;
const GA_ERROR: i32 = -1;

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
    network: Option<String>,
    log_level: Option<u32>,
    wallet: Option<Wallet>,
}

impl GA_session {
    fn ptr(sid: u32) -> *const GA_session {
        let sess = GA_session {
            sid,
            network: None,
            log_level: None,
            wallet: None,
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
pub extern "C" fn GA_get_networks(ret: *mut *const GA_json) -> i32 {
    unsafe {
        *ret = GA_json::ptr(json!(Network::networks()));
    }
    GA_OK
}

// GA_generate_mnemonic
// GA_encrypt + GA_decrypt - mock

//
// Session & account management
//

#[no_mangle]
pub extern "C" fn GA_create_session(ret: *mut *const GA_session) -> i32 {
    println!("GA_create_session()");
    unsafe {
        *ret = GA_session::ptr(1234);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_destroy_session(sess: *const GA_session) -> i32 {
    unsafe {
        drop(&*sess);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32) -> i32 {
    let sess = unsafe { &mut *sess };
    let network = read_str(network);

    if Network::network(&network).is_none() {
        // network does not exists
        return GA_ERROR;
    }

    let rpc = Network::client(&network).unwrap();
    let wallet = Wallet::new(&rpc);

    sess.network = Some(network);
    sess.log_level = Some(log_level);
    sess.wallet = Some(wallet);

    println!("GA_connect() {:?}", sess);

    println!("GA_connect() client: {:?}", rpc.get_blockchain_info());
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_disconnect(sess: *mut GA_session) -> i32 {
    let sess = unsafe { &mut *sess };
    sess.network = None;
    println!("GA_disconnect() {:?}", sess);
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_register_user(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    auth_handler: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &mut *sess };
    let wallet = sess.wallet.as_ref().unwrap();

    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);

    println!("GA_register_user({}) {:?}", mnemonic, sess);

    if let Err(err) = wallet.register(&mnemonic) {
        println!("failed registering wallet: {}", err);
        return GA_ERROR;
    }

    unsafe {
        *auth_handler = GA_auth_handler::ptr(0);
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_login(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    password: *const c_char,
    auth_handler: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &mut *sess };
    let wallet = sess.wallet.as_ref().unwrap();

    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);

    if read_str(password).len() > 0 {
        println!("password-encrypted mnemonics are unsupported");
        return GA_ERROR;
    }

    if let Err(err) = wallet.login(&mnemonic) {
        println!("login failed: {}", err);
        return GA_ERROR;
    }

    unsafe {
        *auth_handler = GA_auth_handler::ptr(0);
    }

    println!("GA_login({}) {:?}", mnemonic, sess);
    GA_OK
}

//
// Transactions & Coins
//

#[no_mangle]
pub extern "C" fn GA_get_transactions(
    sess: *const GA_session,
    details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let details = &unsafe { &*details }.0;

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let txs = match wallet.get_transactions(&details) {
        Err(err) => {
            println!("Wallet::list_transactions() failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(txs) => txs,
    };

    // XXX should we free details or should the client?

    unsafe { *ret = GA_json::ptr(json!(txs)) }

    GA_OK
}

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    println!("GA_convert_json {:?} => {:?}", json, res);
    unsafe {
        *ret = make_str(res);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32 {
    let jstr = read_str(jstr);
    let json = serde_json::from_str(&jstr).expect("invalid json for string_to_json");
    println!("GA_convert_string {:?} => {:?}", jstr, json);
    unsafe {
        *ret = GA_json::ptr(json);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_string(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = json.get(&path).expect("path missing").to_string();
    println!("GA_convert_json_value_to_string {:?} => {:?}", path, res);
    unsafe {
        *ret = make_str(res);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint32(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u32,
) -> i32 {
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
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint64(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u64,
) -> i32 {
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
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_json(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let jstr = json.get(&path).expect("path missing").to_string();
    let res = serde_json::from_str(&jstr).expect("invaliud json for json_value_to_json");
    println!("GA_convert_json_value_to_json {:?} => {:?}", path, res);
    unsafe {
        *ret = GA_json::ptr(res);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_destroy_json(ptr: *mut GA_json) -> i32 {
    // TODO make sure this works
    unsafe {
        drop(&*ptr);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_destroy_string(ptr: *mut c_char) -> i32 {
    unsafe {
        // retake pointer and drop
        let _ = CString::from_raw(ptr);
    }
    GA_OK
}
