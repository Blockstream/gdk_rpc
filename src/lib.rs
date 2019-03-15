#![recursion_limit = "128"]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate dirs;
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

use crate::network::Network;
use crate::wallet::Wallet;

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
    network: Option<String>,
    log_level: Option<u32>,
    wallet: Option<Wallet>,
}

impl GA_session {
    fn ptr() -> *const GA_session {
        let sess = GA_session {
            network: None,
            log_level: None,
            wallet: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum GA_auth_handler {
    Error(String),
    Done(Value),
}

impl GA_auth_handler {
    fn error(err: String) -> *const GA_auth_handler {
        let handler = GA_auth_handler::Error(err);
        unsafe { transmute(Box::new(handler)) }
    }
    fn done(res: Value) -> *const GA_auth_handler {
        let handler = GA_auth_handler::Done(res);
        unsafe { transmute(Box::new(handler)) }
    }
    fn success() -> *const GA_auth_handler {
        GA_auth_handler::done(Value::Null)
    }

    fn to_json(&self) -> Value {
        match self {
            GA_auth_handler::Error(err) => json!({ "status": "error", "error": err }),
            GA_auth_handler::Done(res) => json!({ "status": "done", "result": res }),
        }
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

//
// Session & account management
//

#[no_mangle]
pub extern "C" fn GA_create_session(ret: *mut *const GA_session) -> i32 {
    println!("GA_create_session()");
    unsafe {
        *ret = GA_session::ptr();
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
    ret: *mut *const GA_auth_handler,
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
        *ret = GA_auth_handler::success();
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_login(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    password: *const c_char,
    ret: *mut *const GA_auth_handler,
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
        *ret = GA_auth_handler::success();
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
            println!("get_transations failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(txs) => txs,
    };

    // XXX should we free details or should the client?

    unsafe { *ret = GA_json::ptr(json!(txs)) }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_get_transaction_details(
    sess: *const GA_session,
    txid: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let txid = read_str(txid);

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let tx = match wallet.get_transaction(&txid) {
        Err(err) => {
            println!("get_transaction_details failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(tx) => tx,
    };

    unsafe { *ret = GA_json::ptr(tx) }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_get_balance(
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

    let balance = match wallet.get_balance(&details) {
        Err(err) => {
            println!("get_balance failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(balance) => balance,
    };

    unsafe {
        *ret = GA_json::ptr(balance);
    }

    GA_OK
}

//
// Creating transactions
//

#[no_mangle]
pub extern "C" fn GA_create_transaction(
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

    let tx_detail_unsigned = match wallet.create_transaction(&details) {
        Err(err) => {
            println!("create_transaction failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(t) => t,
    };

    unsafe {
        *ret = GA_json::ptr(tx_detail_unsigned);
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_sign_transaction(
    sess: *const GA_session,
    tx_detail_unsigned: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &*sess };
    let tx_detail_unsigned = &unsafe { &*tx_detail_unsigned }.0;

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let tx_detail_signed = match wallet.sign_transaction(&tx_detail_unsigned) {
        Err(err) => {
            println!("sign_transaction failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(t) => t,
    };

    unsafe {
        *ret = GA_auth_handler::done(tx_detail_signed);
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_send_transaction(
    sess: *const GA_session,
    tx_detail_signed: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &*sess };
    let tx_detail_signed = &unsafe { &*tx_detail_signed }.0;

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let txid = match wallet.send_transaction(&tx_detail_signed) {
        Err(err) => {
            println!("send_transaction failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(txid) => txid,
    };

    unsafe {
        *ret = GA_auth_handler::done(json!(txid));
    }

    GA_OK
}

//
// Addresses
//

#[no_mangle]
pub extern "C" fn GA_get_receive_address(
    sess: *const GA_session,
    _subaccount: u32,
    ret: *mut *const c_char,
) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let address = match wallet.get_receive_address() {
        Err(err) => {
            println!("get_receive_address failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(address) => address,
    };

    unsafe { *ret = make_str(address) }

    GA_OK
}

//
// Subaccounts
//

#[no_mangle]
pub extern "C" fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let account = match wallet.get_account(0) {
        Err(err) => {
            println!("get_account failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(account) => account,
    };

    unsafe {
        // always returns a list of a single account
        *ret = GA_json::ptr(json!([account]));
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_get_subaccount(
    sess: *const GA_session,
    index: u32,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let account = match wallet.get_account(index) {
        Err(err) => {
            println!("get_account failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(account) => account,
    };

    unsafe {
        *ret = GA_json::ptr(account);
    }

    GA_OK
}

//
// Auth handler
//

#[no_mangle]
pub extern "C" fn GA_auth_handler_get_status(
    auth_handler: *const GA_auth_handler,
    ret: *mut *const GA_json,
) -> i32 {
    let auth_handler = unsafe { &*auth_handler };
    let status = auth_handler.to_json();

    unsafe {
        *ret = GA_json::ptr(status);
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_destroy_auth_handler(auth_handler: *const GA_auth_handler) -> i32 {
    // TODO make sure this works
    unsafe {
        drop(&*auth_handler);
    }

    GA_OK
}

//
// Currency conversion
//

#[no_mangle]
pub extern "C" fn GA_get_available_currencies(
    sess: *const GA_session,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let currencies = wallet.get_available_currencies();

    unsafe {
        *ret = GA_json::ptr(currencies);
    }

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_amount(
    sess: *const GA_session,
    value_details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let value_details = &unsafe { &*value_details }.0;

    let wallet = match sess.wallet {
        Some(ref wallet) => wallet,
        None => return GA_ERROR,
    };

    let units = match wallet.convert_amount(&value_details) {
        Err(err) => {
            println!("convert_amount failed: {:?}", err);
            return GA_ERROR;
        }
        Ok(units) => units,
    };

    unsafe {
        *ret = GA_json::ptr(units);
    }

    GA_OK
}

// TODO: GA_get_fee_estimates, GA_generate_mnemonic

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    unsafe {
        *ret = make_str(res);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32 {
    let jstr = read_str(jstr);
    let json = serde_json::from_str(&jstr).expect("invalid json for string_to_json");
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

//
// Unimplemented, but gracefully degrades
//

#[no_mangle]
pub extern "C" fn GA_get_system_message(_sess: *const GA_session, ret: *mut *const c_char) -> i32 {
    // an empty string implies no system messages
    unsafe {
        *ret = make_str("".to_string());
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_ack_system_message(
    _sess: *const GA_session,
    _message_text: *const c_char,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    unsafe {
        *ret = GA_auth_handler::success();
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_get_twofactor_config(
    _sess: *const GA_session,
    ret: *mut *const GA_json,
) -> i32 {
    // 2FA is always off
    let res = json!({ "enabled": false });
    unsafe {
        *ret = GA_json::ptr(res);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_set_notification_handler(
    _sess: *const GA_session,
    _handler: *const libc::c_void,
    _context: *const libc::c_void,
) -> i32 {
    // we don't actually register or notify, just report success back
    GA_OK
}

//
// Unimplemented and GA_ERROR's
//

#[no_mangle]
pub extern "C" fn GA_connect_with_proxy(
    _sess: *const GA_session,
    _network: *const c_char,
    _proxy_uri: *const c_char,
    _use_tor: u32,
    _log_level: u32,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_reconnect_hint(_sess: *const GA_session, _hint: *const GA_json) -> i32 {
    // TODO can we just GA_OK and ignore it?
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_login_with_pin(
    _sess: *mut GA_session,
    _pin: *const c_char,
    _pin_data: *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_set_watch_only(
    _sess: *mut GA_session,
    _username: *const c_char,
    _password: *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_watch_only_username(
    _sess: *mut GA_session,
    _ret: *mut *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_login_watch_only(
    _sess: *mut GA_session,
    _username: *const c_char,
    _password: *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_remove_account(
    _sess: *mut GA_session,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_create_subaccount(
    _sess: *const GA_session,
    _details: *const GA_json,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_unspent_outputs(
    _sess: *const GA_session,
    _details: *const GA_json,
    _ret: *mut *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_unspent_outputs_for_private_key(
    _sess: *const GA_session,
    _private_key: *const c_char,
    _password: *const c_char,
    _unused: u32,
    _ret: *mut *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_set_pin(
    _sess: *const GA_session,
    _mnemonic: *const c_char,
    _pin: *const c_char,
    _device_id: *const c_char,
    _ret: *mut *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_broadcast_transaction(
    _sess: *const GA_session,
    _tx_hex: *const c_char,
    _ret: *mut *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_send_nlocktimes(_sess: *const GA_session) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_set_transaction_memo(
    _sess: *const GA_session,
    _txid: *const c_char,
    _memo: *const c_char,
    _memo_type: u32,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_mnemonic_passphrase(
    _sess: *const GA_session,
    _password: *const c_char,
    _ret: *mut *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_encrypt(
    _sess: *const GA_session,
    _data: *const GA_json,
    _ret: *mut *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_decrypt(
    _sess: *const GA_session,
    _data: *const GA_json,
    _ret: *mut *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_change_settings(
    _sess: *const GA_session,
    _settings: *const GA_json,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_settings(_sess: *const GA_session, _ret: *mut *const GA_json) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_auth_handler_request_code(
    _auth_handler: *const GA_auth_handler,
    _method: *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_auth_handler_resolve_code(
    _auth_handler: *const GA_auth_handler,
    _code: *const c_char,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_auth_handler_call(_auth_handler: *const GA_auth_handler) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_change_settings_twofactor(
    _sess: *const GA_session,
    _method: *const c_char,
    _twofactor_details: *const GA_json,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_twofactor_reset(
    _sess: *const GA_session,
    _email: *const c_char,
    _is_dispute: u32,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_twofactor_cancel_reset(
    _sess: *const GA_session,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_twofactor_change_limits(
    _sess: *const GA_session,
    _limit_details: *const GA_json,
    _ret: *mut *const GA_auth_handler,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_validate_mnemonic(_mnemonic: *const c_char, _ret: *mut *const u32) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_register_network(
    _name: *const c_char,
    _network_details: *const GA_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_uniform_uint32_t(_upper_bound: u32, _ret: *mut *const u32) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GA_get_random_bytes(_num_bytes: u32, _ret: *mut *const c_char, _len: u32) -> i32 {
    GA_ERROR
}
