#![recursion_limit = "128"]

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate chrono;
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
#[macro_use]
extern crate log;

pub mod errors;
pub mod network;
pub mod wallet;

use serde_json::Value;

use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::os::raw::c_char;

use crate::errors::OptionExt;
use crate::network::Network;
use crate::wallet::Wallet;

const GA_OK: i32 = 0;
const GA_ERROR: i32 = -1;

const GA_TRUE: u32 = 1;
const GA_FALSE: u32 = 0;

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
    push: Option<(
        extern "C" fn(*const libc::c_void, *const GA_json),
        *const libc::c_void,
    )>,
}

impl GA_session {
    fn ptr() -> *const GA_session {
        let sess = GA_session {
            network: None,
            log_level: None,
            wallet: None,
            push: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }

    fn wallet(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    fn push(&self, data: Value) {
        debug!("push notification: {:?}", data);
        if let Some((handler, context)) = self.push {
            handler(context, GA_json::ptr(data));
        }
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
// Macros
//

macro_rules! try_ret {
    ($x:expr) => {
        match $x {
            Err(err) => {
                debug!("error: {:?}", err);
                return GA_ERROR;
            }
            Ok(x) => x,
        }
    };
}

macro_rules! ret_ptr {
    ($t:expr, $x:expr) => {
        unsafe {
            *$t = $x;
            return GA_OK;
        };
    };
}

macro_rules! ret_json {
    ($t:expr, $x:expr) => {
        ret_ptr!($t, GA_json::ptr(json!($x)));
    };
}

//
// Networks
//

#[no_mangle]
pub extern "C" fn GA_get_networks(ret: *mut *const GA_json) -> i32 {
    ret_json!(ret, Network::networks())
}

//
// Session & account management
//

#[no_mangle]
pub extern "C" fn GA_create_session(ret: *mut *const GA_session) -> i32 {
    debug!("GA_create_session()");
    ret_ptr!(ret, GA_session::ptr())
}

#[no_mangle]
pub extern "C" fn GA_destroy_session(sess: *const GA_session) -> i32 {
    unsafe {
        drop(&*sess);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_connect(
    sess: *mut GA_session,
    network_name: *const c_char,
    log_level: u32,
) -> i32 {
    let sess = unsafe { &mut *sess };

    let network_name = read_str(network_name);
    let network = try_ret!(Network::network(&network_name).or_err("missing network"));
    let rpc = try_ret!(network.connect());
    let wallet = Wallet::new(rpc);

    sess.network = Some(network_name);
    sess.log_level = Some(log_level);
    sess.wallet = Some(wallet);

    debug!("GA_connect() {:?}", sess);
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_disconnect(sess: *mut GA_session) -> i32 {
    let sess = unsafe { &mut *sess };
    sess.network = None;
    // TODO cleanup rpc connection
    sess.wallet = None;
    debug!("GA_disconnect() {:?}", sess);
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
    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);

    debug!("GA_register_user({}) {:?}", mnemonic, sess);

    try_ret!(wallet.register(&mnemonic));

    ret_ptr!(ret, GA_auth_handler::success());
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
    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    // hw_device is currently ignored
    let mnemonic = read_str(mnemonic);

    if read_str(password).len() > 0 {
        warn!("password-encrypted mnemonics are unsupported");
        return GA_ERROR;
    }

    debug!("GA_login({}) {:?}", mnemonic, sess);

    try_ret!(wallet.login(&mnemonic));

    ret_ptr!(ret, GA_auth_handler::success());
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

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let txs = try_ret!(wallet.get_transactions(&details));

    // XXX should we free details or should the client?

    ret_json!(ret, txs)
}

#[no_mangle]
pub extern "C" fn GA_get_transaction_details(
    sess: *const GA_session,
    txid: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let txid = read_str(txid);

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let tx = try_ret!(wallet.get_transaction(&txid));

    ret_json!(ret, tx)
}

#[no_mangle]
pub extern "C" fn GA_get_balance(
    sess: *const GA_session,
    details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let details = &unsafe { &*details }.0;

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let balance = try_ret!(wallet.get_balance(&details));

    ret_json!(ret, balance)
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

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let tx_detail_unsigned = try_ret!(wallet.create_transaction(&details));

    ret_json!(ret, tx_detail_unsigned)
}

#[no_mangle]
pub extern "C" fn GA_sign_transaction(
    sess: *const GA_session,
    tx_detail_unsigned: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &*sess };
    let tx_detail_unsigned = &unsafe { &*tx_detail_unsigned }.0;

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let tx_detail_signed = try_ret!(wallet.sign_transaction(&tx_detail_unsigned));

    ret_ptr!(ret, GA_auth_handler::done(tx_detail_signed));
}

#[no_mangle]
pub extern "C" fn GA_send_transaction(
    sess: *const GA_session,
    tx_detail_signed: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = unsafe { &*sess };
    let tx_detail_signed = &unsafe { &*tx_detail_signed }.0;

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let txid = try_ret!(wallet.send_transaction(&tx_detail_signed));

    ret_ptr!(ret, GA_auth_handler::done(json!(txid)));
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

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let address = try_ret!(wallet.get_receive_address());

    ret_ptr!(ret, make_str(address))
}

//
// Subaccounts
//

#[no_mangle]
pub extern "C" fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let account = try_ret!(wallet.get_account(0));

    // always returns a list of a single account
    ret_json!(ret, [account])
}

#[no_mangle]
pub extern "C" fn GA_get_subaccount(
    sess: *const GA_session,
    index: u32,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let account = try_ret!(wallet.get_account(index));

    ret_json!(ret, account)
}

//
// Mnemonic
//

#[no_mangle]
pub extern "C" fn GA_generate_mnemonic(ret: *mut *const c_char) -> i32 {
    let mnemonic = Wallet::generate_mnemonic();

    ret_ptr!(ret, make_str(mnemonic))
}

#[no_mangle]
pub extern "C" fn GA_validate_mnemonic(mnemonic: *const c_char, ret: *mut u32) -> i32 {
    let mnemonic = read_str(mnemonic);
    let is_valid = if Wallet::validate_mnemonic(mnemonic) {
        GA_TRUE
    } else {
        GA_FALSE
    };

    ret_ptr!(ret, is_valid)
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

    ret_json!(ret, status)
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
// Currency conversion & fees
//

#[no_mangle]
pub extern "C" fn GA_get_available_currencies(
    sess: *const GA_session,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let currencies = wallet.get_available_currencies();

    ret_json!(ret, currencies)
}

#[no_mangle]
pub extern "C" fn GA_convert_amount(
    sess: *const GA_session,
    value_details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sess = unsafe { &*sess };
    let value_details = &unsafe { &*value_details }.0;

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let units = try_ret!(wallet.convert_amount(&value_details));

    ret_json!(ret, units)
}
#[no_mangle]
pub extern "C" fn GA_get_fee_estimates(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sess = unsafe { &*sess };

    let wallet = try_ret!(sess.wallet().or_err("no loaded wallet"));

    let estimates = try_ret!(wallet.get_fee_estimates());

    ret_json!(ret, estimates)
}

//
// Push notifications
//

#[no_mangle]
pub extern "C" fn GA_set_notification_handler(
    sess: *mut GA_session,
    handler: extern "C" fn(*const libc::c_void, *const GA_json),
    context: *const libc::c_void,
) -> i32 {
    let sess = unsafe { &mut *sess };
    sess.push = Some((handler, context));
    sess.push(json!({ "init": "hello world" }));
    GA_OK
}

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    ret_ptr!(ret, make_str(res))
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32 {
    let jstr = read_str(jstr);
    let json: Value = serde_json::from_str(&jstr).expect("invalid json for string_to_json");
    ret_json!(ret, json)
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
    ret_ptr!(ret, make_str(res))
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
    ret_ptr!(ret, res)
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
    ret_ptr!(ret, res)
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
    let res: Value = serde_json::from_str(&jstr).expect("invaliud json for json_value_to_json");
    ret_json!(ret, res)
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
    ret_ptr!(ret, make_str("".to_string()))
}

#[no_mangle]
pub extern "C" fn GA_ack_system_message(
    _sess: *const GA_session,
    _message_text: *const c_char,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    ret_ptr!(ret, GA_auth_handler::success())
}

#[no_mangle]
pub extern "C" fn GA_get_twofactor_config(
    _sess: *const GA_session,
    ret: *mut *const GA_json,
) -> i32 {
    // 2FA is always off
    ret_json!(ret, json!({ "enabled": false }))
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
