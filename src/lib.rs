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
#[cfg(feature = "android_logger")]
extern crate android_log;
#[cfg(feature = "stderr_logger")]
extern crate stderrlog;

pub mod constants;
pub mod errors;
pub mod network;
pub mod session;
pub mod settings;
pub mod util;
pub mod wallet;

use serde_json::{from_value, Value};

use std::ffi::CString;
use std::mem::transmute;
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

#[cfg(feature = "android_logger")]
use std::sync::{Once, ONCE_INIT};

use crate::constants::{GA_ERROR, GA_FALSE, GA_OK, GA_TRUE};
use crate::errors::OptionExt;
use crate::network::Network;
use crate::session::{spawn_ticker, GA_session, SessionManager};
use crate::util::{log_filter, make_str, read_str};
use crate::wallet::{
    generate_mnemonic, hex_to_mnemonic, mnemonic_to_hex, validate_mnemonic, Wallet,
};

lazy_static! {
    static ref SESS_MANAGER: Arc<Mutex<SessionManager>> = {
        let sm = SessionManager::new();
        spawn_ticker(Arc::clone(&sm));
        sm
    };
}

#[derive(Debug)]
#[repr(C)]
pub struct GA_json(Value);

impl GA_json {
    fn new(data: Value) -> *const GA_json {
        unsafe { transmute(Box::new(GA_json(data))) }
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

//
// Macros
//

macro_rules! tryit {
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

macro_rules! ok {
    ($t:expr, $x:expr) => {
        unsafe {
            *$t = $x;
            GA_OK
        }
    };
}

macro_rules! ok_json {
    ($t:expr, $x:expr) => {
        ok!($t, GA_json::new(json!($x)))
    };
}

//
// Networks
//

#[no_mangle]
pub extern "C" fn GA_get_networks(ret: *mut *const GA_json) -> i32 {
    let networks = Network::list();
    let names: Vec<String> = networks.keys().cloned().collect();

    let mut networks = json!(networks);
    let networks = networks.as_object_mut().unwrap();
    networks.insert("all_networks".to_string(), json!(names));

    ok_json!(ret, networks)
}
//
// Session & account management
//

#[cfg(feature = "android_logger")]
static INIT_LOGGER: Once = ONCE_INIT;

#[no_mangle]
pub extern "C" fn GA_create_session(ret: *mut *const GA_session) -> i32 {
    debug!("GA_create_session()");

    #[cfg(feature = "android_logger")]
    INIT_LOGGER.call_once(|| android_log::init("gdk_rpc").unwrap());

    let mut sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.register();

    ok!(ret, sess)
}

#[no_mangle]
pub extern "C" fn GA_destroy_session(sess: *mut GA_session) -> i32 {
    let mut sm = SESS_MANAGER.lock().unwrap();
    tryit!(sm.remove(sess));
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_connect(
    sess: *mut GA_session,
    network_name: *const c_char,
    log_level: u32,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();
    let network_name = read_str(network_name);

    let network = tryit!(Network::get(&network_name).or_err("missing network"));
    let rpc = tryit!(network.connect());
    let wallet = Wallet::new(rpc);

    log::set_max_level(log_filter(log_level));

    sess.network = Some(network_name);
    sess.wallet = Some(wallet);

    debug!("GA_connect() {:?}", sess);

    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_disconnect(sess: *mut GA_session) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();
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
    println!("GA_register_user1()");
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();
    let mnemonic = read_str(mnemonic);

    debug!("GA_register_user({}) {:?}", mnemonic, sess);

    let wallet = tryit!(sess.wallet_mut().or_err("no loaded wallet"));
    tryit!(wallet.register(&mnemonic));

    ok!(ret, GA_auth_handler::success())
}

#[no_mangle]
pub extern "C" fn GA_login(
    sess: *mut GA_session,
    _hw_device: *const GA_json,
    mnemonic: *const c_char,
    password: *const c_char,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();
    let mnemonic = read_str(mnemonic);

    if read_str(password).len() > 0 {
        warn!("password-encrypted mnemonics are unsupported");
        return GA_ERROR;
    }

    debug!("GA_login({}) {:?}", mnemonic, sess);

    let wallet = tryit!(sess.wallet_mut().or_err("no loaded wallet"));
    tryit!(wallet.login(&mnemonic));

    tryit!(sess.hello());

    ok!(ret, GA_auth_handler::success())
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
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let details = &unsafe { &*details }.0;

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let txs = tryit!(wallet.get_transactions(&details));

    // XXX should we free details or should the client?

    ok_json!(ret, txs)
}

#[no_mangle]
pub extern "C" fn GA_get_transaction_details(
    sess: *const GA_session,
    txid: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let txid = read_str(txid);

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let tx = tryit!(wallet.get_transaction(&txid));

    ok_json!(ret, tx)
}

#[no_mangle]
pub extern "C" fn GA_get_balance(
    sess: *const GA_session,
    details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let details = &unsafe { &*details }.0;

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let balance = tryit!(wallet.get_balance(&details));

    ok_json!(ret, balance)
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
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let details = &unsafe { &*details }.0;

    debug!("GA_create_transaction() {:?}", details);

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));

    // we need to echo "addressees" back, so that the output of GA_create_transaction
    // can be beed back into it as input
    let addressees = &details["addressees"];

    let tx_unsigned = match wallet.create_transaction(&details) {
        Err(err) => {
            // errors are returned as a GA_OK with "error" in the returned object
            debug!("GA_create_transaction error: {:?}", err);
            return ok_json!(
                ret,
                json!({ "error": err.to_string(), "addressees": addressees })
            );
        }
        Ok(x) => x,
    };

    debug!("GA_create_transaction() tx_unsigned {}", tx_unsigned);

    ok_json!(
        ret,
        json!({ "error": "", "hex": tx_unsigned, "addressees": addressees })
    )
}

#[no_mangle]
pub extern "C" fn GA_sign_transaction(
    sess: *const GA_session,
    tx_detail_unsigned: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let tx_detail_unsigned = &unsafe { &*tx_detail_unsigned }.0;

    debug!("GA_sign_transaction() {:?}", tx_detail_unsigned);

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let tx_signed = tryit!(wallet.sign_transaction(&tx_detail_unsigned));

    debug!("GA_sign_transaction() {:?}", tx_signed);

    ok!(
        ret,
        GA_auth_handler::done(json!({ "error": "", "hex": tx_signed }))
    )
}

#[no_mangle]
pub extern "C" fn GA_send_transaction(
    sess: *const GA_session,
    tx_detail_signed: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let tx_detail_signed = &unsafe { &*tx_detail_signed }.0;

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let txid = tryit!(wallet.send_transaction(&tx_detail_signed));

    ok!(
        ret,
        GA_auth_handler::done(json!({ "error": "", "txid": txid }))
    )
}

#[no_mangle]
pub extern "C" fn GA_broadcast_transaction(
    sess: *const GA_session,
    tx_hex: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let tx_hex = read_str(tx_hex);

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let txid = tryit!(wallet.send_raw_transaction(&tx_hex));

    ok!(ret, make_str(txid))
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
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let address = tryit!(wallet.get_receive_address());

    ok!(ret, make_str(address))
}

//
// Subaccounts
//

#[no_mangle]
pub extern "C" fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let account = tryit!(wallet.get_account(0));

    // always returns a list of a single account
    ok_json!(ret, [account])
}

#[no_mangle]
pub extern "C" fn GA_get_subaccount(
    sess: *const GA_session,
    index: u32,
    ret: *mut *const GA_json,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let account = tryit!(wallet.get_account(index));

    ok_json!(ret, account)
}

//
// Mnemonic
//

#[no_mangle]
pub extern "C" fn GA_generate_mnemonic(ret: *mut *const c_char) -> i32 {
    let mnemonic = generate_mnemonic();

    ok!(ret, make_str(mnemonic))
}

#[no_mangle]
pub extern "C" fn GA_validate_mnemonic(mnemonic: *const c_char, ret: *mut u32) -> i32 {
    let mnemonic = read_str(mnemonic);
    let is_valid = if validate_mnemonic(mnemonic) {
        GA_TRUE
    } else {
        GA_FALSE
    };

    ok!(ret, is_valid)
}

#[no_mangle]
pub extern "C" fn GA_get_mnemonic_passphrase(
    sess: *const GA_session,
    _password: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));

    let mnemonic = tryit!(wallet.mnemonic().or_err("mnemonic unavailable"));

    ok!(ret, make_str(mnemonic))
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

    ok_json!(ret, status)
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
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let currencies = wallet.get_available_currencies();

    ok_json!(ret, currencies)
}

#[no_mangle]
pub extern "C" fn GA_convert_amount(
    sess: *const GA_session,
    value_details: *const GA_json,
    ret: *mut *const GA_json,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();
    let value_details = &unsafe { &*value_details }.0;

    debug!("GA_convert_amount() {:?}", value_details);

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let units = tryit!(wallet.convert_amount(&value_details));

    debug!("GA_convert_amount() result: {:?}", units);

    ok_json!(ret, units)
}
#[no_mangle]
pub extern "C" fn GA_get_fee_estimates(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    let wallet = tryit!(sess.wallet().or_err("no loaded wallet"));
    let estimates = tryit!(wallet
        .get_fee_estimates()
        .or_err("fee estimates unavailable"));

    ok_json!(ret, json!({ "fees": estimates }))
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
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();

    sess.notify = Some((handler, context));

    GA_OK
}

//
// Settings
//

#[no_mangle]
pub extern "C" fn GA_get_settings(sess: *const GA_session, ret: *mut *const GA_json) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get(sess).unwrap();

    ok_json!(ret, json!(sess.settings))
}

#[no_mangle]
pub extern "C" fn GA_change_settings(
    sess: *mut GA_session,
    settings: *const GA_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();
    let new_settings = &unsafe { &*settings }.0;

    // XXX should we allow patching just some setting fields instead of replacing it?
    sess.settings = tryit!(from_value(new_settings.clone()));

    ok!(ret, GA_auth_handler::success())
}

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    ok!(ret, make_str(res))
}

#[no_mangle]
pub extern "C" fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32 {
    let jstr = read_str(jstr);
    let json: Value = tryit!(serde_json::from_str(&jstr));
    ok_json!(ret, json)
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_string(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_str().req());
    ok!(ret, make_str(res.to_string()))
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint32(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u32,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_u64().req()) as u32;
    ok!(ret, res)
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_uint64(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut u64,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_u64().req());
    ok!(ret, res)
}

#[no_mangle]
pub extern "C" fn GA_convert_json_value_to_json(
    json: *const GA_json,
    path: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let jstr = tryit!(json[path].as_str().req());
    let res: Value = tryit!(serde_json::from_str(jstr));
    ok_json!(ret, res)
}

#[no_mangle]
pub extern "C" fn GA_destroy_json(ptr: *mut GA_json) -> i32 {
    debug!("GA_destroy_json({:?})", ptr);
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
    ok!(ret, make_str("".to_string()))
}

#[no_mangle]
pub extern "C" fn GA_ack_system_message(
    _sess: *const GA_session,
    _message_text: *const c_char,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    ok!(ret, GA_auth_handler::success())
}

#[no_mangle]
pub extern "C" fn GA_get_twofactor_config(
    _sess: *const GA_session,
    ret: *mut *const GA_json,
) -> i32 {
    // 2FA is always off
    ok_json!(
        ret,
        json!({
            "any_enabled":false,
            "all_methods":[],
            "enabled_methods":[],
            "email":{"confirmed":false,"data":"","enabled":false},
            "limits":{"bits":"0.00","btc":"0.00000000","fiat":"0.00","fiat_currency":"USD","fiat_rate":"0","is_fiat":false,"mbtc":"0.00000","satoshi":0,"ubtc":"0.00"},
            "twofactor_reset":{"days_remaining":-1,"is_active":false,"is_disputed":false},
        })
    )
}

#[no_mangle]
pub extern "C" fn GA_reconnect_hint(_sess: *const GA_session, _hint: *const GA_json) -> i32 {
    GA_OK
}

#[no_mangle]
pub extern "C" fn GA_get_watch_only_username(
    _sess: *mut GA_session,
    ret: *mut *const c_char,
) -> i32 {
    ok!(ret, make_str("".to_string()))
}

#[no_mangle]
pub extern "C" fn GA_set_pin(
    _sess: *const GA_session,
    mnemonic: *const c_char,
    _pin: *const c_char,
    device_id: *const c_char,
    ret: *mut *const GA_json,
) -> i32 {
    let mnemonic = read_str(mnemonic);
    let device_id = read_str(device_id);
    let mnemonic_hex = tryit!(mnemonic_to_hex(&mnemonic));

    // FIXME setting a PIN does not actually do anything, just a successful no-op
    ok_json!(
        ret,
        json!({
            "encrypted_data": mnemonic_hex,
            "salt": "IA==",
            "pin_identifier": device_id,
            "__unencrypted": true
        })
    )
}

#[no_mangle]
pub extern "C" fn GA_login_with_pin(
    sess: *mut GA_session,
    _pin: *const c_char,
    pin_data: *const GA_json,
) -> i32 {
    let sm = SESS_MANAGER.lock().unwrap();
    let sess = sm.get_mut(sess).unwrap();

    let pin_data = &unsafe { &*pin_data }.0;
    let mnemonic_hex = tryit!(pin_data["encrypted_data"].as_str().req()).to_string();
    let mnemonic = tryit!(hex_to_mnemonic(&mnemonic_hex));
    debug!("GA_login_with_pin mnemonic: {}", mnemonic);

    let wallet = tryit!(sess.wallet_mut().or_err("no loaded wallet"));
    tryit!(wallet.login(&mnemonic));

    tryit!(sess.hello());

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
pub extern "C" fn GA_set_watch_only(
    _sess: *mut GA_session,
    _username: *const c_char,
    _password: *const c_char,
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
