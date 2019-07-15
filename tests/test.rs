extern crate libc;
#[cfg(feature = "stderr_logger")]
extern crate stderrlog;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate secp256k1;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::str::FromStr;
use std::{env, fs, sync};

use bitcoin_hashes::{sha256d};
use bitcoincore_rpc::RpcApi;
use serde_json::Value;

const GA_OK: i32 = 0;
const GA_TRUE: u32 = 1;
const GA_FALSE: u32 = 0;

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
    fn GA_get_fee_estimates(sess: *const GA_session, ret: *mut *const GA_json) -> i32;
    fn GA_get_mnemonic_passphrase(
        sess: *const GA_session,
        password: *const c_char,
        ret: *mut *const c_char,
    ) -> i32;
    fn GA_convert_amount(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_json,
    ) -> i32;

    fn GA_create_session(ret: *mut *mut GA_session) -> i32;
    fn GA_connect(sess: *mut GA_session, network: *const c_char, log_level: u32) -> i32;

    fn GA_get_subaccounts(sess: *const GA_session, ret: *mut *const GA_json) -> i32;
    fn GA_get_subaccount(sess: *const GA_session, index: u32, ret: *mut *const GA_json) -> i32;

    fn GA_generate_mnemonic(ret: *mut *const c_char) -> i32;
    fn GA_validate_mnemonic(mnemonic: *const c_char, ret: &mut u32) -> i32;

    fn GA_get_settings(sess: *const GA_session, ret: *mut *const GA_json) -> i32;
    fn GA_change_settings(
        sess: *const GA_session,
        new_settings: *const GA_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GA_get_receive_address(
        sess: *const GA_session,
        details: *const GA_json,
        ret: *mut *const GA_json,
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

    fn GA_get_transaction_details(
        sess: *mut GA_session,
        txid: *const c_char,
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

    fn GA_set_transaction_memo(
        sess: *const GA_session,
        txid: *const c_char,
        memo: *const c_char,
        memo_type: u32,
    ) -> i32;

    fn GA_set_pin(
        sess: *const GA_session,
        mnemonic: *const c_char,
        pin: *const c_char,
        device_id: *const c_char,
        ret: *mut *const GA_json,
    ) -> i32;
    fn GA_login_with_pin(
        sess: *const GA_session,
        device_id: *const c_char,
        pin_data: *const GA_json,
    ) -> i32;

    fn GA_auth_handler_get_status(handler: *const GA_auth_handler, ret: *mut *const GA_json)
        -> i32;

    fn GA_set_notification_handler(
        sess: *mut GA_session,
        handler: extern "C" fn(*const GA_json, *const GA_json),
        context: *const GA_json,
    ) -> i32;

    fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char) -> i32;
    fn GA_convert_string_to_json(jstr: *const c_char, ret: *mut *const GA_json) -> i32;

    fn GA_destroy_auth_handler(handler: *const GA_auth_handler) -> i32;
    fn GA_destroy_json(json: *const GA_json) -> i32;
    fn GA_destroy_session(sess: *const GA_session) -> i32;
    fn GA_destroy_string(s: *const c_char) -> i32;
}

// TODO free up resources
// --test-threads=1

static LOGGER: sync::Once = sync::Once::new();

/// The test setup function.
fn setup_nologin() -> *mut GA_session {
    LOGGER.call_once(|| {
        #[cfg(feature = "stderr_logger")]
        stderrlog::new().verbosity(3).init().unwrap();
    });

    // create new session
    let mut sess: *mut GA_session = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_create_session(&mut sess) });

    // connect
    let network = CString::new("regtest-cookie").unwrap();
    assert_eq!(GA_OK, unsafe { GA_connect(sess, network.as_ptr(), 5) });
    debug!("connected");

    sess
}

/// Setup with login.
fn setup() -> *mut GA_session {
    let sess = setup_nologin();

    let hw_device = make_json(json!({ "type": "trezor" }));
    let mnemonic =
        "plunge wash chimney soap magic luggage bulk mixed chuckle utility come light".to_string();
    let mnemonic_c = CString::new(mnemonic.clone()).unwrap();
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_register_user(sess, hw_device, mnemonic_c.as_ptr(), &mut auth_handler)
    });

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    let password = CString::new("").unwrap();
    assert_eq!(GA_OK, unsafe {
        GA_login(
            sess,
            hw_device,
            mnemonic_c.as_ptr(),
            password.as_ptr(),
            &mut auth_handler,
        )
    });

    sess
}

/// The test teardown function.
fn teardown(sess: *mut GA_session) {
    debug!("destroying session");
    assert_eq!(GA_OK, unsafe { GA_destroy_session(sess) })
}

lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref BITCOIND: bitcoincore_rpc::Client = {
        let rpc_url = env::var("BITCOIND_URL")
            .ok()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let rpc_cookie = env::var("BITCOIND_DIR")
            .ok()
            .map(|p| Path::new(&p).join(".cookie").to_string_lossy().into_owned());
        let contents = fs::read_to_string(rpc_cookie.unwrap()).unwrap();
        let parts: Vec<&str> = contents.split(":").collect();
        let auth = bitcoincore_rpc::Auth::UserPass(parts[0].to_string(), parts[1].to_string());
        bitcoincore_rpc::Client::new(rpc_url, auth).unwrap()
    };
}

const GENKEY_WIF: &str = "cSqP5fzDsrwKHkhTBPtoM447jLW8kEGo3HdG53CCiUwDEtA9Yt1J";
const GENKEY_ADDR: &str = "mydYeZg2uSCRWk7sDsSG1BGLrQysotYTJn";
const GENKEY_SCRIPT_PK: &str = "76a914c6b16fd4ac700cbab750d297223eb425a4ad339488ac";
/// The block height of the last used coinbase output.
const GENKEY_USED_IDX: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(0);

fn mine_blocks(n: u64) -> Vec<sha256d::Hash> {
    BITCOIND.generate_to_address(n, &GENKEY_ADDR.parse().unwrap()).unwrap()
}

fn send_coins(address: &bitcoin::Address) -> sha256d::Hash {
    let utxo_block_idx = GENKEY_USED_IDX.fetch_add(1, sync::atomic::Ordering::Relaxed) + 1;
    let (utxo, value) = {
        let block_hash = BITCOIND.get_block_hash(utxo_block_idx as u64).unwrap();
        let block = BITCOIND.get_block(&block_hash).unwrap();
        (bitcoin::OutPoint {
            txid: block.txdata[0].txid(),
            vout: 0,
        }, block.txdata[0].output[0].value)
    };

    let mut tx = bitcoin::Transaction {
        version: 1,
        lock_time: 0,
        input: vec![
            bitcoin::TxIn {
                previous_output: utxo,
                script_sig: bitcoin::Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![
            bitcoin::TxOut {
                value: value,
                script_pubkey: address.script_pubkey(),
            },
        ],
    };
    let gen_script: bitcoin::Script = hex::decode(&GENKEY_SCRIPT_PK).unwrap().into();
    let sighash = tx.signature_hash(0, &gen_script, bitcoin::SigHashType::All.as_u32());

    let privkey = bitcoin::PrivateKey::from_str(&GENKEY_WIF).unwrap();
    let pubkey = privkey.public_key(&SECP).to_bytes();
    let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();
    let signature = SECP.sign(&msg, &privkey.key).serialize_der();
    let scriptsig = bitcoin::blockdata::script::Builder::new()
        .push_slice(&pubkey)
        .push_slice(&signature)
        .into_script();
    tx.input[0].script_sig = scriptsig;

    let txid = BITCOIND.send_raw_transaction(&tx).unwrap();
    txid
}

#[test]
fn test_notifications() {
    let sess = setup_nologin();

    let ctx = make_json(json!({ "test": "my ctx" }));
    assert_eq!(GA_OK, unsafe {
        GA_set_notification_handler(sess, notification_handler, ctx)
    });

    teardown(sess);
}

#[test]
fn test_account() {
    let sess = setup_nologin();

    let hw_device = make_json(json!({ "type": "trezor" }));
    let mnemonic =
        "plunge wash chimney soap magic luggage bulk mixed chuckle utility come light".to_string();
    let mnemonic_c = CString::new(mnemonic.clone()).unwrap();
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_register_user(sess, hw_device, mnemonic_c.as_ptr(), &mut auth_handler)
    });
    debug!("register status: {:?}", get_status(auth_handler));

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    let password = CString::new("").unwrap();
    assert_eq!(GA_OK, unsafe {
        GA_login(
            sess,
            hw_device,
            mnemonic_c.as_ptr(),
            password.as_ptr(),
            &mut auth_handler,
        )
    });
    debug!("log in status: {:?}", get_status(auth_handler));

    let mut mnemonic_r: *const c_char = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_mnemonic_passphrase(sess, password.as_ptr(), &mut mnemonic_r)
    });
    let mnemonic_r = read_str(mnemonic_r);
    // FIXME turn off loggin of mnemonic (here and elsewhere)
    debug!("get_mnemonic_passphrase: {}", mnemonic_r);
    assert_eq!(mnemonic_r, mnemonic);

    teardown(sess);
}

#[test]
fn test_currencies() {
    let sess = setup();

    let mut currencies: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_available_currencies(sess, &mut currencies)
    });
    debug!("currencies: {:?}\n", read_json(currencies));

    let details = make_json(json!({ "satoshi": 1234567 }));
    let mut units: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_convert_amount(sess, details, &mut units)
    });
    debug!("converted units from satoshi: {:?}\n", read_json(units));

    let details = make_json(json!({ "btc": 0.1 }));
    let mut units: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_convert_amount(sess, details, &mut units)
    });
    debug!("converted units from btc: {:?}\n", read_json(units));

    let details = make_json(json!({ "fiat": 400 }));
    let mut units: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_convert_amount(sess, details, &mut units)
    });
    debug!("converted units from fiat: {:?}\n", read_json(units));

    teardown(sess);
}

#[test]
fn test_estimates() {
    let sess = setup();

    let mut estimates: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_get_fee_estimates(sess, &mut estimates) });
    info!("fee estimates: {:?}\n", read_json(estimates));

    teardown(sess);
}

#[test]
fn test_subaccount() {
    let sess = setup();

    let mut subaccounts: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_get_subaccounts(sess, &mut subaccounts) });
    debug!("subaccounts: {:#?}\n", read_json(subaccounts));

    teardown(sess);
}

#[test]
fn test_transactions() {
    let sess = setup();

    let details = make_json(json!({ "page_id": 0 }));
    let mut txs: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_transactions(sess, details, &mut txs)
    });
    debug!("txs: {:#?}\n", read_json(txs));

    teardown(sess);
}

#[test]
fn test_balance() {
    let sess = setup();

    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_balance(sess, details, &mut balance)
    });
    debug!("balance: {:#?}\n", read_json(balance));

    teardown(sess);
}

#[test]
fn test_get_address() {
    let sess = setup();

    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_receive_address(sess, details, &mut recv_addr)
    });
    debug!("recv addr: {:#?}\n", read_json(recv_addr));

    teardown(sess);
}

#[test]
fn test_settings() {
    let sess = setup();

    let mut settings: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_get_settings(sess, &mut settings) });
    let mut settings = read_json(settings);
    debug!("get settings: {:#?}\n", settings);
    assert_eq!(settings.get("unit").unwrap().as_str().unwrap(), "btc");

    *settings.get_mut("unit").unwrap() = json!("satoshi");

    let settings = make_json(settings);
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_change_settings(sess, settings, &mut auth_handler)
    });
    debug!("change settings status: {:#?}\n", get_status(auth_handler));

    let mut settings: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_get_settings(sess, &mut settings) });
    let settings = read_json(settings);
    debug!("get settings again: {:#?}\n", settings);
    assert_eq!(settings.get("unit").unwrap().as_str().unwrap(), "satoshi");

    teardown(sess);
}

#[test]
fn send_tx() {
    let sess = setup();

    // receive some coins first
    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_receive_address(sess, details, &mut recv_addr)
    });
    let address = read_json(recv_addr)["address"].as_str().unwrap().parse().unwrap();
    debug!("Received coins to addr {} in txid {}", address, send_coins(&address));
    mine_blocks(1);

    let details = make_json(
        // address privkeys: cTBHbKQuegSNeQuSurjy4mEGNm5ebW7Y8R9jYj11Lfc37PTej5ny -> mt9XjRweetsyCtc6HaXRohJSzvV9v796Ym
        // address privkeys: cSNEZVDaawKzkZcmby8GrTwroE5EoNkSeH6XMxZfauzrpWJDkQ6p -> mnQUxaPB6hXKV8aGvShvuUDuXbPzhfVCy1
        json!({ "addressees": [ {"address":"mt9XjRweetsyCtc6HaXRohJSzvV9v796Ym", "satoshi": 569000}, {"address":"bitcoin:mnQUxaPB6hXKV8aGvShvuUDuXbPzhfVCy1", "satoshi":1000} ] }),
    );
    let mut tx_detail_unsigned: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_create_transaction(sess, details, &mut tx_detail_unsigned)
    });
    debug!("create_transaction: {:#?}\n", read_json(tx_detail_unsigned));

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_sign_transaction(sess, tx_detail_unsigned, &mut auth_handler)
    });
    let sign_status = get_status(auth_handler);
    debug!("sign_transaction status: {:#?}\n", sign_status);

    let tx_detail_signed = make_json(sign_status.get("result").unwrap().clone());
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_send_transaction(sess, tx_detail_signed, &mut auth_handler)
    });
    let status = get_status(auth_handler);
    debug!("send_transaction status: {:#?}\n", status);

    let txid = CString::new(status.pointer("/result/txid").unwrap().as_str().unwrap()).unwrap();

    let mut loaded_tx: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    info!("loaded broadcasted tx: {:#?}", read_json(loaded_tx));

    let memo = CString::new("hello world").unwrap();
    assert_eq!(GA_OK, unsafe {
        GA_set_transaction_memo(sess, txid.as_ptr(), memo.as_ptr(), 0)
    });
    debug!("set memo");

    let mut loaded_tx: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    info!("loaded tx with memo: {:?}", read_json(loaded_tx));

    teardown(sess);
}

#[test]
fn test_pin() {
    let sess = setup();

    let mnemonic =
        "plunge wash chimney soap magic luggage bulk mixed chuckle utility come light".to_string();

    let mnemonic = CString::new(mnemonic).unwrap();
    let pin = CString::new("1234").unwrap();
    let device_id = CString::new("foo").unwrap();
    let mut pin_data: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_set_pin(
            sess,
            mnemonic.as_ptr(),
            pin.as_ptr(),
            device_id.as_ptr(),
            &mut pin_data,
        )
    });
    let pin_data = read_json(pin_data);
    debug!("pin data: {:?}", pin_data);

    let pin_data = make_json(pin_data);
    assert_eq!(GA_OK, unsafe {
        GA_login_with_pin(sess, pin.as_ptr(), pin_data)
    });

    teardown(sess);
}

#[test]
fn test_networks() {
    let sess = setup();

    let mut nets: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_get_networks(&mut nets) });
    debug!("networks: {:?}\n", read_json(nets));

    teardown(sess);
}

#[test]
fn test_mnemonic() {
    let sess = setup();

    let mut mnemonic: *const c_char = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_generate_mnemonic(&mut mnemonic) });
    let mnemonic = read_str(mnemonic);
    info!("generated mnemonic: {}", mnemonic);

    let mnemonic_c = CString::new(mnemonic.clone()).unwrap();
    let mut is_valid = 0;
    assert_eq!(GA_OK, unsafe {
        GA_validate_mnemonic(mnemonic_c.as_ptr(), &mut is_valid)
    });
    info!("mnemonic is valid: {}", is_valid);
    assert_eq!(GA_TRUE, is_valid);

    let mnemonic_c = CString::new(mnemonic + "invalid").unwrap();
    let mut is_valid = 0;
    assert_eq!(GA_OK, unsafe {
        GA_validate_mnemonic(mnemonic_c.as_ptr(), &mut is_valid)
    });
    info!("invalid mnemonic is valid: {}", is_valid);
    assert_eq!(GA_FALSE, is_valid);

    teardown(sess);
}

#[test]
fn test_destroy_string() {
    let sess = setup();

    let mut mnemonic: *const c_char = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_generate_mnemonic(&mut mnemonic) });

    assert_eq!(GA_OK, unsafe { GA_destroy_string(mnemonic) });

    teardown(sess);
}

extern "C" fn notification_handler(ctx: *const GA_json, data: *const GA_json) {
    info!(
        "notification handler called: {:?} -- {:?}",
        read_json(ctx),
        read_json(data)
    );
}

fn read_json(json: *const GA_json) -> Value {
    let mut s: *const c_char = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GA_convert_json_to_string(json, &mut s) });
    let s = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    unsafe { GA_destroy_json(json) };
    serde_json::from_str(&s).unwrap()
}

fn make_json(val: Value) -> *const GA_json {
    let cstr = CString::new(val.to_string()).unwrap();
    let mut json: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_convert_string_to_json(cstr.as_ptr(), &mut json)
    });
    json
}

fn get_status(auth_handler: *const GA_auth_handler) -> Value {
    let mut status: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_auth_handler_get_status(auth_handler, &mut status)
    });
    read_json(status)
}

fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}
