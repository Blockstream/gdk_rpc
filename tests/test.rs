extern crate libc;
#[cfg(feature = "stderr_logger")]
extern crate stderrlog;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

extern crate bip39;
extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate secp256k1;
extern crate url;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::{env, fs, sync};
//use std::{thread, time};

use bitcoin_hashes::sha256d;
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

    // this method only exists for testing purposes
    fn GA_test_tick(sess: *mut GA_session) -> i32;
}

// TODO free up resources
// --test-threads=1

static LOGGER: sync::Once = sync::Once::new();
static WALLET_COUNT: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(0);

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
    // generate a new mnemonic
    let mnemonic = bip39::Mnemonic::new(bip39::MnemonicType::Words12, bip39::Language::English);
    let mnemonic_c = CString::new(mnemonic.to_string()).unwrap();
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
        let base_rpc_url = env::var("BITCOIND_URL")
            .ok()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let rpc_url = url::Url::parse(&base_rpc_url)
            .unwrap()
            .join("/wallet/")
            .unwrap()
            .to_string();
        let rpc_cookie = env::var("BITCOIND_DIR")
            .ok()
            .map(|p| Path::new(&p).join(".cookie").to_string_lossy().into_owned());
        let contents = fs::read_to_string(rpc_cookie.unwrap()).unwrap();
        let parts: Vec<&str> = contents.split(":").collect();
        let auth = bitcoincore_rpc::Auth::UserPass(parts[0].to_string(), parts[1].to_string());
        bitcoincore_rpc::Client::new(rpc_url, auth).unwrap()
    };
}

fn tick(sess: *mut GA_session) {
    assert_eq!(GA_OK, unsafe { GA_test_tick(sess) });
}

fn mine_blocks(n: u64) -> Vec<sha256d::Hash> {
    BITCOIND.generate(n, None).unwrap()
}

fn send_coins(address: &bitcoin::Address, amount: f64) -> sha256d::Hash {
    let txid = BITCOIND
        .send_to_address(address, amount, None, None, None, None, None, None)
        .unwrap();
    info!("send_coins(): Send {} BTC to {} in txid {}", amount, address, txid);
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
fn test_balance() {
    let sess = setup();

    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_balance(sess, details, &mut balance)
    });
    let balance_before = read_json(balance)["btc"].as_str().unwrap().to_owned();
    debug!("balance_before: {}\n", balance_before);
    assert_eq!("0", balance_before);

    // receive some coins
    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_receive_address(sess, details, &mut recv_addr)
    });
    let address = read_json(recv_addr)["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    debug!(
        "Received coins to addr {} in txid {}",
        address,
        send_coins(&address, 50.0)
    );
    mine_blocks(6);

    // balance now
    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_balance(sess, details, &mut balance)
    });
    let balance_after = read_json(balance)["btc"].as_str().unwrap().to_owned();
    debug!("balance_after: {}\n", balance_after);
    assert_eq!("50", balance_after);

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
    let address = read_json(recv_addr)["address"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    send_coins(&address, 500.0);
    mine_blocks(10);

    let details = make_json(
        // cTBHbKQuegSNeQuSurjy4mEGNm5ebW7Y8R9jYj11Lfc37PTej5ny -> mt9XjRweetsyCtc6HaXRohJSzvV9v796Ym
        // cSNEZVDaawKzkZcmby8GrTwroE5EoNkSeH6XMxZfauzrpWJDkQ6p -> mnQUxaPB6hXKV8aGvShvuUDuXbPzhfVCy1
        json!({ "addressees": [ {"address":"mt9XjRweetsyCtc6HaXRohJSzvV9v796Ym", "satoshi": 569000}, {"address":"bitcoin:mnQUxaPB6hXKV8aGvShvuUDuXbPzhfVCy1", "satoshi":1000} ] }),
    );
    let mut tx_detail_unsigned: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_create_transaction(sess, details, &mut tx_detail_unsigned)
    });
    info!("create_transaction: {:#?}\n", read_json(tx_detail_unsigned));

    // check balance
    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_balance(sess, details, &mut balance)
    });
    let balance = read_json(balance)["btc"].as_str().unwrap().to_owned();
    assert_eq!("500", balance);

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_sign_transaction(sess, tx_detail_unsigned, &mut auth_handler)
    });
    let sign_status = get_status(auth_handler);
    info!("sign_transaction status: {:#?}\n", sign_status);

    let tx_detail_signed = make_json(sign_status.get("result").unwrap().clone());
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_send_transaction(sess, tx_detail_signed, &mut auth_handler)
    });
    let status = get_status(auth_handler);
    info!("send_transaction status: {:#?}\n", status);

    let txid = CString::new(status.pointer("/result/txid").unwrap().as_str().unwrap()).unwrap();

    let mut loaded_tx: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    info!("loaded broadcasted tx: {:#?}", read_json(loaded_tx));

    //warn!("xxxxxxx");
    //::std::thread::sleep(::std::time::Duration::from_secs(160));

    let memo = CString::new("hello world").unwrap();
    assert_eq!(GA_OK, unsafe {
        GA_set_transaction_memo(sess, txid.as_ptr(), memo.as_ptr(), 0)
    });
    debug!("set memo");

    let mut loaded_tx: *const GA_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GA_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    let details = read_json(loaded_tx);
    info!("loaded tx with memo: {:?}", details);
    assert_eq!(details["memo"].as_str().unwrap(), "hello world");

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
