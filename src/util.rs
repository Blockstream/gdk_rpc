use chrono::NaiveDateTime;
use failure::Error;
use log::LevelFilter;
use serde_json::Value;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::constants::{GA_DEBUG, GA_INFO, GA_NONE, SAT_PER_BTC};
use crate::errors::OptionExt;

pub fn make_str(data: String) -> *const c_char {
    CString::new(data).unwrap().into_raw()
}

pub fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}

pub fn log_filter(level: u32) -> LevelFilter {
    match level {
        GA_NONE => LevelFilter::Error,
        GA_INFO => LevelFilter::Info,
        GA_DEBUG => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

pub fn btc_to_usat(amount: f64) -> u64 {
    (amount * SAT_PER_BTC) as u64
}

pub fn btc_to_isat(amount: f64) -> i64 {
    (amount * SAT_PER_BTC) as i64
}

pub fn usat_to_fbtc(sat: u64) -> f64 {
    (sat as f64) / SAT_PER_BTC
}

pub fn f64_from_val(val: &Value) -> Option<f64> {
    val.as_f64()
        .or_else(|| val.as_str().and_then(|x| x.parse().ok()))
}

pub fn extend(mut dest: Value, mut src: Value) -> Result<Value, Error> {
    let dest = dest.as_object_mut().req()?;
    for (k, v) in src.as_object_mut().req()? {
        dest.insert(k.to_string(), v.take());
    }
    Ok(json!(dest))
}

pub fn fmt_time(unix_ts: u64) -> String {
    NaiveDateTime::from_timestamp(unix_ts as i64, 0).to_string()
}
