extern crate libc;
extern crate serde_json;

use serde_json::Value;

use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
pub struct GA_json {
    _private: [u8; 0],
}

#[link(name = "gdk_rpc")]
extern "C" {
    fn GA_get_networks(ret: *mut *const GA_json);
    fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char);
}

#[test]
fn main() {
    let mut nets: *const GA_json = std::ptr::null_mut();
    unsafe {
        GA_get_networks(&mut nets);
    }
    println!("networks: {:#?}\n", json_obj(nets))
}

fn json_obj(json: *const GA_json) -> Value {
    let mut s: *const c_char = std::ptr::null_mut();
    unsafe { GA_convert_json_to_string(json, &mut s) };
    let s = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    serde_json::from_str(&s).unwrap()
}
