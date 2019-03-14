extern crate libc;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[repr(C)] pub struct GA_json { _private: [u8; 0] }

#[link(name = "gdk_rpc")]
extern "C" {
    fn GA_get_networks(ret: *mut *const GA_json);
    fn GA_convert_json_to_string(json: *const GA_json, ret: *mut *const c_char);
}

#[test]
fn main() {
    unsafe {
        let mut nets: *const GA_json = std::ptr::null_mut();
        GA_get_networks(&mut nets);
        print_json("networks", nets);
    }
}

fn print_json(desc: &str, json: *const GA_json) {
    let mut s: *const c_char = std::ptr::null_mut();
    unsafe { GA_convert_json_to_string(json, &mut s) };
    let s = unsafe { CStr::from_ptr(s) }.to_str().unwrap();
    println!("{}: {}\n", desc, s);
}
