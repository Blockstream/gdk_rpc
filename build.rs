use std::{env, path};

fn main() {
    let wally_dir = env::var("WALLY_LOCATION").expect("WALLY_LOCATION not set, please clone http://github.com/elementsProject/libwally-core");
    let wally_dir_path = path::PathBuf::from(wally_dir);
    let wally_dir_str = wally_dir_path.as_path().to_str().expect("invalid WALLY_LOCATION value");
    println!("cargo:rustc-link-search=native={}", wally_dir_str);
    println!("cargo:rustc-link-lib=dylib=wallycore");
}
