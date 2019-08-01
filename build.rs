use std::{env, path};

fn main() {
    let wally_dir_path = path::PathBuf::from("./bld/lib");
    let wally_dir_str = wally_dir_path.as_path().to_str().expect("Please build wally first (in ./bld)");
    println!("cargo:rustc-link-search=native={}", wally_dir_str);
    println!("cargo:rustc-link-lib=dylib=wallycore");
}
