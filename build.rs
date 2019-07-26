use std::{env, path};

fn main() {
    let gdk_dir = env::var("GDK_LOCATION").expect("GDK_LOCATION not set");
    let mut lib_dir = path::PathBuf::from(gdk_dir);
    lib_dir.push("build-clang/libwally-core/build/lib");
    let lib_dir_str = lib_dir.as_path().to_str().expect("invalid GDK_LOCATION value");

    println!("cargo:rustc-link-search=native={}", lib_dir_str);
    println!("cargo:rustc-link-lib=dylib=wallycore");
}
