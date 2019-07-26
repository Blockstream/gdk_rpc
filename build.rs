fn main() {
    let lib_dir = "gdk/build-clang/libwally-core/build/lib";

    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=dylib=wallycore");
}
