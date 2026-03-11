// Link libloophole.a (Go c-archive) for the loophole block I/O engine.
fn main() {
    // Look for libloophole.a in the LOOPHOLE_LIB_DIR env var, or fall back
    // to a default path relative to the workspace root.
    let lib_dir = std::env::var("LOOPHOLE_LIB_DIR")
        .unwrap_or_else(|_| "/tmp".to_string());

    // The `loophole` feature is set via Cargo.toml / --features, not build.rs.
    println!("cargo:rustc-link-search=native={lib_dir}");
    println!("cargo:rustc-link-lib=static=loophole");

    // Go runtime dependencies.
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=resolv");
}
