// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

const ADVANCED_BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";

const JSON_DIR: &str = "../../resources/seccomp";
/// fxdax's rules, added to each thread's of the target's filter with the `fxdax` feature.
#[cfg(feature = "fxdax")]
const FXDAX_JSON_DIR: &str = "../../resources/fxdax/seccomp";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler-bin.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    // Target triple
    let target = std::env::var("TARGET").expect("Missing target.");
    let debug: bool = std::env::var("DEBUG")
        .expect("Missing debug.")
        .parse()
        .expect("Invalid env variable DEBUG");
    let out_dir = std::env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");
    // Target arch (x86_64 / aarch64)
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

    let seccomp_json_path = format!("{}/{}.json", JSON_DIR, target);
    // If the current target doesn't have a default filter, or if we're building a debug binary,
    // use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't
    // provide a default filter. For example, GNU libc.
    let seccomp_json_path = if debug {
        println!(
            "cargo:warning=Using empty default seccomp policy for debug builds: \
             `resources/seccomp/unimplemented.json`."
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else if !Path::new(&seccomp_json_path).exists() {
        println!(
            "cargo:warning=No default seccomp policy for target: {}. Defaulting to \
             `resources/seccomp/unimplemented.json`.",
            target
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else {
        seccomp_json_path
    };

    // Retrigger the build script if the JSON file has changed.
    // let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", seccomp_json_path);
    // Also retrigger the build script on any seccompiler source code change.
    println!("cargo:rerun-if-changed={}", SECCOMPILER_SRC_DIR);

    // fxdax: its rules too, in the target's own filter, not in the empty default.
    #[cfg(feature = "fxdax")]
    let seccomp_json_path = if seccomp_json_path == format!("{}/{}.json", JSON_DIR, target) {
        with_fxdax_rules(&seccomp_json_path, &target, &out_dir)
    } else {
        seccomp_json_path
    };

    let out_path = format!("{}/{}", out_dir, ADVANCED_BINARY_FILTER_FILE_NAME);
    seccompiler::compile_bpf(&seccomp_json_path, &target_arch, &out_path, false, false)
        .expect("Cannot compile seccomp filters");
}

/// fxdax: the filters of `seccomp_json_path` with fxdax's rules for the target before each
/// thread's own, written beside the build's output: what fxdax's extent device does on the threads
/// it runs on, which upstream's filters refuse. The JSON files upstream ships stay as they are.
#[cfg(feature = "fxdax")]
fn with_fxdax_rules(seccomp_json_path: &str, target: &str, out_dir: &str) -> String {
    let read = |path: &str| -> serde_json::Value {
        let json = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("{path}: {err}"));
        serde_json::from_str(&json).unwrap_or_else(|err| panic!("{path}: {err}"))
    };
    let fxdax_json_path = format!("{}/{}.json", FXDAX_JSON_DIR, target);
    println!("cargo:rerun-if-changed={}", fxdax_json_path);
    let mut filters = read(seccomp_json_path);
    let fxdax = read(&fxdax_json_path);
    let threads = fxdax
        .as_object()
        .unwrap_or_else(|| panic!("{fxdax_json_path}: not an object of threads' filters"));
    for (thread, rules) in threads {
        let filter = filters[thread.as_str()]["filter"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("{seccomp_json_path}: no filter for thread {thread}"));
        let rules = rules["filter"]
            .as_array()
            .unwrap_or_else(|| panic!("{fxdax_json_path}: no filter for thread {thread}"));
        filter.splice(0..0, rules.iter().cloned());
    }
    let merged = format!("{}/seccomp_filter_fxdax.json", out_dir);
    std::fs::write(&merged, serde_json::to_string_pretty(&filters).unwrap())
        .unwrap_or_else(|err| panic!("{merged}: {err}"));
    merged
}
