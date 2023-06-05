// Copyright (C) 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;

use libbpf_cargo::SkeletonBuilder;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");
    let out_dir = env::var("OUT_DIR").unwrap();
    SkeletonBuilder::new()
        .source("src/bpf/egress.bpf.c")
        // For BTF
        .debug(true)
        // Since include! is also concatting
        .build_and_generate([&out_dir, "/egress.skel.rs"].concat())
        .unwrap();
    println!("cargo:rerun-if-changed=src/bpf/egress.bpf.c");
    SkeletonBuilder::new()
        .source("src/bpf/ingress.bpf.c")
        .debug(true)
        .build_and_generate([&out_dir, "/ingress.skel.rs"].concat())
        .unwrap();
    println!("cargo:rerun-if-changed=src/bpf/ingress.bpf.c");
}
