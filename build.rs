// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;
use std::fs::remove_file;
use std::path::Path;
use std::process::Command;

fn main() {
  println!("cargo:rerun-if-changed=src/bpf");
  println!("cargo:rerun-if-env-changed=LOG_LEVEL");
  println!("cargo:rerun-if-env-changed=LOG_USE_MAP");

  let out_dir = env::var("OUT_DIR").unwrap();
  remove_file(Path::new(&out_dir).join("ingress.bpf.o")).ok();
  remove_file(Path::new(&out_dir).join("egress.bpf.o")).ok();
  Command::new("make")
    .args(&["make"])
    .env("BUILD_DIR", &out_dir)
    .status()
    .unwrap();
}
