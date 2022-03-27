// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;
use std::fs::remove_file;
use std::path::Path;
use std::process::Command;

fn build_bpf(name: &str) {
  let out_dir = env::var("OUT_DIR").unwrap();
  remove_file(Path::new(&out_dir).join(format!("{}.bpf.o", name))).ok();
  assert!(Command::new("clang")
    .args(&[
      "-O2",
      "-Wall",
      "--target=bpf",
      "-Iinclude",
      "-g",
      &format!(
        "-DLOG_LEVEL={}",
        env::var("LOG_LEVEL")
          .or::<()>(if env::var("DEBUG").unwrap().is_empty() {
            Ok("1".to_owned())
          } else {
            Ok("3".to_owned())
          })
          .unwrap()
      ),
      &format!(
        "-DLOG_USE_MAP={}",
        env::var("LOG_USE_MAP").or::<()>(Ok("".to_owned())).unwrap()
      ),
      "-c",
      &format!("src/bpf/{}.bpf.c", name),
      "-o",
      Path::new(&out_dir)
        .join(format!("{}.bpf.o", name))
        .to_str()
        .unwrap(),
    ])
    .status()
    .unwrap()
    .success());
}

fn main() {
  println!("cargo:rerun-if-changed=src/bpf");
  println!("cargo:rerun-if-env-changed=LOG_LEVEL");
  println!("cargo:rerun-if-env-changed=LOG_USE_MAP");
  build_bpf("egress");
  build_bpf("ingress");
}
