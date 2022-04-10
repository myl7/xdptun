// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

use std::env;
use std::path::Path;
use std::process::Command;

fn build_bpf(name: &str) {
  let out_dir = env::var("OUT_DIR").unwrap();
  let log_level_flag = format!(
    "-DLOG_LEVEL={}",
    env::var("LOG_LEVEL")
      .or::<()>(if env::var("DEBUG").unwrap().is_empty() {
        Ok("1".to_owned())
      } else {
        Ok("3".to_owned())
      })
      .unwrap()
  );
  let log_map_flag = format!(
    "-DLOG_USE_MAP={}",
    env::var("LOG_USE_MAP").or::<()>(Ok("".to_owned())).unwrap()
  );
  let src = format!("src/bpf/{}.bpf.c", name);
  let output = Path::new(&out_dir)
    .join(format!("{}.bpf.o", name))
    .to_str()
    .unwrap()
    .to_owned();
  let mut args = vec![
    "-O2",
    "-Wall",
    "--target=bpf",
    "-Iinclude",
    &log_level_flag,
    &log_map_flag,
    "-c",
    &src,
    "-o",
    &output,
  ];
  if env::var("DISABLE_BTF").unwrap_or("".to_owned()).is_empty() {
    args.push("-g");
  }
  assert!(Command::new("clang").args(args).status().unwrap().success());
}

fn main() {
  println!("cargo:rerun-if-changed=src/bpf");
  println!("cargo:rerun-if-env-changed=LOG_LEVEL");
  println!("cargo:rerun-if-env-changed=LOG_USE_MAP");
  println!("cargo:rerun-if-env-changed=DISABLE_BTF");
  build_bpf("egress");
  build_bpf("ingress");
}
