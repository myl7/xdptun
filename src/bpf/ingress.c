// Copyright (C) 2021-2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("license")
const char ___license[] = "GPL";

SEC("xdptun_ingress")
int ingress() {
  return XDP_PASS;
}
