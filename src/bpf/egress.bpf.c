// Copyright (C) 2022, 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "egress.h"

const char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int egress_f(struct __sk_buff *skb) {
  return TC_ACT_SHOT;
}
