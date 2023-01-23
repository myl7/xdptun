// Copyright (C) 2022, 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "ingress.h"

const char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int ingress_f(struct xdp_md *ctx) {
  return XDP_DROP;
}
