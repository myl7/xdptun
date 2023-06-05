// Copyright (C) myl7
// SPDX-License-Identifier: GPL-2.0-or-later

// Modify the file to add your complicated filter rules if required

#pragma once

#include "vmlinux.h"
#include <bpf/bpf_endian.h>

const volatile u32 peer_ip = 0;

// If unmatched, return 0, otherwise non-0
static inline u32 filter(struct iphdr *ip) {
  if (bpf_ntohl(ip->daddr) != peer_ip) return 0;
  return 1;
}
