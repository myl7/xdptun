// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <bpf/bpf_helpers.h>
#include "inline.h"

static always_inline __u16 csum_delta(__u32 old_sum, int delta) {
  __u32 new_sum = ~old_sum + delta;
  if (new_sum <= 0xffff) return ~new_sum;
  new_sum = (new_sum & 0xffff) + (new_sum >> 16);  // 0xffff + 0xffff = 0x1fffe at worst
  if (new_sum <= 0xffff) return ~new_sum;
  new_sum = (new_sum & 0xffff) + (new_sum >> 16);  // 0x1 + 0xffff = 0x10000 at worst
  if (new_sum <= 0xffff) return ~new_sum;
  new_sum = (new_sum & 0xffff) + (new_sum >> 16);
  return ~new_sum;
}
