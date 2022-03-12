// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <linux/bpf.h>
#include "utils.h"

static always_inline __u16 csum_delta(__u32 old_sum, __u32 delta) {
  __u32 new_sum = old_sum + delta;
  return ((new_sum & 0xffff) + (new_sum >> 16)) & 0xffff;
}
