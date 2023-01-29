// Copyright (C) 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "vmlinux.h"

struct xdptun_tail_meta {
  __be16 udp_len;
  u8: 2;
};
