// Copyright (C) 2021-2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#ifndef always_inline
#define always_inline inline __attribute__((always_inline))
#endif

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

static always_inline int check_bound(void *start, void *end, void *data, void *data_end) {
  if (start > end) {
    return 1;
  }
  if (start < data) {
    return 2;
  }
  if (end > data_end) {
    return 3;
  }
  return 0;
}
