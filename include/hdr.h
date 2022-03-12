// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <linux/bpf.h>
#include "utils.h"

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

static always_inline void *data_ptr(__u32 data) {
  return (void *)(long)data;
}

#define CHECK_ETH_BOUND(eth, ret) ___CHECK_ETH_BOUND(eth, ret, data, data_end)
#define ___CHECK_ETH_BOUND(eth, ret, data, data_end) \
  ({                                                 \
    eth = data;                                      \
    if (check_bound(eth, eth + 1, data, data_end)) { \
      return ret;                                    \
    }                                                \
  })

#define CHECK_IP_BOUND(ip, ret) ___CHECK_IP_BOUND(ip, ret, eth, data, data_end)
#define ___CHECK_IP_BOUND(ip, ret, eth, data, data_end)              \
  ({                                                                 \
    ip = (void *)(eth + 1);                                          \
    if (check_bound(ip, ip + 1, data, data_end)) {                   \
      return ret;                                                    \
    }                                                                \
    if (check_bound(ip, (void *)ip + ip->ihl * 4, data, data_end)) { \
      return ret;                                                    \
    }                                                                \
  })

#define CHECK_TCP_BOUND(tcp, ret) ___CHECK_TCP_BOUND(tcp, ret, ip, data, data_end)
#define ___CHECK_TCP_BOUND(tcp, ret, ip, data, data_end) \
  ({                                                     \
    tcp = (void *)ip + ip->ihl * 4;                      \
    if (check_bound(tcp, tcp + 1, data, data_end)) {     \
      return ret;                                        \
    }                                                    \
  })

#define CHECK_UDP_BOUND(udp, ret) ___CHECK_UDP_BOUND(udp, ret, ip, data, data_end)
#define ___CHECK_UDP_BOUND(udp, ret, ip, data, data_end) \
  ({                                                     \
    udp = (void *)ip + ip->ihl * 4;                      \
    if (check_bound(udp, udp + 1, data, data_end)) {     \
      return ret;                                        \
    }                                                    \
  })
