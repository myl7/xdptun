// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <bpf/bpf_helpers.h>

#define EGRESS_FILTER(ret) __EGRESS_FILTER(ret, eth, ip, udp, data, data_end)
// Customize here to change the egress filter
#define ___EGRESS_FILTER(ret, eth, ip, udp, data, data_end) \
  ({                                                        \
    if (bpf_ntohs(udp->dest) != 8000) {                     \
      return ret;                                           \
    }                                                       \
  })

#define INGRESS_FILTER(ret) __INGRESS_FILTER(ret, eth, ip, tcp, data, data_end)
// Customize here to change the ingress filter
#define ___INGRESS_FILTER(ret, eth, ip, tcp, data, data_end) \
  ({                                                         \
    if (bpf_ntohs(udp->dest) != 8000) {                      \
      return ret;                                            \
    }                                                        \
  })
