// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EGRESS_FILTER(ret) ___EGRESS_FILTER(ret, eth, ip, udp)
// Customize here to change the egress filter
#define ___EGRESS_FILTER(ret, eth, ip, udp)                               \
  ({                                                                      \
    if (bpf_ntohs(udp->source) != 8000 && bpf_ntohs(udp->dest) != 8000) { \
      return ret;                                                         \
    }                                                                     \
  })

#define INGRESS_FILTER(ret) ___INGRESS_FILTER(ret, eth, ip, tcp)
// Customize here to change the ingress filter
#define ___INGRESS_FILTER(ret, eth, ip, tcp)                              \
  ({                                                                      \
    if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000) { \
      return ret;                                                         \
    }                                                                     \
  })
