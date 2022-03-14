// Copyright (c) 2021-2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#define BPF_NO_GLOBAL_DATA
#define LOG_MAP_NAME ingress_log_map

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "mem.h"
#include "hdr.h"
#include "csum.h"
#include "log.h"

const char ___license[] SEC("license") = "GPL";

SETUP_LOG_MAP(ingress_log_map);

SEC("ingress")
int ingress_f(struct xdp_md *ctx) {
  void *data, *data_end;
  struct ethhdr *eth;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;

  data = data_ptr(ctx->data);
  data_end = data_ptr(ctx->data_end);

  CHECK_ETH_BOUND(eth, XDP_PASS);
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    return XDP_PASS;
  }

  CHECK_IP_BOUND(ip, XDP_PASS);
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  CHECK_TCP_BOUND(tcp, XDP_PASS);

  LOG_INFO("ingress recv");

  __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
  // 12 bytes are moved to tail to leave enough space to transform UDP header to TCP header
  if (ip_tot_len < 12) {
    return XDP_PASS;
  }
  ip_tot_len -= 12;
  ip_tot_len &= 0xfff;

  void *data_bak = (void *)ip + ip_tot_len;
  if (check_bound(data_bak, data_bak + 12, data, data_end)) {
    return XDP_PASS;
  }

  // Update IP header protocol, total length, header checksum
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 12);
  ip->check = bpf_htons(csum_delta(bpf_ntohs(ip->check), IPPROTO_UDP - IPPROTO_TCP - 12));

  udp = (void *)tcp;
  if (check_bound(udp, udp + 1, data, data_end)) {
    return XDP_PASS;
  }

  memmove((void *)tcp + 4, data_bak, 12);
  bpf_xdp_adjust_tail(ctx, -12);

  LOG_INFO("ingress done");
  return XDP_PASS;
}
