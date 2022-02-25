// Copyright (C) 2021-2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "mem.h"

SEC("license")
const char ___license[] = "GPL";

SEC("xdptun_ingress")
int ingress(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if (check_bound(eth, eth + 1, data, data_end)) {
    return XDP_PASS;
  }
  if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
    return XDP_PASS;
  }

  struct iphdr *ip = (void *)(eth + 1);
  if (check_bound(ip, ip + 1, data, data_end)) {
    return XDP_PASS;
  }
  if (check_bound(ip, (void *)ip + ip->ihl * 4, data, data_end)) {
    return XDP_PASS;
  }
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
  if (check_bound(tcp, tcp + 1, data, data_end)) {
    return XDP_PASS;
  }
  if (check_bound(tcp, (void *)tcp + tcp->doff * 4, data, data_end)) {
    return XDP_PASS;
  }

  void *tcp_data = (void *)tcp + tcp->doff * 4;

#ifdef DEBUG
  bpf_printk("ingress recv");
#endif

  ip->protocol = IPPROTO_UDP;

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

  memmove((void *)tcp + 4, data_bak, 12);
  bpf_xdp_adjust_tail(ctx, -12);

#ifdef DEBUG
  bpf_printk("ingress done");
#endif

  return XDP_TX;
}
