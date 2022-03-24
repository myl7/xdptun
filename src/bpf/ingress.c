// Copyright (c) 2022 myl7
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
  if (bpf_ntohs(ip->tot_len) < 12) {
    return XDP_PASS;
  }

  CHECK_TCP_BOUND(tcp, XDP_PASS);
  if (check_bound(tcp, (void *)tcp + tcp->doff * 4, data, data_end)) {
    return XDP_PASS;
  }
  if (tcp->doff != 5) {
    return XDP_PASS;
  }

#ifdef FILTER_PORT
  if (bpf_ntohs(tcp->dest) != FILTER_PORT) {
    return XDP_PASS;
  }
#endif

  LOG_INFO("ingress recv");

  udp = (void *)tcp;
  if (check_bound(udp, udp + 1, data, data_end)) {
    return XDP_PASS;
  }

  int pad_diff = 12 - (int)(bpf_ntohs(udp->len) - 8);
  __u8 pad_alloc = pad_diff > 0 ? pad_diff : 0;

  __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
  ip_tot_len -= 12;
  ip_tot_len &= 0xfff;

  void *data_bak = (void *)ip + ip_tot_len;
  if (check_bound(data_bak, data_bak + 12, data, data_end)) {
    return XDP_PASS;
  }

  // Update IP header protocol, total length, header checksum
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - 12 - pad_alloc);
  ip->check = bpf_htons(csum_delta(bpf_ntohs(ip->check), IPPROTO_UDP - IPPROTO_TCP - 12 - (int)pad_alloc));

  // Set UDP checksum according to TCP checksum
  udp->check = bpf_htons(csum_delta(bpf_ntohs(tcp->check), IPPROTO_UDP - IPPROTO_TCP - 12 - (int)pad_alloc - (tcp->doff << 12)));

  // 12 bytes are moved to tail to leave enough space to transform UDP header to TCP header
  memmove((void *)tcp + 8, data_bak, 12);

  long res = bpf_xdp_adjust_tail(ctx, -12 - (int)pad_alloc);
  if (res != 0) {
    LOG_ERROR("bpf_xdp_adjust_tail failed with %ld", res);
    return XDP_PASS;
  }

  LOG_INFO("ingress done");
  return XDP_PASS;
}
