// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#define BPF_NO_GLOBAL_DATA
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "mem.h"
#include "hdr.h"
#include "csum.h"
#define LOG_CTX_NAME skb
#include "log.h"
#include "filter.h"

const char ___license[] SEC("license") = "GPL";

SETUP_LOG_MAP(log_map);

SEC("egress")
int egress_f(struct __sk_buff *skb) {
  void *data, *data_end;
  struct ethhdr *eth;
  struct iphdr *ip;
  struct udphdr *udp;
  struct tcphdr *tcp;

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);

  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
    return TC_ACT_OK;
  }

  CHECK_IP_BOUND(ip, TC_ACT_OK);
  if (ip->protocol != IPPROTO_UDP) {
    return TC_ACT_OK;
  }

  CHECK_UDP_BOUND(udp, TC_ACT_OK);

  EGRESS_FILTER(TC_ACT_OK);

  LOG_INFO("egress recv");

  int pad_diff = 12 - (int)(bpf_ntohs(udp->len) - 8);
  __u8 pad_alloc = pad_diff > 0 ? pad_diff : 0;

  // 12 bytes are moved to tail to leave enough space to transform UDP header to TCP header
  long res = bpf_skb_change_tail(skb, skb->len + 12 + pad_alloc, 0);
  if (res < 0) {
    LOG_ERROR("bpf_skb_change_tail failed with %ld", res);
    return TC_ACT_OK;
  }

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);
  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  CHECK_IP_BOUND(ip, TC_ACT_OK);
  CHECK_TCP_BOUND(tcp, TC_ACT_OK);

  udp = (void *)tcp;
  if (check_bound(udp, udp + 1, data, data_end)) {
    return TC_ACT_OK;
  }

  __u8 buf[12];
  memcpy(buf, udp + 1, 12);
  memset(udp + 1, 0, 12);
  unsigned offset = (void *)ip - data + bpf_ntohs(ip->tot_len) + pad_alloc;
  res = bpf_skb_store_bytes(skb, offset, buf, 12, 0);
  if (res < 0) {
    LOG_ERROR("bpf_skb_store_bytes failed with %ld", res);
    return TC_ACT_OK;
  }

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);
  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  CHECK_IP_BOUND(ip, TC_ACT_OK);
  CHECK_TCP_BOUND(tcp, TC_ACT_OK);
  CHECK_UDP_BOUND(udp, TC_ACT_OK);

  // Update IP header protocol, total length, header checksum
  ip->protocol = IPPROTO_TCP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12 + pad_alloc);
  ip->check = bpf_htons(csum_delta(bpf_ntohs(ip->check), IPPROTO_TCP - IPPROTO_UDP + 12 + (int)pad_alloc));

  // Update TCP header data offset
  tcp->doff = 5;

  // Reset UDP checksum since current value is useless when L4 checksum is offloaded
  udp->check = 0;

  LOG_INFO("egress done");
  return TC_ACT_OK;
}
