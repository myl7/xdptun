// Copyright (c) 2021-2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#define BPF_NO_GLOBAL_DATA

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
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

SEC("license")
const char ___license[] = "GPL";

SEC("xdptun_egress")
int egress(struct __sk_buff *skb) {
  void *data, *data_end;
  struct ethhdr *eth;
  struct iphdr *ip;
  struct udphdr *udp;
  struct tcphdr *tcp;

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);

  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  CHECK_IP_BOUND(ip, TC_ACT_OK);
  if (ip->protocol != IPPROTO_UDP) {
    return TC_ACT_OK;
  }

  CHECK_UDP_BOUND(udp, TC_ACT_OK);

#ifdef DEBUG
  bpf_printk("egress recv");
#endif

  __u32 udp_check = bpf_ntohs(udp->check);

  // 12 bytes are moved to tail to leave enough space to transform UDP header to TCP header
  bpf_skb_change_tail(skb, skb->len + 12, 0);

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);
  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  CHECK_IP_BOUND(ip, TC_ACT_OK);
  CHECK_TCP_BOUND(tcp, TC_ACT_OK);

  __u8 buf[12];
  memcpy(buf, (void *)tcp + 4, 12);
  memset((void *)tcp + 4, 0, 12);
  unsigned offset = (void *)ip - data + bpf_ntohs(ip->tot_len);
  bpf_skb_store_bytes(skb, offset, buf, 12, 0);

  data = data_ptr(skb->data);
  data_end = data_ptr(skb->data_end);
  CHECK_ETH_BOUND(eth, TC_ACT_OK);
  CHECK_IP_BOUND(ip, TC_ACT_OK);
  CHECK_TCP_BOUND(tcp, TC_ACT_OK);

  // Update IP header protocol, total length, header checksum
  ip->protocol = IPPROTO_TCP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
  ip->check = bpf_htons(csum_delta(bpf_ntohs(ip->check), IPPROTO_TCP - IPPROTO_UDP + 12));

  // Update TCP header checksum
  tcp->check = bpf_htons(csum_delta(udp_check, IPPROTO_TCP - IPPROTO_UDP + 12));

#ifdef DEBUG
  bpf_printk("egress done");
#endif

  return TC_ACT_OK;
}
