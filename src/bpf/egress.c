// Copyright (C) 2021-2022 myl7
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

SEC("license")
const char ___license[] = "GPL";

SEC("xdptun_egress")
int egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if (check_bound(eth, eth + 1, data, data_end)) {
    return TC_ACT_OK;
  }
  if (eth->h_proto != bpf_ntohs(ETH_P_IP)) {
    return TC_ACT_OK;
  }

  struct iphdr *ip = (void *)(eth + 1);
  if (check_bound(ip, ip + 1, data, data_end)) {
    return TC_ACT_OK;
  }
  if (check_bound(ip, (void *)ip + ip->ihl * 4, data, data_end)) {
    return TC_ACT_OK;
  }
  if (ip->protocol != IPPROTO_UDP) {
    return TC_ACT_OK;
  }

  struct udphdr *udp = (void *)ip + ip->ihl * 4;
  if (check_bound(udp, udp + 1, data, data_end)) {
    return TC_ACT_OK;
  }

  void *udp_data = udp + 1;

#ifdef DEBUG
  bpf_printk("egress recv");
#endif

  ip->protocol = IPPROTO_TCP;
  // 12 bytes are moved to tail to leave enough space to transform UDP header to TCP header
  bpf_skb_change_tail(skb, skb->len + 12, 0);

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  eth = data;
  if (check_bound(eth, eth + 1, data, data_end)) {
    return TC_ACT_OK;
  }

  ip = (void *)(eth + 1);
  if (check_bound(ip, ip + 1, data, data_end)) {
    return TC_ACT_OK;
  }
  if (check_bound(ip, (void *)ip + ip->ihl * 4, data, data_end)) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
  if (check_bound(tcp, tcp + 1, data, data_end)) {
    return TC_ACT_OK;
  }

  __u8 buf[12];
  memcpy(buf, (void *)tcp + 4, 12);
  memset((void *)tcp + 4, 0, 12);
  unsigned offset = (void *)ip - data + bpf_ntohs(ip->tot_len);
  bpf_skb_store_bytes(skb, offset, buf, 12, 0);

#ifdef DEBUG
  bpf_printk("egress done");
#endif

  return TC_ACT_OK;
}
