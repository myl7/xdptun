// Copyright (C) 2022, 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "egress.h"

const char LICENSE[] SEC("license") = "GPL";

const volatile u32 peer_ip = 0;

SEC("tc")
int egress(struct __sk_buff *skb) {
  int err;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
  if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
  u8 ip_hlen = ip->ihl * 4;
  if (ip_hlen < sizeof(struct iphdr)) return TC_ACT_SHOT;
  // Limit upper bound for manual memmove
  if (ip_hlen > 60) return TC_ACT_SHOT;
  if ((void *)ip + ip_hlen > data_end) return TC_ACT_SHOT;
  if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
  if (bpf_ntohl(ip->daddr) != peer_ip) return TC_ACT_OK;

  err = bpf_skb_change_head(skb, 12, 0);
  if (err) return TC_ACT_OK;

  // This section contains many dup pkt bound checks,
  // since BPF verifier is not smart enough to allow the read
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  u8 all_hlen = sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);
  u8 i;
  // Manual memmove since len is from variable
  for (i = sizeof(struct ethhdr); i < all_hlen - 4; i += 4) {
    if (data + 12 + i + 4 > data_end) return TC_ACT_SHOT;
    __builtin_memcpy(data + i, data + 12 + i, 4);
  }
  switch (all_hlen - i) {
    case 4:
      if (data + 12 + i + 4 > data_end) return TC_ACT_SHOT;
      __builtin_memcpy(data + i, data + 12 + i, 4);
      break;
    case 2:
      if (data + 12 + i + 2 > data_end) return TC_ACT_SHOT;
      __builtin_memcpy(data + i, data + 12 + i, 2);
      break;
    default:
      return TC_ACT_SHOT;
  }
  // Note: UDP len & check, which are at TCP seq, are not zeroed so far
  if (data + all_hlen + 12 > data_end) return TC_ACT_SHOT;
  __builtin_memset(data + all_hlen + 4, 0, sizeof(struct udphdr));
  s64 check_diff = 0;

  ip = data + sizeof(struct ethhdr);
  if ((void *)ip + ip_hlen > data_end) return TC_ACT_SHOT;
  u32 ip_words[3];
  __builtin_memcpy(ip_words, ip, 12);
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
  check_diff += bpf_csum_diff(ip_words, 12, (void *)ip, 12, ip->check);

  struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_hlen;
  if ((void *)(tcp + 1) > data_end) return TC_ACT_SHOT;
  u32 tcp_words[4];
  __builtin_memcpy(tcp_words, tcp, 16);
  tcp->doff = 5;
  tcp->seq = 0;
  check_diff += bpf_csum_diff(tcp_words, 16, (void *)tcp, 16, check_diff);

  err = bpf_l3_csum_replace(skb, (void *)&ip->check - data, 0, check_diff, 0);
  if (err) return TC_ACT_SHOT;

  return TC_ACT_OK;
}
