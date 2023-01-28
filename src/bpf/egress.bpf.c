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
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

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
  if (err) return TC_ACT_SHOT;

  // This section contains many dup pkt bound checks,
  // since one check for all read is not admitted by the BPF verifier.
  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;
  u8 all_hlen = sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);
  u8 i;
  // Manual memmove since len is from variable
  for (i = sizeof(struct ethhdr); i < all_hlen; i += 4) {
    if (data + 12 + i + 4 > data_end) return TC_ACT_SHOT;
    __builtin_memcpy(data + i, data + 12 + i, 4);
  }
  if (data + all_hlen + 12 > data_end) return TC_ACT_SHOT;
  __builtin_memset(data + all_hlen, 0, 12);

  ip = data + sizeof(struct ethhdr);
  // Above dup checks have covered IPv4 header range so here bound check can be skipped
  u32 ip_words[3];
  __builtin_memcpy(ip_words, ip, 12);
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 12);
  s64 check_diff = bpf_csum_diff(ip_words, 12, (void *)ip, 12, 0);

  struct tcphdr *tcp = data + sizeof(struct ethhdr) + ip_hlen;
  if ((void *)(tcp + 1) > data_end) return TC_ACT_SHOT;
  u32 tcp_words[4];
  __builtin_memcpy(tcp_words, tcp, 16);
  tcp->doff = 5;
  tcp->seq = 0;

  err = bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, check_diff, 0);
  if (err) return TC_ACT_SHOT;

  return TC_ACT_OK;
}
