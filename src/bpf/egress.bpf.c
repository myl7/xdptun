// Copyright (C) 2022, 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "egress.h"
#include "tail_meta.h"

const char LICENSE[] SEC("license") = "GPL";

const volatile u32 peer_ip = 0;

SEC("tc")
int egress(struct __sk_buff *skb) {
  int err;
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
  // Take advantage of __bpf_constant_hton*
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
  u8 ip_hlen = ip->ihl * 4;
  if ((void *)ip + ip_hlen > data_end) return TC_ACT_SHOT;
  if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
  if (bpf_ntohl(ip->daddr) != peer_ip) return TC_ACT_OK;

  u16 ip_tot_len = bpf_ntohs(ip->tot_len);
  u16 min_ip_tot_len = ip_hlen + sizeof(struct udphdr) + 12;
  // To align word and handle if UDP body len < 12
  u16 ip_padded_tot_len = ip_tot_len < min_ip_tot_len ? min_ip_tot_len : ip_tot_len + (4 - ip_tot_len % 4) % 4;
  u16 padded_len = ip_padded_tot_len - ip_tot_len;
  const u16 extended_len = 12 + sizeof(struct xdptun_tail_meta);
  err = bpf_skb_change_tail(skb, sizeof(struct ethhdr) + ip_tot_len + padded_len + extended_len, 0);
  if (err) {
    bpf_printk("xdptun-egress: skb_change_tail failed with %d", err);
    return TC_ACT_SHOT;
  }

  data = (void *)(long)skb->data;
  data_end = (void *)(long)skb->data_end;

  void *udp_body = data + sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);
  if (udp_body + 12 > data_end) return TC_ACT_SHOT;
  // Limit ip_padded_tot_len static upper bound for BPF verifier
  // TODO: Provide an option
  if (ip_padded_tot_len + extended_len > 0xff) {
    bpf_printk("xdptun-egress: packet out too large that > %d", 0xff);
    return TC_ACT_SHOT;
  }
  // tail = old data_end + padded_len
  void *tail = data + sizeof(struct ethhdr) + ip_padded_tot_len;
  if (tail + extended_len > data_end) return TC_ACT_SHOT;
  __builtin_memcpy(tail, udp_body, 12);
  __builtin_memset(udp_body, 0, 12);

  struct udphdr *udp = data + sizeof(struct ethhdr) + ip_hlen;
  if ((void *)(udp + 1) > data_end) return TC_ACT_SHOT;
  struct xdptun_tail_meta meta = {
    .udp_len = udp->len,
  };
  // tail has been checked
  __builtin_memcpy(tail + 12, &meta, sizeof(struct xdptun_tail_meta));

  ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) return TC_ACT_SHOT;
  if ((void *)ip + ip_hlen > data_end) return TC_ACT_SHOT;
  u32 ip_words[3];
  __builtin_memcpy(ip_words, ip, 12);
  ip->protocol = IPPROTO_TCP;
  ip->tot_len = bpf_htons(ip_tot_len + padded_len + extended_len);
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
