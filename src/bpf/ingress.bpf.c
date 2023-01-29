// Copyright (C) 2022, 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ingress.h"
#include "tail_meta.h"

const char LICENSE[] SEC("license") = "GPL";

const volatile u32 peer_ip = 0;

SEC("xdp")
int ingress(struct xdp_md *ctx) {
  long err;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) return XDP_DROP;
  if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

  struct iphdr *ip = data + sizeof(struct ethhdr);
  if ((void *)(ip + 1) > data_end) return XDP_DROP;
  u8 ip_hlen = ip->ihl * 4;
  if ((void *)ip + ip_hlen > data_end) return XDP_DROP;
  if (ip->protocol != IPPROTO_UDP) return XDP_PASS;
  if (bpf_ntohl(ip->saddr) != peer_ip) return XDP_PASS;
  u16 ip_tot_len = bpf_ntohs(ip->tot_len);
  const extended_len = 12 + sizeof(struct xdptun_tail_meta);
  u16 tail_offset = ip_tot_len - extended_len;
  if (tail_offset < 0) return XDP_PASS;
  // TODO: Provide an option
  if (tail_offset > 0xff - extended_len) {
    return XDP_PASS;
  }
  // Filter OK

  s64 l4_check_diff = 0;
  // tail = data_end - extended_len
  void *tail = data + sizeof(struct ethhdr) + tail_offset;
  if (tail + extended_len > data_end) return XDP_DROP;
  void *udp_body = data + sizeof(struct ethhdr) + ip_hlen + sizeof(struct udphdr);
  if (udp_body + 12 > data_end) return XDP_DROP;
  l4_check_diff += bpf_csum_diff(udp_body, 12, NULL, 0, 0);
  __builtin_memcpy(udp_body, tail, 12);

  struct udphdr *udp = data + sizeof(struct ethhdr) + ip_hlen;
  if ((void *)(udp + 1) > tail) return XDP_DROP;
  struct xdptun_tail_meta meta;
  __builtin_memcpy(&meta, tail + 12, sizeof(struct xdptun_tail_meta));
  udp->len = meta.udp_len;
  meta.udp_len = 0;
  l4_check_diff += bpf_csum_diff(&meta, sizeof(struct xdptun_tail_meta), NULL, 0, 0);

  s32 padded_len = (s32)ip_tot_len - (s32)ip_hlen - (s32)bpf_ntohs(udp->len) - (s32)extended_len;
  if (padded_len < 0 || padded_len > 12) return XDP_DROP;
  s32 ip_new_tot_len = (s32)ip_tot_len - (s32)padded_len - (s32)extended_len;
  if (ip_new_tot_len < ip_hlen) return XDP_DROP;
  u32 ip_words[3];
  __builtin_memcpy(ip_words, ip, 12);
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = bpf_htons(ip_new_tot_len);
  s64 l3_check_diff = bpf_csum_diff(ip_words, 12, (void *)ip, 12, 0);

  err = bpf_xdp_adjust_tail(ctx, -padded_len - extended_len);
  if (err) {
    bpf_printk("xdptun-egress: xdp_adjust_tail failed with %d", err);
    return XDP_DROP;
  }

  data = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;
  err =
    local_bpf_csum_replace(data, data_end, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, l3_check_diff, 0);
  if (err) return XDP_DROP;
  err = local_bpf_csum_replace(
    data, data_end, sizeof(struct ethhdr) + ip_hlen + offsetof(struct udphdr, check), 0, l4_check_diff, 0);
  if (err) return XDP_DROP;

  return XDP_PASS;
}
