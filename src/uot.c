// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "mem.h"

char _license[] SEC("license") = "GPL";  // NOLINT(bugprone-reserved-identifier)

SEC("uot_send")
int uot_send_f(struct xdp_md *ctx) {
  if (bpf_xdp_adjust_tail(ctx, sizeof(struct tcphdr)) < 0) {
    return XDP_ABORTED;
  }

  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  struct ethhdr *ethh = data;
  void *ethh_end = (void *) ethh + sizeof(*ethh);
  if (ethh_end > data_end) {
    return XDP_ABORTED;
  }
  if (ethh->h_proto != ETH_P_IP) {
    return XDP_PASS;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  void *iph_end = (void *) iph + sizeof(*iph);
  if (iph_end > data_end) {
    return XDP_ABORTED;
  }
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
  void *udph_end = (void *) udph + sizeof(*udph);
  if (udph_end > data_end) {
    return XDP_ABORTED;
  }

  struct udphdr *new_udph = (void *) udph + sizeof(struct tcphdr);
  void *new_udph_end = (void *) new_udph + sizeof(*new_udph);
  if (new_udph_end > data_end) {
    return XDP_ABORTED;
  }

  memmove(new_udph, udph, sizeof(*new_udph));

  struct tcphdr *tcph = (void *) udph;
  tcph->res1 = 0x8;
  tcph->doff += sizeof(*tcph);

  return XDP_TX;
}

SEC("uot_recv")
int uot_recv_f(struct xdp_md *ctx) {
  // void *data = (void *) (long) ctx->data;
  // void *data_end = (void *) (long) ctx->data_end;

  return XDP_TX;
}
