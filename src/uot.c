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
#include "log.h"

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
  int p = bpf_ntohs(ethh->h_proto);
  if (p != ETH_P_IP) {
    if (p != ETH_P_ARP) {
      log_debug_pass4proto("eth", ETH_P_IP, p);
    }
    return XDP_PASS;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  void *iph_end = (void *) iph + sizeof(*iph);
  if (iph_end > data_end) {
    return XDP_ABORTED;
  }
  p = bpf_ntohs(iph->protocol);
  if (p != IPPROTO_UDP) {
    log_debug_pass4proto("ip", IPPROTO_UDP, p);
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
  memset(tcph, 0, sizeof(*tcph));
  tcph->res1 |= bpf_htons(0x8);
  tcph->doff += bpf_htons(sizeof(*tcph));
  tcph->check = 0;

  return XDP_TX;
}

SEC("uot_recv")
int uot_recv_fn(struct xdp_md *ctx) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  struct ethhdr *ethh = data;
  void *ethh_end = (void *) ethh + sizeof(*ethh);
  if (ethh_end > data_end) {
    return XDP_DROP;
  }
  int p = bpf_ntohs(ethh->h_proto);
  if (p != ETH_P_IP) {
    if (p != ETH_P_ARP) {
      log_debug_pass4proto("eth", ETH_P_IP, p);
    }
    return XDP_PASS;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  void *iph_end = (void *) iph + sizeof(*iph);
  if (iph_end > data_end) {
    return XDP_DROP;
  }
  p = bpf_ntohs(iph->protocol);
  if (p != IPPROTO_TCP) {
    log_debug_pass4proto("ip", IPPROTO_TCP, p);
    return XDP_PASS;
  }

  struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
  void *tcph_end = (void *) tcph + sizeof(*tcph);
  if (tcph_end > data_end) {
    return XDP_DROP;
  }
  if ((bpf_ntohs(tcph->res1) & 0x8) == 0) {
    return XDP_PASS;
  }

  struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4) + tcph->doff;
  void *udph_end = (void *) udph + sizeof(*udph);
  if (udph_end > data_end) {
    return XDP_DROP;
  }

  void *udpd_end = data + sizeof(struct ethhdr) + iph->tot_len;
  if (udpd_end > data_end || udph->len != udph_end - (void *) udph - sizeof(struct udphdr)) {
    return XDP_DROP;
  }

  memmove(tcph, udph, sizeof(*udph));

  iph->tot_len = bpf_htons(udph->len + (iph->ihl * 4));
  iph->check = 0;
  iph->check = 0;

  void *new_data_end = (void *) iph + iph->tot_len;
  if (bpf_xdp_adjust_tail(ctx, (int) (new_data_end - data_end)) < 0) {
    return XDP_DROP;
  }

  return XDP_TX;
}
