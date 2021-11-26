// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include "utils.h"

char _license[] SEC("license") = "GPL";  // NOLINT(bugprone-reserved-identifier)

SEC("uot_send")
int uot_send_f(struct xdp_md *ctx) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  return XDP_TX;
}

SEC("uot_recv")
int uot_recv_f(struct xdp_md *ctx) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  return XDP_TX;
}
