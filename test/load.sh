#!/usr/bin/env bash
set -euo pipefail

# XDP up
sudo ip link set dev eth0 xdp obj ingress.o sec ingress
# XDP down
sudo ip link set dev eth0 xdp off

# TC BPF prepare
sudo tc qdisc add dev eth0 clsact
# TC BPF up
sudo tc filter add dev eth0 egress bpf da obj egress.o sec egress
# TC BPF down
sudo tc filter del dev eth0 egress
