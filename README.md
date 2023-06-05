# xdptun

UDP packet obfuscation with eBPF, which tunnels UDP over pseudo-TCP

## Environment

`vmlinux.h` is generated by `bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h`.
`vmlinux-uname.txt` is generated by `uname -a > src/bpf/vmlinux-uname.txt`.

## License

Copyright (C) myl7

SPDX-License-Identifier: GPL-2.0-or-later
