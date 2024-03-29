<!-- Copyright (c) 2022 myl7 -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Technical Notes

A detailed report-like technical description can be found in `docs/thesis/{pre,thesis}`, here we only talk about some trivial but technically critical stuff

To aviod confusing anyone, here `alias BPF = eBPF`

## `BPF_NO_GLOBAL_DATA` and `bpf_printk`

```c
// In <bpf/bpf_helpers.h>
#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD
#else
#define BPF_PRINTK_FMT_MOD static const
#endif

#define __bpf_printk(fmt, ...)        \
({              \
  BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;  \
  bpf_trace_printk(____fmt, sizeof(____fmt),  \
       ##__VA_ARGS__);    \
})
```

Since `BPF_NO_GLOBAL_DATA` has no default value (not defined by default), and current eBPF has no BSS or static section[^1] (which means no `static`), to use `bpf_printk`, a `#define BPF_NO_GLOBAL_DATA` is required before `#include <bpf/bpf_helpers.h>`, otherwise the BPF verifier will complain.

[^1]: See [BPF and XDP Reference Guide of cilium docs](https://docs.cilium.io/en/v1.11/bpf/) and paper [Fast Packet Processing with eBPF and XDP: Concepts, Code, Challenges, and Applications](https://doi.org/10.1145/3371038)

## `SEC("license")` Named as `___license`

As we all know, it is better not to use `_` / `__` prefixed string as variable name[^2].
In `<bpf/bpf_helpers.h>` you can also see temporary variables are named with prefix `___`.
Though many tutorials name the section as `_license`, IMO `___license` should be better.

[^2]: See [1.3.3 Reserved Names of GNU libc manual](https://www.gnu.org/software/libc/manual/html_node/Reserved-Names.html)

## Values of `SEC("license")`[^3]

`GPL` = `GPL v2` = `SPDX-License-Identifier: GPL-v2-only` or `SPDX-License-Identifier: GPL-v2-or-later` (since they can both work with `SPDX-License-Identifier: GPL-v2-only`)

The value may affect the symbols a module can be linked with

[^3]: See [linux source comment about all available values and detailed description](https://github.com/torvalds/linux/blob/551acdc3c3d2b6bc97f11e31dcf960bc36343bfc/include/linux/module.h#L186-L229)

## `SEC["maps"]` vs. `SEC[".maps"]`[^4]

```c
// In <bpf/bpf_helpers>
/*
 * Helper structure used by eBPF C program
 * to describe BPF map attributes to libbpf loader
 */
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
} __attribute__((deprecated("use BTF-defined maps in .maps section")));
```

As `SEC["maps"]` uses `bpf_map_def` which is deprecated, you would be better to use `SEC[".maps"]`.
An example can be found in [`include/log.h`](/include/log.h), and also [samples in linux source tree](https://github.com/torvalds/linux/blob/551acdc3c3d2b6bc97f11e31dcf960bc36343bfc/samples/bpf/trace_output_kern.c#L7-L12).

[^4]: Added in [the patch](https://lore.kernel.org/bpf/4553f579-c7bb-2d4c-a1ef-3e4fbed64427@fb.com/t/)

## `ntoh*` in BPF

Use `bpf_ntoh*` in `<bpf/bpf_endian.h>`

## Access data on tail while passing BPF verifier

See [Experiment01 - Accessing data at packet end of xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/experiment01-tailgrow).
To access the final, like 12 bytes, data, an example is available in [`src/bpf/ingress.c`](/src/bpf/ingress.c).
Just `-= 12` and `&= 0xfff` (limit upper bound to pass BPF verifier).

## `memset`, `memmove`, `memcpy`

See [`include/mem.h`](/include/mem.h), and also [BPF and XDP Reference Guide of cilium docs](https://docs.cilium.io/en/v1.11/bpf/)

## `always_inline`

The latest BPF actually HAS function calls, but inlining is still nice.
If you use `clang` to generate the BPF executable (is there any other option?), see [`include/utils.h`](/include/utils.h) to use it.

## Checksum

Checksum code can be found in [`include/csum.h`](/include/csum.h).
Here we use 3 `new_sum = (new_sum & 0xffff) + (new_sum >> 16)`, the reason is included in the comments around.
If you find the checksum is always +/- 1 from the correct value, here may be the reason.

We do not use `bpf_csum_*` and `bpf_l*_csum_replace` because we do not change so many values.
Just be simple.

## Trap of `bpf_xdp_adjust_tail` on Raspberry Pi

Tested on Raspberry Pi 3B+ with Raspberry Pi OS 64 bit, though XDP is basically FINE by default, the NIC card driver of it does not set `frame_sz` of `struct xdp_buff` (`struct xdp_buff` is not exposed but = `struct xdp_md` except on the tail there is one extra field `frame_sz` to record acceptable frame size of current NIC card driver to get `data_hard_end` and enable `bpf_xdp_adjust_tail` to grow). And though this should only affect growing but not shrinking, in `bpf_xdp_adjust_tail` linux source there is a check:

```c
/* ALL drivers MUST init xdp->frame_sz, chicken check below */
if (unlikely(xdp->frame_sz > PAGE_SIZE)) {
  WARN_ONCE(1, "Too BIG xdp->frame_sz = %d\n", xdp->frame_sz);
  return -EINVAL;
}
```

The default value (Or maybe the unexpected value wrongly/deliberately set by the NIC card driver? But the author says the check should be unnecessary if all NIC card driver correctly set the `frame_sz` field[^5]) is over 30000 and bigger than `PAGE_SIZE` which is 4096, causing the check failed and `bpf_xdp_adjust_tail` always returns `-EINVAL` = `-22`.
To temporarily fix it, we comment the check and recompiled the kernel[^6], and after that everything is fine.

[^5]: See [conversation of [PATCH RFC v2 29/33] xdp: allow bpf_xdp_adjust_tail() to grow packet size](https://www.spinics.net/lists/netdev/msg643967.html)
[^6]: See [The Linux kernel of Raspberry Pi Documentation](https://www.raspberrypi.com/documentation/computers/linux_kernel.html) to get detailed steps to recompile the kernel

## Checksum Offload

See [Checksum Offloads of linux docs](https://www.kernel.org/doc/html/v5.16/networking/checksum-offloads.html):

> This interface only allows a single checksum to be offloaded. Where encapsulation is used, the packet may have multiple checksum fields in different header layers, and the rest will have to be handled by another mechanism such as LCO or RCO.

> No offloading of the IP header checksum is performed; it is always done in software. This is OK because when we build the IP header, we obviously have it in cache, so summing it isn’t expensive. It’s also rather short.

## `iproute` BPF verifier complains `Error fetching program/map!` only and show no other things

According to [the Stack Overflow answer](https://stackoverflow.com/questions/64861121/ebpf-program-load-fails-without-verifier-log), it should be a bug of `iproute`.
I meet it only on Arch Linux and on Raspberry Pi OS (64-bit) the detailed error info is finely output.

## Why `-g` is passed even not to debug?

Building BPF with `-g` will add BTF sections to the executable, which is very helpful[^7]

[^7]: See [the kernel doc](https://www.kernel.org/doc/html/latest/bpf/btf.html) for details

## Change Ubuntu to latest stable Linux kernel

To play well with XDP and eBPF, it would be better to use a Linux kernel as new as possible.
Actually `bpf-next` bleeding edge branch is suggested.
To use latest kernel on Ubuntu, following [the guide of Ubuntu Wiki](https://wiki.ubuntu.com/Kernel/MainlineBuilds) should be enough.
One point is though `linux-headers-*-generic_*_amd64.deb` is marked with A, if you can not satisfy its dependency requirement (e.g. a newer libc), you CAN in fact skip it and get package `linux-headers-*-generic` from `linux-headers-*_*_all.deb` which is marked both with A and B.
I CAN NOT ENSURE IT IS STABLE AND SECURE but it works.
