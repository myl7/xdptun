// Copyright (C) 2023 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

// Checksum utilites copied & modified from Linux v6.1.8.
// Relicensed under SPDX-License-Identifier: GPL-2.0-or-later.

#pragma once

#include "vmlinux.h"

// From <linux/errno.h>
#define EINVAL 22
#define EFAULT 14

// From Linux /include/asm-generic/checksum.h
static inline __sum16 csum_fold(__wsum csum) {
  u32 sum = csum;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return ~sum;
}

// From Linux /arch/x86/include/asm/checksum_64.h

static inline u32 add32_with_carry(u32 a, u32 b) {
  u64 sum = (u64)a + b;
  return (u32)sum + (sum >> 32);
}

static inline __wsum csum_add(__wsum csum, __wsum addend) {
  return add32_with_carry(csum, addend);
}

// From Linux /include/net/checksum.h
/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Checksumming functions for IP, TCP, UDP and so on
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Borrows very liberally from tcp.c and ip.c, see those
 *		files for more names.
 */

static __always_inline __wsum csum_unfold(__sum16 n) {
  return (__wsum)n;
}

static __always_inline void csum_replace_by_diff(__sum16 *sum, __wsum diff) {
  *sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}

// From Linux /net/core/filter.c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux Socket Filter - Kernel level socket filtering
 *
 * Based on the design of the Berkeley Packet Filter. The new
 * internal format has been designed by PLUMgrid:
 *
 *	Copyright (c) 2011 - 2014 PLUMgrid, http://plumgrid.com
 *
 * Authors:
 *
 *	Jay Schulist <jschlst@samba.org>
 *	Alexei Starovoitov <ast@plumgrid.com>
 *	Daniel Borkmann <dborkman@redhat.com>
 *
 * Andi Kleen - Fix a few bad bugs and races.
 * Kris Katterjohn - Added many additional checks in bpf_check_classic()
 */
// offset needs to be bound checked in advance, or uses const
static long local_bpf_csum_replace(void *data, void *data_end, u32 offset, u64 from, u64 to, u64 flags) {
  __sum16 *ptr;
  if (flags) return -EINVAL;
  ptr = (__sum16 *)(data + offset);
  if ((void *)ptr + 2 > data_end) return -EFAULT;
  switch (flags) {
    case 0:
      if (from != 0) return -EINVAL;
      csum_replace_by_diff(ptr, to);
      break;
    default:
      return -EINVAL;
  }
  return 0;
}
