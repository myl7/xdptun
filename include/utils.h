#pragma once

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif  // memset

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif  // memcpy

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif  // memmove

#ifndef always_inline
#define always_inline inline __attribute__((always_inline))
#endif  // always_inline
