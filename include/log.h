#pragma once

#include <bpf/bpf_helpers.h>

#ifdef DEBUG
#ifndef LOG_DEBUG
#define LOG_DEBUG
#endif  // LOG_DEBUG
#endif  // DEBUG

#ifdef LOG_DEBUG
#define log_debug_pass4proto(proto, expected, got) ({ \
  char ____proto[] = (proto); \
  bpf_printk("%s proto mismatch: expected %d, got %d", ____proto, (expected), (got)); \
})
#define log_debug(msg, ...) bpf_printk(msg, ##__VA_ARGS__)
#else  // LOG_DEBUG
#define log_debug_pass4proto(proto, expected, got)
#define log_debug(msg, ...)
#endif  // LOG_DEBUG