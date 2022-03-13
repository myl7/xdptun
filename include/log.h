// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <bpf/bpf_helpers.h>

#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_VERBOSE 2
#define LOG_LEVEL_DEBUG 3

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_VERBOSE
#endif
#ifndef LOG_MSG_MAX_SIZE
#define LOG_MSG_MAX_SIZE 255
#endif
#ifndef LOG_MAP_NAME
#define LOG_MAP_NAME log_map
#endif

#ifdef LOG_USE_MAP
#define SETUP_LOG_MAP(name)                \
  struct {                                 \
    __u32 type;                            \
    __u32 max_entries;                     \
    __u32 key_size;                        \
    __u32 value_size;                      \
  } name SEC(".maps") = {                  \
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY, \
    .max_entries = 2,                      \
    .key_size = sizeof(int),               \
    .value_size = sizeof(__u32),           \
  }
#else
#define SETUP_LOG_MAP(name)
#endif

#define LOG_TO_MAP(s, args...)                              \
  ({                                                        \
    char out[LOG_MSG_MAX_SIZE];                             \
    __u64 n = BPF_SNPRINTF(out, sizeof(out), s, ##args);    \
    bpf_perf_event_output(NULL, &LOG_MAP_NAME, 0, &out, n); \
  })

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#ifdef LOG_USE_MAP
#define LOG_ERROR(s, args...) LOG_TO_MAP("ERROR: " s, ##args)
#else
#define LOG_ERROR(s, args...) bpf_printk("ERROR: " s, ##args)
#endif
#else
#define LOG_ERROR(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#ifdef LOG_USE_MAP
#define LOG_INFO(s, args...) LOG_TO_MAP("INFO: " s, ##args)
#else
#define LOG_INFO(s, args...) bpf_printk("INFO: " s, ##args)
#endif
#else
#define LOG_INFO(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_VERBOSE
#ifdef LOG_USE_MAP
#define LOG_VERBOSE(s, args...) LOG_TO_MAP("VERBOSE: " s, ##args)
#else
#define LOG_VERBOSE(s, args...) bpf_printk("VERBOSE: " s, ##args)
#endif
#else
#define LOG_VERBOSE(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#ifdef LOG_USE_MAP
#define LOG_DEBUG(s, args...) LOG_TO_MAP("DEBUG: " s, ##args)
#else
#define LOG_DEBUG(s, args...) bpf_printk("DEBUG: " s, ##args)
#endif
#else
#define LOG_DEBUG(s, args...)
#endif
