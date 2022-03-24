// Copyright (c) 2022 myl7
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <bpf/bpf_helpers.h>

#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_DEBUG 2

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_DEBUG
#endif
#ifndef LOG_MSG_BODY_MAXSIZE
#define LOG_MSG_BODY_MAXSIZE 50
#endif
#ifndef LOG_MAP_NAME
#define LOG_MAP_NAME log_map
#endif
#ifndef LOG_CTX_NAME
#define LOG_CTX_NAME ctx
#endif

#define LOG_MSG_HDR_MAXSIZE 10
#define LOG_MSG_MAXSIZE (LOG_MSG_HDR_MAXSIZE + LOG_MSG_BODY_MAXSIZE)

#ifdef LOG_USE_MAP
#define SETUP_LOG_MAP(name)                      \
  struct {                                       \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
    __uint(key_size, sizeof(int));               \
    __uint(value_size, sizeof(__u32));           \
    __uint(max_entries, 1);                      \
  } name SEC(".maps");
#else
#define SETUP_LOG_MAP(name)
#endif

// FIXME: BPF_SNPRINTF and bpf_perf_event_output seem not to work
#define LOG_TO_MAP(s, args...)                                      \
  ({                                                                \
    BPF_PRINTK_FMT_MOD char out[LOG_MSG_MAXSIZE];                   \
    __u64 n = BPF_SNPRINTF(out, sizeof(out), s, ##args);            \
    bpf_perf_event_output(LOG_CTX_NAME, &LOG_MAP_NAME, 0, &out, n); \
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

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#ifdef LOG_USE_MAP
#define LOG_DEBUG(s, args...) LOG_TO_MAP("DEBUG: " s, ##args)
#else
#define LOG_DEBUG(s, args...) bpf_printk("DEBUG: " s, ##args)
#endif
#else
#define LOG_DEBUG(s, args...)
#endif
