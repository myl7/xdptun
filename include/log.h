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

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define LOG_ERROR(s, args...) bpf_printk("ERROR: " s, ##args)
#else
#define LOG_ERROR(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define LOG_INFO(s, args...) bpf_printk("INFO: " s, ##args)
#else
#define LOG_INFO(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_VERBOSE
#define LOG_VERBOSE(s, args...) bpf_printk("VERBOSE: " s, ##args)
#else
#define LOG_VERBOSE(s, args...)
#endif

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define LOG_DEBUG(s, args...) bpf_printk("DEBUG: " s, ##args)
#else
#define LOG_DEBUG(s, args...)
#endif
