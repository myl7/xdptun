# Copyright (c) 2022 myl7
# SPDX-License-Identifier: GPL-2.0-or-later

# Define logging level
# 0: error, 1: info, 2: debug
LOG_LEVEL ?= 2
LOG_USE_MAP ?=

# Define filter config
FILTER_PORT ?= 8000

# Basic config
BUILD_DIR ?= build
SRC_DIR = src
INCLUDE_DIR = include

# BPF config
BPF_SRC_DIR = $(SRC_DIR)/bpf
BPF_BUILD_DIR = $(BUILD_DIR)/bpf
BPF_SRCS = $(wildcard $(BPF_SRC_DIR)/*.c)
BPF_OBJS = $(BPF_SRCS:$(BPF_SRC_DIR)/%.c=$(BPF_BUILD_DIR)/%.o)
BPF_DEPS = $(BPF_OBJ:%.o=%.d)
BPF_FLAGS = -O2 -Wall -target bpf -I$(INCLUDE_DIR) -DLOG_LEVEL=$(LOG_LEVEL)$(if $(LOG_USE_MAP), -DLOG_USE_MAP)$(if $(FILTER_PORT), -DFILTER_PORT=$(FILTER_PORT))

# Executable config
CLANG ?= clang
CLANG_FORMAT ?= clang-format

all: mkdir $(BPF_OBJS)

.PHONY: all mkdir clean format format-check

-include $(BPF_DEPS)

$(BPF_BUILD_DIR)/%.o: $(BPF_SRC_DIR)/%.c
	$(CLANG) $(BPF_FLAGS) -MMD -c $< -o $@

mkdir:
	@mkdir -p $(BPF_BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR)

format:
	$(CLANG_FORMAT) -i src/**/*.c include/*.h

format-check:
	$(CLANG_FORMAT) -n src/**/*.c include/*.h
