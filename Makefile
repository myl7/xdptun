# Copyright (C) 2021-2022 myl7
# SPDX-License-Identifier: GPL-2.0-or-later

# Available flags
RELEASE ?=

# Basic dirs
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR ?= build

# BPF config
BPF_DIR = src/bpf
BPF_FILES = $(wildcard $(BPF_DIR)/*.c)
BPF_TARGETS = $(BPF_FILES:$(BPF_DIR)/%.c=$(BUILD_DIR)/%.o)
BPF_FLAGS = -O2 -Wall -target bpf -I$(INCLUDE_DIR)$(if ! $(RELEASE), -DDEBUG,)

# Executable config
CLANG ?= clang
CLANG_FORMAT ?= clang-format

all: mkdir $(BPF_TARGETS)

.PHONY: all mkdir clean format format-check

$(BUILD_DIR)/ingress.o: $(BPF_DIR)/ingress.c $(INCLUDE_DIR)/mem.h
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

$(BUILD_DIR)/egress.o: $(BPF_DIR)/egress.c $(INCLUDE_DIR)/mem.h
	$(CLANG) $(BPF_FLAGS) -c $< -o $@

mkdir:
	@mkdir -p $(BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR)

format:
	$(CLANG_FORMAT) -i src/**/*.c include/*.h

format-check:
	$(CLANG_FORMAT) -n src/**/*.c include/*.h
