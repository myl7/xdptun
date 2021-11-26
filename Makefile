SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR ?= build
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
TARGETS = $(SRC_FILES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
INCLUDE_FILES = $(wildcard $(INCLUDE_DIR)/*.h)
CFLAGS = -O2 $(if $(DEBUG),-g ,)-Wall -target bpf -I$(INCLUDE_DIR)
CLANG ?= clang

all: mkdir $(TARGETS)

.PHONY: all mkdir clean

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDE_FILES)
	$(CLANG) $(CFLAGS) -c $< -o $@

mkdir:
	@mkdir -p $(BUILD_DIR)

clean:
	-rm -rf $(BUILD_DIR)
