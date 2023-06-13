CC = gcc
CFLAGS = -g -Iinclude -Ireference -lcapstone -D_GNU_SOURCE

SRC_DIR = src
BUILD_DIR = build

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGET = debugger.out

.PHONY: gen_build_path gen_execute clean

$(TARGET): gen_build_path gen_execute

gen_build_path:
	test -d $(BUILD_DIR) || mkdir -p $(BUILD_DIR)

gen_execute: $(OBJS)
	$(CC) $^ $(CFLAGS) -o $(TARGET) 

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $< -c -o $@ $(CFLAGS) 

clean:
	rm -f $(TARGET) || true
	rm -rf $(BUILD_DIR) || true
