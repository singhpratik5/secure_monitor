# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include -fPIC
LDFLAGS = -ldl -lpthread
DEBUG_FLAGS = -g -DDEBUG

# Directories
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
PLUGIN_DIR = plugins
TEST_DIR = tests

# Target binary
TARGET = $(BIN_DIR)/secure_monitor

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Plugin files
PLUGIN_SRCS = $(wildcard $(PLUGIN_DIR)/*.c)
PLUGIN_OBJS = $(patsubst $(PLUGIN_DIR)/%.c,$(BIN_DIR)/%.so,$(PLUGIN_SRCS))

# Default target
all: directories $(TARGET) plugins

# Create directories
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Build main executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $(TARGET)"

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Build plugins
plugins: $(PLUGIN_OBJS)

$(BIN_DIR)/%.so: $(PLUGIN_DIR)/%.c
	$(CC) $(CFLAGS) -shared -o $@ $<
	@echo "Built plugin $@"

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts"

# Install
install: all
	install -d /usr/local/bin
	install -m 755 $(TARGET) /usr/local/bin/
	install -d /usr/lib/secure_monitor/plugins
	install -m 644 $(BIN_DIR)/*.so /usr/lib/secure_monitor/plugins/
	install -d /etc/secure_monitor
	install -m 644 config/monitor.conf /etc/secure_monitor/
	install -m 755 scripts/init-script.sh /etc/init.d/secure_monitor
	@echo "Installation complete"

# Uninstall
uninstall:
	rm -f /usr/local/bin/secure_monitor
	rm -rf /usr/lib/secure_monitor
	rm -rf /etc/secure_monitor
	rm -f /etc/init.d/secure_monitor
	@echo "Uninstall complete"

# Build tests
tests: directories
	$(CC) $(CFLAGS) -o $(BIN_DIR)/test_protocol $(TEST_DIR)/test_protocol.c -L$(BIN_DIR) $(LDFLAGS)
	@echo "Built tests"

# Run tests
test: tests
	./scripts/test_suite.sh

.PHONY: all directories plugins debug clean install uninstall tests test