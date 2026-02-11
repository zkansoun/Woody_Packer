NAME := woody_woodpacker
CC := cc
CFLAGS := -Wall -Wextra -Werror
CPPFLAGS := -Iinclude

SRC_DIR := src
OBJ_DIR := obj
DOCS_DIR := docs

SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC))

# Stub build configuration
STUB_SRC := $(DOCS_DIR)/stub_runtime.S
STUB_OBJ := $(DOCS_DIR)/stub_runtime.o
STUB_BIN := $(DOCS_DIR)/stub_runtime.bin
STUB_PAYLOAD := $(SRC_DIR)/stub_payload.inc

$(NAME): $(STUB_PAYLOAD) $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJ) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

# Build stub payload from assembly source
# Process: stub_runtime.S -> stub_runtime.o -> stub_runtime.bin -> stub_payload.inc
stub: $(STUB_PAYLOAD)

$(STUB_PAYLOAD): $(STUB_BIN)
	@echo "Generating stub_payload.inc from stub_runtime.bin..."
	@xxd -i $(STUB_BIN) | sed '1d' | sed '/unsigned int/d' | sed 's/};$$//' > $(STUB_PAYLOAD)
	@echo "Generated $(STUB_PAYLOAD)"

$(STUB_BIN): $(STUB_OBJ)
	@echo "Converting stub_runtime.o to binary..."
	@objcopy -O binary $(STUB_OBJ) $(STUB_BIN)

$(STUB_OBJ): $(STUB_SRC)
	@echo "Assembling stub_runtime.S..."
	@$(CC) -c -nostdlib -fno-asynchronous-unwind-tables -fno-stack-protector -Wa,--noexecstack $(STUB_SRC) -o $(STUB_OBJ)

.PHONY: all clean fclean re stub

all: $(NAME)

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

