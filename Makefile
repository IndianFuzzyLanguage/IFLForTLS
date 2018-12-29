SRC_DIR=src
BIN_DIR=bin
OBJ_DIR=obj
TEST_BIN=$(BIN_DIR)/ifl_tls12_client
TARGET=$(TEST_BIN)

SRCS=$(wildcard $(SRC_DIR)/*.c)
OBJS=$(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))

CC = gcc
AR = ar
RM = rm

IFL_DIR=../IFL

CFLAGS = -g -ggdb -O0 -Wall -Werror
LFLAGS = -L $(IFL_DIR)/bin -lifl

INC = -I ./src -I $(IFL_DIR)/include
CFLAGS += $(INC)

.PHONY: all clean init_setup

all: init_setup $(TARGET)

init_setup:
	@mkdir -p $(OBJ_DIR)/$(SRC_DIR)
	@mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(TEST_BIN): $(OBJS)
	$(CC) $^ $(LFLAGS) -o $@

clean:
	@$(RM) -rf $(OBJS)
	@$(RM) -rf $(TARGET)
	@$(RM) -rf $(OBJ_DIR) $(BIN_DIR)
