SRC_DIR=src
BIN_DIR=bin
OBJ_DIR=obj
IFL_T12CLIENT=ifl_t12client
IFL_T12CLIENT_BIN=$(BIN_DIR)/$(IFL_T12CLIENT)
TSERVER=tserver
TSERVER_BIN=$(BIN_DIR)/$(TSERVER)
TARGET=$(IFL_T12CLIENT_BIN) $(TSERVER_BIN)

DEPENDENCY_DIR=dependency
OPENSSL_1_1_1=openssl-1.1.1a
OPENSSL_1_1_1_DIR=$(DEPENDENCY_DIR)/$(OPENSSL_1_1_1)
OPENSSL_1_0_2_DIR=$(DEPENDENCY_DIR)/openssl-1.0.2q
OPENSSL_1_1_1_LIBS=$(OPENSSL_1_1_1_DIR)/libssl.a
DEPENDENCY = $(OPENSSL_1_1_1_LIBS)

COMMON_SRC_DIR=$(SRC_DIR)/common
COMMON_SRCS=$(wildcard $(COMMON_SRC_DIR)/*.c)

IFL_T12CLIENT_SRC_DIR=$(SRC_DIR)/$(IFL_T12CLIENT)
IFL_T12CLIENT_SRCS=$(wildcard $(IFL_T12CLIENT_SRC_DIR)/*.c) $(COMMON_SRCS)
IFL_T12CLIENT_OBJS=$(addprefix $(OBJ_DIR)/,$(IFL_T12CLIENT_SRCS:.c=.o))

TSERVER_SRC_DIR=$(SRC_DIR)/$(TSERVER)
TSERVER_SRCS=$(wildcard $(TSERVER_SRC_DIR)/*.c) $(COMMON_SRCS) $(COMMON_SRCS)
TSERVER_OBJS=$(addprefix $(OBJ_DIR)/,$(TSERVER_SRCS:.c=.o))

CC = gcc
AR = ar
RM = rm

IFL_DIR=../IFL

ifeq ($(NOSAN),1)
	SAN_CFLAGS=
else
	SAN_CFLAGS= -fsanitize=address -static-libasan
endif

CFLAGS = -g -ggdb -O0 -Wall -Werror -I include -I $(COMMON_SRC_DIR) $(SAN_CFLAGS) -fstack-protector-all

IFL_T12CLIENT_CFLAGS = -I $(IFL_DIR)/include -I ./$(IFL_T12CLIENT_SRC_DIR)
IFL_LFLAGS = -L $(IFL_DIR)/bin -lifl -lexpat $(SAN_CFLAGS)

OSSL_CFLAGS = -I $(OPENSSL_1_1_1_DIR)/include
OSSL_LFLAGS = $(OPENSSL_1_1_1_DIR)/libssl.a $(OPENSSL_1_1_1_DIR)/libcrypto.a -lpthread -ldl $(SAN_CFLAGS)

.PHONY: all clean init_setup build_dependency

all: init_setup build_dependency $(TARGET)

init_setup:
	@mkdir -p $(OBJ_DIR)/$(COMMON_SRC_DIR)
	@mkdir -p $(OBJ_DIR)/$(IFL_T12CLIENT_SRC_DIR)
	@mkdir -p $(OBJ_DIR)/$(TSERVER_SRC_DIR)
	@mkdir -p $(BIN_DIR)

build_dependency:$(DEPENDENCY)

$(OPENSSL_1_1_1_LIBS): $(OPENSSL_1_1_1_DIR).tar.gz
	cd $(DEPENDENCY_DIR) && tar -zxvf $(OPENSSL_1_1_1).tar.gz
	cd $(OPENSSL_1_1_1_DIR) && ./config -d
	cd $(OPENSSL_1_1_1_DIR) && make

$(OBJ_DIR)/$(COMMON_SRC_DIR)/%.o:$(COMMON_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ -c $^

$(OBJ_DIR)/$(IFL_T12CLIENT_SRC_DIR)/%.o:$(IFL_T12CLIENT_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(IFL_T12CLIENT_CFLAGS) -o $@ -c $^

$(IFL_T12CLIENT_BIN): $(IFL_T12CLIENT_OBJS)
	$(CC) $^ $(IFL_LFLAGS) -o $@

$(OBJ_DIR)/$(TSERVER_SRC_DIR)/%.o:$(TSERVER_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(OSSL_CFLAGS) -o $@ -c $^

$(TSERVER_BIN): $(TSERVER_OBJS)
	$(CC) $^ $(OSSL_LFLAGS) -o $@

clean:
	@$(RM) -rf $(TARGET)
	@$(RM) -rf $(OBJ_DIR) $(BIN_DIR)
