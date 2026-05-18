CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2 -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE
INCLUDES = -Ivendor/tomlc99

SRC = bandit-helper.c vendor/tomlc99/toml.c
TEST_SRC = test_bandit.c vendor/tomlc99/toml.c

BIN = bin/bandit-helper
TEST_BIN = bin/test_bandit

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRC) | bin
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRC)

$(TEST_BIN): $(TEST_SRC) | bin
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SRC)

bin:
	mkdir -p bin

test: $(TEST_BIN)
	$(TEST_BIN)

clean:
	rm -rf bin
