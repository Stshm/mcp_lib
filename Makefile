CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g
CFLAGS += -fPIC

OBJS = mcp_transport.o mcp_sandbox.o mcp_path.o mcp_fs.o mcp_time.o
TARGET = libmcp_core.a

all: $(TARGET)

$(TARGET): $(OBJS)
	ar rcs $@ $^

%.o: %.c mcp_core.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) tests/test_path

test: $(TARGET)
	$(CC) $(CFLAGS) -o tests/test_path tests/test_path.c $(TARGET)
	./tests/test_path

.PHONY: all clean test
