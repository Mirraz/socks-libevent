CC=gcc
LD=gcc
STRIP=true
WARNINGS=-Wall -Wextra
COPTIM=
DEFINES=
INCLUDES=
CFLAGS=$(WARNINGS) $(COPTIM) $(DEFINES) $(INCLUDES)
LDOPTIM=
LIBFILES=-levent_core
LDFLAGS=$(WARNINGS) $(LDOPTIM) $(LIBFILES)
SRC_DIR=.
BUILD_DIR=build
EXECUTABLE=socks_server_libevent


all: $(BUILD_DIR) $(EXECUTABLE)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(EXECUTABLE): $(BUILD_DIR)/main_loop.o $(BUILD_DIR)/socks_proto.o $(BUILD_DIR)/common.o
	$(LD) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

$(BUILD_DIR)/main_loop.o: $(SRC_DIR)/main_loop.c $(SRC_DIR)/socks_proto.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/socks_proto.o: $(SRC_DIR)/socks_proto.c $(SRC_DIR)/socks_proto.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/common.o: $(SRC_DIR)/common.c $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

clean:
	rm -rf $(BUILD_DIR)

