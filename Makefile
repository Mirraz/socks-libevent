CC=gcc
LD=gcc
STRIP=true
WARNINGS=-Wall -Wextra
DEBUG=-ggdb
COPTIM=-march=native -mfpmath=sse,387 -O2 -fomit-frame-pointer -pipe
DEFINES=
INCLUDES=
CFLAGS=$(WARNINGS) $(COPTIM) $(DEFINES) $(INCLUDES) $(DEBUG)
LDOPTIM=-Wl,-O1 -Wl,--as-needed
LIBFILES=-levent_core -levent_extra
LDFLAGS=$(WARNINGS) $(LDOPTIM) $(LIBFILES) $(DEBUG)
SRC_DIR=.
BUILD_DIR=build
EXECUTABLE=socks_server_libevent


all: $(BUILD_DIR) $(EXECUTABLE)

$(BUILD_DIR):
	mkdir $(BUILD_DIR)

$(EXECUTABLE): $(BUILD_DIR)/main_loop.o $(BUILD_DIR)/transfer.o $(BUILD_DIR)/handle_client.o $(BUILD_DIR)/socks_proto.o $(BUILD_DIR)/task.o $(BUILD_DIR)/common.o $(BUILD_DIR)/stack.o
	$(LD) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@

$(BUILD_DIR)/main_loop.o: $(SRC_DIR)/main_loop.c $(SRC_DIR)/transfer.h $(SRC_DIR)/handle_client.h $(SRC_DIR)/common.h $(SRC_DIR)/stack.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/transfer.o: $(SRC_DIR)/transfer.c $(SRC_DIR)/transfer.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/handle_client.o: $(SRC_DIR)/handle_client.c $(SRC_DIR)/handle_client.h $(SRC_DIR)/transfer.h $(SRC_DIR)/socks_proto.h $(SRC_DIR)/task.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/socks_proto.o: $(SRC_DIR)/socks_proto.c $(SRC_DIR)/socks_proto.h $(SRC_DIR)/task.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/task.o: $(SRC_DIR)/task.c $(SRC_DIR)/task.h $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/common.o: $(SRC_DIR)/common.c $(SRC_DIR)/common.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

$(BUILD_DIR)/stack.o: $(SRC_DIR)/stack.c $(SRC_DIR)/stack.h Makefile
	$(CC) -o $@ $< -c $(CFLAGS)

clean:
	rm -rf $(BUILD_DIR)

