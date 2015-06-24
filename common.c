#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"

void printf_err(const char *format, ...) {
	va_list arglist;
	va_start(arglist, format);
	vfprintf(stderr, format, arglist);
	va_end(arglist);
	fprintf(stderr, "\n");
}

int make_socket_nonblocking(int fd) {
	int flags;
	if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
		return -1;
	}
	if (!(flags & O_NONBLOCK)) {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			return -1;
		}
	}
	return 0;
}

