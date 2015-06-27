#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "common.h"

void everror(const char *s) { // TODO
	fprintf(stderr, "%s\n", s);
}

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

/* return:
	< 0 -- -errno
	= 0 -- read returned EAGAIN
	> 0 -- read bytes
*/
ssize_t read_wrapper(int fd, void *buf, size_t count) {
	ssize_t bytes = read(fd, buf, count);
	if (bytes < 0) {
		switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				return 0;
			case ECONNRESET:
				return -errno;
			default:
				perror("read");
				return -errno;
		}
	} else if (bytes == 0) {
		return -ECONNRESET;
	} else {
		return bytes;
	}
}

/* return:
	< 0 -- -errno
	= 0 -- write returned EAGAIN
	> 0 -- write bytes
*/
ssize_t write_wrapper(int fd, void *buf, size_t count) {
	ssize_t bytes = write(fd, buf, count);
	if (bytes < 0) {
		switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
				return 0;
			case ECONNRESET:
				return -errno;
			default:
				perror("write");
				return -errno;
		}
	} else if (bytes == 0) {
		return -ECONNRESET;
	} else {
		return bytes;
	}
}

