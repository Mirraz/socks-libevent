#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

void printf_and_exit(const char *format, ...) {
   va_list arglist;
   va_start(arglist, format);
   vfprintf(stderr, format, arglist);
   va_end(arglist);
   fprintf(stderr, "\n");
   exit(EXIT_FAILURE);
}

void perror_and_exit(const char *s) {
	perror(s);
	exit(EXIT_FAILURE);
}

ssize_t read_wrapper(int fd, void *buf, size_t count) {
	ssize_t read_bytes = read(fd, buf, count);
	if (read_bytes < 0) {
		if (errno == ECONNRESET) return -1;
		else perror_and_exit("read");
	}
	if (read_bytes == 0) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	assert(read_bytes <= count);
#pragma GCC diagnostic pop
	return read_bytes;
}

ssize_t write_wrapper(int fd, const void *buf, size_t count) {
	ssize_t write_bytes = write(fd, buf, count);
	if (write_bytes < 0) {
		if (errno == ECONNRESET) return -1;
		else perror_and_exit("write");
	}
	if (write_bytes == 0) return -1;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
	assert(write_bytes <= count);
#pragma GCC diagnostic pop
	return write_bytes;
}

int read_all(int fd, void *buf, size_t count) {
	ssize_t read_bytes;
	while (count > 0) {
		read_bytes = read_wrapper(fd, buf, count);
		if (read_bytes <= 0) return -1;
		buf   += read_bytes;
		count -= read_bytes;
	}
	return 0;
}

int write_all(int fd, const void *buf, size_t count) {
	ssize_t write_bytes;
	while (count > 0) {
		write_bytes = write_wrapper(fd, buf, count);
		if (write_bytes <= 0) return -1;
		buf   += write_bytes;
		count -= write_bytes;
	}
	return 0;
}

