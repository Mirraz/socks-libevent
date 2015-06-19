#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"

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

void fill_read_task(read_task_struct *read_task, int fd, void *buf, size_t count) {
	read_task->fd = fd;
	read_task->buf = buf;
	read_task->count = count;
}

ssize_t do_read_task(read_task_struct *read_task) {
	assert(read_task->count > 0);
	ssize_t read_bytes = read_wrapper(read_task->fd, read_task->buf, read_task->count);
	assert(read_bytes != 0);
	if (read_bytes < 0) return read_bytes;
	read_task->buf   += read_bytes;
	read_task->count -= read_bytes;
	return read_task->count;
}

int get_read_result(read_task_struct *read_task) {
	return read_task->ret;
}

void fill_getaddrinfo_task(getaddrinfo_task_struct *getaddrinfo_task,
		const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	getaddrinfo_task->node = node;
	getaddrinfo_task->service = service;
	getaddrinfo_task->hints = hints;
	getaddrinfo_task->res = res;
}

int get_getaddrinfo_result(getaddrinfo_task_struct *getaddrinfo_task) {
	return getaddrinfo_task->ret;
}

void fill_connect_task(connect_task_struct *connect_task, int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	connect_task->sockfd = sockfd;
	connect_task->addr = addr;
	connect_task->addrlen = addrlen;
}

int get_connect_result(connect_task_struct *connect_task) {
	return connect_task->ret;
}

