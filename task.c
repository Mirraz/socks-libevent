#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "task.h"
#include "common.h"

void fill_read_task(read_task_struct *read_task, int fd, void *buf, size_t count) {
	read_task->fd = fd;
	read_task->buf = buf;
	read_task->count = count;
}

/* return:
	-1 -- failed                    task->ret = errno
	 0 -- read all                  task->ret = 0
	 1 -- read not all, try again   task->ret not seted
*/
int continue_read_task(read_task_struct *task) {
	assert(task->count > 0);
	ssize_t bytes = read_wrapper(task->fd, task->buf, task->count);
	if (bytes < 0) {
		task->ret = bytes;
		return -1;
	} else if (bytes == 0) {
		return 1;
	} else {
		assert(bytes <= (ssize_t)(task->count));
		task->buf   += bytes;
		task->count -= bytes;
		if (task->count > 0) {
			return 1;
		} else {
			task->ret = 0;
			return 0;
		}
	}
}

int get_read_result(read_task_struct *read_task) {
	return read_task->ret;
}



void fill_write_task(write_task_struct *write_task, int fd, void *buf, size_t count) {
	write_task->fd = fd;
	write_task->buf = buf;
	write_task->count = count;
}

/* return:
	-1 -- failed                     task->ret = errno
	 0 -- write all                  task->ret = 0
	 1 -- write not all, try again   task->ret not seted
*/
int continue_write_task(write_task_struct *task) {
	assert(task->count > 0);
	ssize_t bytes = write_wrapper(task->fd, task->buf, task->count);
	if (bytes < 0) {
		task->ret = bytes;
		return -1;
	} else if (bytes == 0) {
		return 1;
	} else {
		assert(bytes <= (ssize_t)(task->count));
		task->buf   += bytes;
		task->count -= bytes;
		if (task->count > 0) {
			return 1;
		} else {
			task->ret = 0;
			return 0;
		}
	}
}

int get_write_result(write_task_struct *write_task) {
	return write_task->ret;
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

static int handle_connect_err(connect_task_struct *connect_task, int err) {
	switch (err) {
		case 0:
			connect_task->ret = 0;
			return 0;
		case EINPROGRESS:
			return 1;
		case ECONNREFUSED:
		case ETIMEDOUT:
		case ENETUNREACH:
			connect_task->ret = errno;
			return -1;
		default:
			perror("connect");
			connect_task->ret = errno;
			return -1;
	}
}

/* return:
	-1 -- failed                         connect_task->ret = errno
	 0 -- succeeded                      connect_task->ret = 0
	 1 -- not completed yet, try again   connect_task->ret not seted
*/
int first_try_connect_task(connect_task_struct *connect_task) {
	int err = connect(connect_task->sockfd, connect_task->addr, connect_task->addrlen);
	if (err) err = errno;
	return handle_connect_err(connect_task, err);
}

/* return:
	-1 -- failed                         connect_task->ret = errno
	 0 -- succeeded                      connect_task->ret = 0
	 1 -- not completed yet, try again   connect_task->ret not seted
*/
int continue_connect_task(connect_task_struct *connect_task) {
	int err;
	socklen_t err_len = sizeof(err);
	int ret = getsockopt(connect_task->sockfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
	if (ret) {
		perror("getsockopt");
		connect_task->ret = errno;
		return -1;
	}
	assert(err_len == sizeof(err));
	return handle_connect_err(connect_task, err);
}

int get_connect_result(connect_task_struct *connect_task) {
	return connect_task->ret;
}

