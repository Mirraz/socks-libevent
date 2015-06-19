#ifndef COMMON_H
#define COMMON_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct {
	int fd;
	void *buf;
	size_t count;
	int ret;
} read_task_struct;

typedef struct {
	const char *node;
	const char *service;
	const struct addrinfo *hints;
	struct addrinfo **res;
	int ret;
} getaddrinfo_task_struct;

typedef struct {
	int sockfd;
	const struct sockaddr *addr;
	socklen_t addrlen;
	int ret;
} connect_task_struct;

typedef enum {
	TASK_READ,
	TASK_GETADDRINFO,
	TASK_CONNECT,
} task_type_enum;

typedef unsigned int task_type;

typedef union {
	read_task_struct read_task;
	getaddrinfo_task_struct getaddrinfo_task;
	connect_task_struct connect_task;
} task_data_union;

typedef struct {
	task_type type;
	task_data_union data;
} task_struct;

void printf_and_exit(const char *format, ...);
void perror_and_exit(const char *s);
ssize_t read_wrapper(int fd, void *buf, size_t count);
ssize_t write_wrapper(int fd, const void *buf, size_t count);
int read_all(int fd, void *buf, size_t count);
int write_all(int fd, const void *buf, size_t count);

void fill_read_task(read_task_struct *read_task, int fd, void *buf, size_t count);
ssize_t do_read_task(read_task_struct *read_task);
int get_read_result(read_task_struct *read_task);
void fill_getaddrinfo_task(getaddrinfo_task_struct *getaddrinfo_task,
		const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
int get_getaddrinfo_result(getaddrinfo_task_struct *getaddrinfo_task);
void fill_connect_task(connect_task_struct *connect_task, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int get_connect_result(connect_task_struct *connect_task);

#endif/*COMMON_H*/

