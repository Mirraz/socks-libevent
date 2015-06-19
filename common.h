#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <unistd.h>

void printf_and_exit(const char *format, ...);
void perror_and_exit(const char *s);
ssize_t read_wrapper(int fd, void *buf, size_t count);
ssize_t write_wrapper(int fd, const void *buf, size_t count);
int read_all(int fd, void *buf, size_t count);
int write_all(int fd, const void *buf, size_t count);

#endif/*COMMON_H*/

